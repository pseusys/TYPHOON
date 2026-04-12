#[cfg(all(test, feature = "tokio"))]
#[path = "../../tests/utils/sync.rs"]
mod tests;

use std::future::Future;
#[cfg(feature = "client")]
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

#[cfg(feature = "async-std")]
use async_channel::{Receiver, Sender, bounded, unbounded};
#[cfg(feature = "async-std")]
use async_io::Timer;
use cfg_if::cfg_if;
#[cfg(all(feature = "server", feature = "tokio"))]
use crossbeam::queue::ArrayQueue;
#[cfg(feature = "tokio")]
use crossbeam::queue::SegQueue;
#[cfg(feature = "client")]
use futures::stream::{FuturesUnordered, StreamExt};
#[cfg(feature = "server")]
use log::debug;
#[cfg(feature = "tokio")]
use tokio::sync::Notify;
#[cfg(feature = "tokio")]
use tokio::time::sleep as tokio_sleep;

cfg_if! {
    if #[cfg(feature = "tokio")] {
        pub use tokio::sync::{RwLock, Mutex};
    } else if #[cfg(feature = "async-std")] {
        pub use async_lock::{RwLock, Mutex};
    }
}

/// Runtime-agnostic async task executor trait.
pub trait AsyncExecutor: Clone + Send + Sync {
    /// Create a new executor instance.
    fn new() -> Self;
    /// Spawn a fire-and-forget future onto the runtime.
    fn spawn<F: Future<Output = ()> + Send + 'static>(&self, future: F);
}

// ── Watch channel (latest-value-wins, destructive read) ──────────────────────
//
// Semantics: the sender stores the latest value and wakes all current
// receivers; each receiver *takes* (consumes) the value on recv().
// No off-the-shelf watch channel provides destructive single-consumer reads
// across both runtimes, so this stays hand-rolled.

struct WatchState<T> {
    value: std::sync::Mutex<Option<T>>,
    closed: AtomicBool,
    receiver_count: AtomicUsize,
    #[cfg(feature = "tokio")]
    notify: Notify,
    #[cfg(feature = "async-std")]
    notifiers: std::sync::Mutex<Vec<Sender<()>>>,
}

/// Watch channel sender: stores the latest value, wakes all receivers on change.
pub struct WatchSender<T: Send> {
    state: Arc<WatchState<T>>,
}

/// Watch channel receiver: waits for the next change and takes the latest value.
pub struct WatchReceiver<T> {
    state: Arc<WatchState<T>>,
    #[cfg(feature = "async-std")]
    notify: Receiver<()>,
}

impl<T: Send> WatchSender<T> {
    /// Send a new value, overwriting the previous one.
    /// Returns false if all receivers have been dropped.
    pub fn send(&self, value: T) -> bool {
        *self.state.value.lock().unwrap() = Some(value);
        #[cfg(feature = "tokio")]
        self.state.notify.notify_waiters();
        #[cfg(feature = "async-std")]
        {
            let notifiers = self.state.notifiers.lock().unwrap();
            for tx in notifiers.iter() {
                let _ = tx.try_send(());
            }
        }
        self.state.receiver_count.load(Ordering::Relaxed) > 0
    }

    /// Create a new receiver watching the same sender.
    #[cfg(feature = "client")]
    pub fn subscribe(&self) -> WatchReceiver<T> {
        self.state.receiver_count.fetch_add(1, Ordering::Relaxed);
        #[cfg(feature = "tokio")]
        return WatchReceiver {
            state: Arc::clone(&self.state),
        };
        #[cfg(feature = "async-std")]
        {
            let (tx, rx) = bounded(1);
            self.state.notifiers.lock().unwrap().push(tx);
            WatchReceiver {
                state: Arc::clone(&self.state),
                notify: rx,
            }
        }
    }
}

impl<T: Send> Drop for WatchSender<T> {
    fn drop(&mut self) {
        self.state.closed.store(true, Ordering::Release);
        #[cfg(feature = "tokio")]
        self.state.notify.notify_waiters();
        #[cfg(feature = "async-std")]
        {
            let mut notifiers = self.state.notifiers.lock().unwrap();
            for tx in notifiers.drain(..) {
                let _ = tx.try_send(());
            }
        }
    }
}

impl<T> Drop for WatchReceiver<T> {
    fn drop(&mut self) {
        self.state.receiver_count.fetch_sub(1, Ordering::Release);
    }
}

impl<T: Send> WatchReceiver<T> {
    /// Wait for the next value change and take it (destructive read),
    /// or `None` if the sender is dropped.
    pub async fn recv(&mut self) -> Option<T> {
        loop {
            #[cfg(feature = "tokio")]
            let mut notified = std::pin::pin!(self.state.notify.notified());
            #[cfg(feature = "tokio")]
            notified.as_mut().enable();

            {
                let mut guard = self.state.value.lock().unwrap();
                if let Some(v) = guard.take() {
                    return Some(v);
                }
                if self.state.closed.load(Ordering::Acquire) {
                    return None;
                }
            }

            #[cfg(feature = "tokio")]
            notified.await;
            #[cfg(feature = "async-std")]
            {
                self.notify.recv().await.ok();
            }
        }
    }
}

/// Create a watch channel.
#[cfg(feature = "tokio")]
pub fn create_watch<T: Send>() -> (WatchSender<T>, WatchReceiver<T>) {
    let state = Arc::new(WatchState {
        value: std::sync::Mutex::new(None),
        closed: AtomicBool::new(false),
        receiver_count: AtomicUsize::new(1),
        notify: Notify::new(),
    });
    (
        WatchSender {
            state: Arc::clone(&state),
        },
        WatchReceiver {
            state,
        },
    )
}

/// Create a watch channel.
#[cfg(feature = "async-std")]
pub fn create_watch<T: Send>() -> (WatchSender<T>, WatchReceiver<T>) {
    let (tx, rx) = bounded(1);
    let state = Arc::new(WatchState {
        value: std::sync::Mutex::new(None),
        closed: AtomicBool::new(false),
        receiver_count: AtomicUsize::new(1),
        notifiers: std::sync::Mutex::new(vec![tx]),
    });
    (
        WatchSender {
            state: Arc::clone(&state),
        },
        WatchReceiver {
            state,
            notify: rx,
        },
    )
}

// ── Notifying queues ──────────────────────────────────────────────────────────
//
// Design: crossbeam SegQueue/ArrayQueue for O(1) lock-free, allocation-free
// storage; runtime-native Notify/channel for efficient async wakeup.
//
// Compared to the previous design (SegQueue + WatchSender which locked a mutex
// per notify) and the naive alternative (tokio mpsc which allocates a Box<Node>
// per push), this hybrid is optimal for both throughput and latency.

cfg_if! {
    if #[cfg(feature = "tokio")] {

        // ── Shared state ─────────────────────────────────────────────────────

        struct NotifyQueueState<T> {
            queue: SegQueue<T>,
            notify: Notify,
            closed: AtomicBool,
        }

        // ── Unbounded ────────────────────────────────────────────────────────

        /// Push side of an unbounded notifying queue.
        pub struct NotifyQueueSender<T: Send>(Arc<NotifyQueueState<T>>);

        /// Pop side of an unbounded notifying queue.
        pub struct NotifyQueueReceiver<T: Send>(Arc<NotifyQueueState<T>>);

        impl<T: Send> NotifyQueueSender<T> {
            /// Push an item; never blocks.
            pub fn push(&self, item: T) {
                self.0.queue.push(item);
                self.0.notify.notify_one();
            }
        }

        impl<T: Send> Drop for NotifyQueueSender<T> {
            fn drop(&mut self) {
                self.0.closed.store(true, Ordering::Release);
                self.0.notify.notify_waiters();
            }
        }

        impl<T: Send> NotifyQueueReceiver<T> {
            /// Pop the next item, waiting asynchronously until one is pushed.
            /// Returns `None` if the sender has been dropped and the queue is empty.
            pub async fn recv(&mut self) -> Option<T> {
                loop {
                    if let Some(item) = self.0.queue.pop() {
                        return Some(item);
                    }
                    if self.0.closed.load(Ordering::Acquire) && self.0.queue.is_empty() {
                        return None;
                    }
                    // Pre-register the waker before the second pop so we cannot
                    // miss a push that arrives between the two checks.
                    let mut notified = std::pin::pin!(self.0.notify.notified());
                    notified.as_mut().enable();
                    if let Some(item) = self.0.queue.pop() {
                        return Some(item);
                    }
                    notified.await;
                }
            }
        }

        /// Create an unbounded notifying queue.
        pub fn create_notify_queue<T: Send>() -> (NotifyQueueSender<T>, NotifyQueueReceiver<T>) {
            let state = Arc::new(NotifyQueueState {
                queue: SegQueue::new(),
                notify: Notify::new(),
                closed: AtomicBool::new(false),
            });
            (NotifyQueueSender(Arc::clone(&state)), NotifyQueueReceiver(state))
        }

        // ── Bounded ──────────────────────────────────────────────────────────

        #[cfg(feature = "server")]
        struct BoundedNotifyQueueState<T> {
            queue: ArrayQueue<T>,
            notify: Notify,
            closed: AtomicBool,
        }

        /// Push side of a bounded notifying queue.
        #[cfg(feature = "server")]
        pub struct BoundedNotifyQueueSender<T: Send>(Arc<BoundedNotifyQueueState<T>>);

        /// Pop side of a bounded notifying queue.
        #[cfg(feature = "server")]
        pub struct BoundedNotifyQueueReceiver<T: Send>(Arc<BoundedNotifyQueueState<T>>);

        #[cfg(feature = "server")]
        impl<T: Send> BoundedNotifyQueueSender<T> {
            /// Push an item; silently drops it (with a debug log) if the queue is full.
            pub fn push(&self, item: T) {
                if self.0.queue.push(item).is_err() {
                    debug!("BoundedNotifyQueue: queue full, dropping item");
                    return;
                }
                self.0.notify.notify_one();
            }
        }

        #[cfg(feature = "server")]
        impl<T: Send> Drop for BoundedNotifyQueueSender<T> {
            fn drop(&mut self) {
                self.0.closed.store(true, Ordering::Release);
                self.0.notify.notify_waiters();
            }
        }

        #[cfg(feature = "server")]
        impl<T: Send> BoundedNotifyQueueReceiver<T> {
            /// Pop the next item, waiting asynchronously until one is pushed.
            /// Returns `None` if the sender has been dropped and the queue is empty.
            pub async fn recv(&mut self) -> Option<T> {
                loop {
                    if let Some(item) = self.0.queue.pop() {
                        return Some(item);
                    }
                    if self.0.closed.load(Ordering::Acquire) && self.0.queue.is_empty() {
                        return None;
                    }
                    let mut notified = std::pin::pin!(self.0.notify.notified());
                    notified.as_mut().enable();
                    if let Some(item) = self.0.queue.pop() {
                        return Some(item);
                    }
                    notified.await;
                }
            }
        }

        /// Create a bounded notifying queue with the given capacity.
        #[cfg(feature = "server")]
        pub fn create_bounded_notify_queue<T: Send>(cap: usize) -> (BoundedNotifyQueueSender<T>, BoundedNotifyQueueReceiver<T>) {
            let state = Arc::new(BoundedNotifyQueueState {
                queue: ArrayQueue::new(cap),
                notify: Notify::new(),
                closed: AtomicBool::new(false),
            });
            (BoundedNotifyQueueSender(Arc::clone(&state)), BoundedNotifyQueueReceiver(state))
        }

    } else if #[cfg(feature = "async-std")] {

        // Under async-std there is no standalone Notify equivalent, so we use
        // async_channel which is already a dependency.

        /// Push side of an unbounded notifying queue.
        pub struct NotifyQueueSender<T: Send>(Sender<T>);

        /// Pop side of an unbounded notifying queue.
        pub struct NotifyQueueReceiver<T: Send>(Receiver<T>);

        impl<T: Send> NotifyQueueSender<T> {
            pub fn push(&self, item: T) {
                let _ = self.0.try_send(item);
            }
        }

        impl<T: Send> NotifyQueueReceiver<T> {
            pub async fn recv(&mut self) -> Option<T> {
                self.0.recv().await.ok()
            }
        }

        /// Create an unbounded notifying queue.
        pub fn create_notify_queue<T: Send>() -> (NotifyQueueSender<T>, NotifyQueueReceiver<T>) {
            let (tx, rx) = unbounded();
            (NotifyQueueSender(tx), NotifyQueueReceiver(rx))
        }

        /// Push side of a bounded notifying queue.
        #[cfg(feature = "server")]
        pub struct BoundedNotifyQueueSender<T: Send>(Sender<T>);

        /// Pop side of a bounded notifying queue.
        #[cfg(feature = "server")]
        pub struct BoundedNotifyQueueReceiver<T: Send>(Receiver<T>);

        #[cfg(feature = "server")]
        impl<T: Send> BoundedNotifyQueueSender<T> {
            pub fn push(&self, item: T) {
                if self.0.try_send(item).is_err() {
                    debug!("BoundedNotifyQueue: queue full, dropping item");
                }
            }
        }

        #[cfg(feature = "server")]
        impl<T: Send> BoundedNotifyQueueReceiver<T> {
            pub async fn recv(&mut self) -> Option<T> {
                self.0.recv().await.ok()
            }
        }

        /// Create a bounded notifying queue with the given capacity.
        #[cfg(feature = "server")]
        pub fn create_bounded_notify_queue<T: Send>(cap: usize) -> (BoundedNotifyQueueSender<T>, BoundedNotifyQueueReceiver<T>) {
            let (tx, rx) = bounded(cap);
            (BoundedNotifyQueueSender(tx), BoundedNotifyQueueReceiver(rx))
        }
    }
}

// ── Future pool ───────────────────────────────────────────────────────────────

/// Pool of concurrent futures that resolves them as they complete.
#[cfg(feature = "client")]
pub struct FuturePool<'f, T> {
    tasks: FuturesUnordered<Pin<Box<dyn Future<Output = T> + Send + 'f>>>,
}

#[cfg(feature = "client")]
impl<'f, T> FuturePool<'f, T> {
    pub fn new() -> Self {
        Self {
            tasks: FuturesUnordered::new(),
        }
    }

    pub fn add<F: Future<Output = T> + Send + 'f>(&mut self, future: F) {
        self.tasks.push(Box::pin(future));
    }

    pub async fn next(&mut self) -> Option<T> {
        self.tasks.next().await
    }
}

// ── Sleep ─────────────────────────────────────────────────────────────────────

#[cfg(feature = "tokio")]
pub async fn sleep(duration: Duration) {
    tokio_sleep(duration).await;
}

#[cfg(feature = "async-std")]
pub async fn sleep(duration: Duration) {
    Timer::after(duration).await;
}
