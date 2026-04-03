use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use cfg_if::cfg_if;
use futures::stream::{FuturesUnordered, StreamExt};

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

// ── Watch channel (latest-value-wins, point-to-point) ────────────────────────

/// Shared state for the watch channel.
struct WatchState<T> {
    value: std::sync::Mutex<Option<T>>,
    closed: AtomicBool,
    #[cfg(feature = "tokio")]
    notify: tokio::sync::Notify,
    #[cfg(feature = "async-std")]
    notifiers: std::sync::Mutex<Vec<async_channel::Sender<()>>>,
}

/// Watch channel sender: stores the latest value, wakes all current receivers on change.
/// Requires only `T: Send` (not `T: Sync`).
pub struct WatchSender<T: Send> {
    state: Arc<WatchState<T>>,
}

/// Watch channel receiver: waits for the next value change and returns the latest value.
pub struct WatchReceiver<T> {
    state: Arc<WatchState<T>>,
    #[cfg(feature = "async-std")]
    notify: async_channel::Receiver<()>,
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
        !self.state.closed.load(Ordering::Relaxed)
    }

    /// Create a new receiver watching the same sender.
    pub fn subscribe(&self) -> WatchReceiver<T> {
        #[cfg(feature = "tokio")]
        return WatchReceiver { state: Arc::clone(&self.state) };
        #[cfg(feature = "async-std")]
        {
            let (tx, rx) = async_channel::bounded(1);
            self.state.notifiers.lock().unwrap().push(tx);
            WatchReceiver { state: Arc::clone(&self.state), notify: rx }
        }
    }
}

impl<T: Send> Drop for WatchSender<T> {
    fn drop(&mut self) {
        self.state.closed.store(true, Ordering::Relaxed);
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

impl<T: Clone + Send> WatchReceiver<T> {
    /// Wait for the next value change and return it, or None if the sender is dropped.
    pub async fn recv(&mut self) -> Option<T> {
        loop {
            #[cfg(feature = "tokio")]
            let notified = self.state.notify.notified();

            {
                let mut guard = self.state.value.lock().unwrap();
                if let Some(v) = guard.take() {
                    return Some(v);
                }
            }

            if self.state.closed.load(Ordering::Relaxed) {
                return None;
            }

            #[cfg(feature = "tokio")]
            notified.await;
            #[cfg(feature = "async-std")]
            { self.notify.recv().await.ok(); }
        }
    }
}

/// Create a watch channel: the sender stores the latest value; receivers are woken on each change.
#[cfg(feature = "tokio")]
pub fn create_watch<T: Send>() -> (WatchSender<T>, WatchReceiver<T>) {
    let state = Arc::new(WatchState {
        value: std::sync::Mutex::new(None),
        closed: AtomicBool::new(false),
        notify: tokio::sync::Notify::new(),
    });
    (WatchSender { state: Arc::clone(&state) }, WatchReceiver { state })
}

/// Create a watch channel: the sender stores the latest value; receivers are woken on each change.
#[cfg(feature = "async-std")]
pub fn create_watch<T: Send>() -> (WatchSender<T>, WatchReceiver<T>) {
    let (tx, rx) = async_channel::bounded(1);
    let state = Arc::new(WatchState {
        value: std::sync::Mutex::new(None),
        closed: AtomicBool::new(false),
        notifiers: std::sync::Mutex::new(vec![tx]),
    });
    (WatchSender { state: Arc::clone(&state) }, WatchReceiver { state, notify: rx })
}


/// Pool of concurrent futures that resolves them as they complete.
pub struct FuturePool<'f, T> {
    tasks: FuturesUnordered<Pin<Box<dyn Future<Output = T> + Send + 'f>>>,
}

impl<'f, T> FuturePool<'f, T> {
    pub fn new() -> Self {
        Self {
            tasks: FuturesUnordered::new(),
        }
    }

    /// Add a future to the pool.
    pub fn add<F: Future<Output = T> + Send + 'f>(&mut self, future: F) {
        self.tasks.push(Box::pin(future));
    }

    /// Wait for the next future in the pool to complete.
    pub async fn next(&mut self) -> Option<T> {
        self.tasks.next().await
    }
}

/// Sleep for the specified duration.
#[cfg(feature = "tokio")]
pub async fn sleep(duration: Duration) {
    tokio::time::sleep(duration).await;
}

/// Sleep for the specified duration.
#[cfg(feature = "async-std")]
pub async fn sleep(duration: Duration) {
    async_io::Timer::after(duration).await;
}
