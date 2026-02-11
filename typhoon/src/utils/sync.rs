use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

#[cfg(feature = "tokio")]
use std::marker::PhantomData;

#[cfg(feature = "async-std")]
use std::sync::Arc;

use cfg_if::cfg_if;
use futures::stream::{FuturesUnordered, StreamExt};

cfg_if! {
    if #[cfg(feature = "tokio")] {
        pub use tokio::sync::mpsc::{Sender, Receiver, WeakSender, channel};
        pub use tokio::sync::{RwLock, Mutex};
    } else if #[cfg(feature = "async-std")] {
        pub use async_channel::{Sender, Receiver, WeakSender, bounded as channel};
        pub use async_lock::{RwLock, Mutex};
        use async_executor::Executor;
    }
}

#[cfg(feature = "tokio")]
#[derive(Clone)]
pub struct AsyncExecutor<'a, 'b: 'a> {
    _marker_a: PhantomData<&'a ()>,
    _marker_b: PhantomData<&'b ()>,
}

#[cfg(feature = "async-std")]
#[derive(Clone)]
enum ExecutorHolder<'a, 'b: 'a> {
    Owned(Arc<Executor<'a>>),
    Borrowed(&'b Executor<'a>),
}

#[cfg(feature = "async-std")]
#[derive(Clone)]
pub struct AsyncExecutor<'a, 'b> {
    executor: ExecutorHolder<'a, 'b>,
}

/// Pool of concurrent futures that resolves them as they complete.
pub struct FuturePool<'f, T> {
    tasks: FuturesUnordered<Pin<Box<dyn Future<Output = T> + Send + 'f>>>,
}

impl<'a, 'b> AsyncExecutor<'a, 'b> {
    /// Spawn a future onto the runtime.
    #[cfg(feature = "tokio")]
    pub fn spawn<F: Future<Output = ()> + Send + 'a>(&self, future: F) {
        tokio::spawn(future);
    }

    /// Spawn a future onto the runtime.
    #[cfg(feature = "async-std")]
    pub fn spawn<F: Future<Output = ()> + Send + 'a>(&self, future: F) {
        match &self.executor {
            ExecutorHolder::Owned(res) => res.spawn(future),
            ExecutorHolder::Borrowed(res) => res.spawn(future),
        }.detach();
    }
}

#[cfg(feature = "tokio")]
impl<'a, 'b> Default for AsyncExecutor<'a, 'b> {
    fn default() -> Self {
        Self {
            _marker_a: PhantomData,
            _marker_b: PhantomData,
        }
    }
}

#[cfg(feature = "async-std")]
impl<'a, 'b> Default for AsyncExecutor<'a, 'b> {
    fn default() -> Self {
        Self {
            executor: ExecutorHolder::Owned(Arc::new(Executor::new())),
        }
    }
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
