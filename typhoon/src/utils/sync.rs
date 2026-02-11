use std::future::Future;
use std::time::Duration;

#[cfg(feature = "async-std")]
use std::sync::Arc;

use cfg_if::cfg_if;
use futures::stream::{FuturesUnordered, StreamExt};

cfg_if! {
    if #[cfg(feature = "tokio")] {
        pub use tokio::sync::mpsc::{Sender, Receiver, WeakSender, channel};
        pub use tokio::sync::{RwLock, Mutex};
        use tokio::task::JoinHandle;
    } else if #[cfg(feature = "async-std")] {
        pub use async_channel::{Sender, Receiver, WeakSender, bounded as channel};
        pub use async_lock::{RwLock, Mutex};
        use async_executor::{Executor, Task};
    }
}

#[cfg(feature = "tokio")]
#[derive(Clone)]
pub struct AsyncExecutor<'a, 'b: 'a> {}

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

#[cfg(feature = "tokio")]
pub struct FuturePool<'a, 'b, T: Send + 'static> {
    tasks: FuturesUnordered<JoinHandle<T>>,
    executor: AsyncExecutor<'a, 'b>,
}

#[cfg(feature = "async-std")]
pub struct FuturePool<'a, 'b, T: Send + 'static> {
    tasks: FuturesUnordered<Task<T>>,
    executor: AsyncExecutor<'a, 'b>,
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
        Self {}
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

impl<'a, 'b, T: Send + 'static> FuturePool<'a, 'b, T> {
    pub fn new(executor: AsyncExecutor<'a, 'b>) -> Self {
        Self {
            tasks: FuturesUnordered::new(),
            executor,
        }
    }

    fn initiate<F: Future<Output = T> + Send + 'static, I: IntoIterator<Item = F>>(iter: I, executor: AsyncExecutor<'a, 'b>) -> Self {
        let mut futures = Self::new(executor);

        for future in iter {
            futures.add(future);
        }

        futures
    }

    #[cfg(feature = "tokio")]
    pub fn add<F: std::future::Future<Output = T> + Send + 'static>(&mut self, future: F) {
        self.tasks.push(tokio::spawn(fut));
    }

    #[cfg(feature = "async-std")]
    pub fn add<F: std::future::Future<Output = T> + Send + 'static>(&mut self, future: F) {
        self.tasks.push(match &self.executor.executor {
            ExecutorHolder::Owned(res) => res.spawn(future),
            ExecutorHolder::Borrowed(res) => res.spawn(future),
        });
    }

    pub async fn next(&mut self) -> Option<T> {
        match self.tasks.next().await {
            Some(value) => Some(value),
            None => None,
        }
    }
}

impl<'a, 'b, T: Send + 'static> Drop for FuturePool<'a, 'b, T> {
    fn drop(&mut self) {
        self.tasks.clear();
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
