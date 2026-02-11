use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use cfg_if::cfg_if;
use futures::stream::{FuturesUnordered, StreamExt};

cfg_if! {
    if #[cfg(feature = "tokio")] {
        pub use tokio::sync::mpsc::{Sender, Receiver, channel};
        pub use tokio::sync::{RwLock, Mutex};
    } else if #[cfg(feature = "async-std")] {
        pub use async_channel::{Sender, Receiver, bounded as channel};
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
