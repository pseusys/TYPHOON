use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use cfg_if::cfg_if;
use futures::stream::{FuturesUnordered, StreamExt};

cfg_if! {
    if #[cfg(feature = "tokio")] {
        use tokio::sync::broadcast::{Sender, Receiver, channel};
        pub use tokio::sync::{RwLock, Mutex};
    } else if #[cfg(feature = "async-std")] {
        use async_channel::{Sender, Receiver, bounded as channel};
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

/// Channel sender wrapper with runtime-agnostic API.
pub struct ChannelSender<T> {
    sender: Sender<T>,
    #[cfg(feature = "async-std")]
    receiver: Receiver<T>,
}

/// Channel receiver wrapper with runtime-agnostic API.
pub struct ChannelReceiver<T> {
    receiver: Receiver<T>,
}

impl<T: Clone> ChannelSender<T> {
    #[cfg(feature = "tokio")]
    pub async fn send(&self, value: T) -> bool {
        self.sender.send(value).is_ok()
    }

    #[cfg(feature = "async-std")]
    pub async fn send(&self, value: T) -> bool {
        self.sender.send(value).await.is_ok()
    }

    /// Create a new receiver for this channel.
    #[cfg(feature = "tokio")]
    pub fn subscribe(&self) -> ChannelReceiver<T> {
        ChannelReceiver {
            receiver: self.sender.subscribe(),
        }
    }

    /// Create a new receiver for this channel.
    #[cfg(feature = "async-std")]
    pub fn subscribe(&self) -> ChannelReceiver<T> {
        ChannelReceiver {
            receiver: self.receiver.clone(),
        }
    }
}

impl<T: Clone> ChannelReceiver<T> {
    #[cfg(feature = "tokio")]
    pub async fn recv(&mut self) -> Option<T> {
        loop {
            match self.receiver.recv().await {
                Ok(val) => return Some(val),
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                Err(tokio::sync::broadcast::error::RecvError::Closed) => return None,
            }
        }
    }

    #[cfg(feature = "async-std")]
    pub async fn recv(&mut self) -> Option<T> {
        match self.receiver.recv().await {
            Ok(res) => Some(res),
            Err(_) => None,
        }
    }
}

/// Create a channel with the given capacity.
pub fn create_channel<T: Clone>(capacity: usize) -> (ChannelSender<T>, ChannelReceiver<T>) {
    let (sender, receiver) = channel(capacity);
    #[cfg(feature = "tokio")]
    let tx = ChannelSender {
        sender,
    };
    #[cfg(feature = "async-std")]
    let tx = ChannelSender {
        sender,
        receiver: receiver.clone(),
    };
    (
        tx,
        ChannelReceiver {
            receiver,
        },
    )
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
