use std::future::Future;
use std::time::Duration;

use cfg_if::cfg_if;

cfg_if! {
    if #[cfg(feature = "tokio")] {
        pub use tokio::sync::mpsc::{Sender, Receiver, WeakSender, channel};
        pub use tokio::sync::{RwLock, Mutex};
    } else if #[cfg(feature = "async-std")] {
        pub use async_channel::{Sender, Receiver, WeakSender, bounded as channel};
        pub use async_lock::{RwLock, Mutex};
        use async_executor::Executor;
        use lazy_static::lazy_static;
    }
}

#[cfg(feature = "async-std")]
lazy_static! {
    static ref EXECUTOR: Executor<'static> = Executor::new();
}

/// Spawn a future onto the runtime.
#[cfg(feature = "tokio")]
pub fn spawn<F: Future<Output = ()> + Send + 'static>(future: F) {
    tokio::spawn(future);
}

/// Spawn a future onto the runtime.
#[cfg(feature = "async-std")]
pub fn spawn<F: Future<Output = ()> + Send + 'static>(future: F) {
    EXECUTOR.spawn(future);
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
