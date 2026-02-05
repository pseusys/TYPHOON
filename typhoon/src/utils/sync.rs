use cfg_if::cfg_if;
use std::future::Future;
use std::time::Duration;

cfg_if! {
    if #[cfg(feature = "tokio")] {
        pub use tokio::sync::mpsc::{Sender, Receiver, WeakSender, channel};
        pub use tokio::sync::{RwLock, Mutex};

        /// Spawn a future onto the runtime.
        pub fn spawn<F>(future: F)
        where
            F: Future<Output = ()> + Send + 'static,
        {
            tokio::spawn(future);
        }

        /// Sleep for the specified duration.
        pub async fn sleep(duration: Duration) {
            tokio::time::sleep(duration).await;
        }
    } else if #[cfg(feature = "async-std")] {
        pub use async_channel::{Sender, Receiver, WeakSender, bounded as channel};
        pub use async_lock::{RwLock, Mutex};

        /// Spawn a future onto the runtime.
        pub fn spawn<F>(future: F)
        where
            F: Future<Output = ()> + Send + 'static,
        {
            async_io::block_on(future);
        }

        /// Sleep for the specified duration.
        pub async fn sleep(duration: Duration) {
            async_io::Timer::after(duration).await;
        }
    }
}
