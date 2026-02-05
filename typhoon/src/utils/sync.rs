//! Async synchronization primitives.
//!
//! This module provides re-exports of tokio async primitives.

use std::future::Future;
use std::time::Duration;

// ==================== Channels ====================
pub use tokio::sync::mpsc::{channel, Receiver, Sender, WeakSender};
pub use tokio::sync::oneshot::{
    channel as oneshot_channel, Receiver as OneshotReceiver, Sender as OneshotSender,
};

// ==================== Locks ====================
pub use tokio::sync::{Mutex, RwLock};

// ==================== Time ====================
pub use tokio::time::sleep;

/// Timeout wrapper - returns None on timeout, Some(result) otherwise.
pub async fn timeout<F, T>(duration: Duration, future: F) -> Option<T>
where
    F: Future<Output = T>,
{
    tokio::time::timeout(duration, future).await.ok()
}

/// Receive from channel with timeout.
pub async fn recv_timeout<T>(rx: &mut Receiver<T>, duration: Duration) -> Option<T> {
    timeout(duration, rx.recv()).await.flatten()
}

/// Receive from a oneshot channel, returning None if the sender was dropped.
pub async fn oneshot_recv<T>(rx: OneshotReceiver<T>) -> Option<T> {
    rx.await.ok()
}

// ==================== Spawning ====================

/// Spawn a Send future on the runtime.
pub fn spawn<F>(future: F)
where
    F: Future<Output = ()> + Send + 'static,
{
    tokio::spawn(future);
}

// ==================== Select/Join macros ====================

/// Re-export tokio's select! macro.
pub use tokio::select;

/// Re-export tokio's join! macro.
pub use tokio::join;

// ==================== Utility futures ====================

/// Create a future that is pending forever.
pub fn pending<T>() -> impl Future<Output = T> {
    std::future::pending()
}

/// A biased select between two futures.
/// If both are ready, prefers the first one.
pub async fn select_biased<A, B, T>(a: A, b: B) -> T
where
    A: Future<Output = T>,
    B: Future<Output = T>,
{
    tokio::select! {
        biased;
        result = a => result,
        result = b => result,
    }
}
