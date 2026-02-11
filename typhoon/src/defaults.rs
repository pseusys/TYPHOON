use std::future::Future;

use cfg_if::cfg_if;

use crate::bytes::{ByteBuffer, StaticByteBuffer};
use crate::settings::Settings;
use crate::settings::consts::DEFAULT_TYPHOON_ID_LENGTH;
use crate::tailor::{IdentityType, Tailor};
use crate::utils::sync::AsyncExecutor;

impl IdentityType for StaticByteBuffer {
    fn from_bytes(bytes: &[u8]) -> Self {
        Self::from_slice(bytes)
    }

    fn to_bytes(&self) -> &[u8] {
        self.slice()
    }

    fn length() -> usize {
        DEFAULT_TYPHOON_ID_LENGTH
    }
}

/// Tokio-backed async executor.
#[cfg(feature = "tokio")]
#[derive(Clone)]
pub struct TokioExecutor;

#[cfg(feature = "tokio")]
impl AsyncExecutor for TokioExecutor {
    fn new() -> Self {
        Self
    }

    fn spawn<F: Future<Output = ()> + Send + 'static>(&self, future: F) {
        tokio::spawn(future);
    }
}

/// async-executor-backed async executor.
#[cfg(feature = "async-std")]
#[derive(Clone)]
pub struct AsyncStdExecutor {
    executor: std::sync::Arc<async_executor::Executor<'static>>,
}

#[cfg(feature = "async-std")]
impl AsyncExecutor for AsyncStdExecutor {
    fn new() -> Self {
        Self {
            executor: std::sync::Arc::new(async_executor::Executor::new()),
        }
    }

    fn spawn<F: Future<Output = ()> + Send + 'static>(&self, future: F) {
        self.executor.spawn(future).detach();
    }
}

#[cfg(feature = "async-std")]
impl From<std::sync::Arc<async_executor::Executor<'static>>> for AsyncStdExecutor {
    fn from(executor: std::sync::Arc<async_executor::Executor<'static>>) -> Self {
        Self { executor }
    }
}

// Default definitions:

cfg_if! {
    if #[cfg(feature = "tokio")] {
        /// The default executor type selected by the active feature flag.
        pub type DefaultExecutor = TokioExecutor;
    } else if #[cfg(feature = "async-std")] {
        /// The default executor type selected by the active feature flag.
        pub type DefaultExecutor = AsyncStdExecutor;
    }
}

pub type DefaultSettings = Settings<DefaultExecutor>;

pub type DefaultTailor = Tailor<StaticByteBuffer>;
