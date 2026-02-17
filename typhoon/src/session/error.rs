/// Errors that can occur during session management.
use thiserror::Error;

use crate::cache::CacheError;
use crate::crypto::CryptoError;
use crate::flow::FlowControllerError;

#[derive(Error, Debug)]
pub enum SessionControllerError {
    #[error("flow controller error: {}", .0.to_string())]
    FlowError(#[source] FlowControllerError),

    #[error("payload encryption error: {}", .0.to_string())]
    CryptoError(#[source] CryptoError),

    #[error("error accessing cached cipher: {}", .0.to_string())]
    MissingCache(#[source] CacheError),

    #[error("connection decayed after {} retries", .0)]
    ConnectionDecayed(u64),

    #[error("connection terminated by peer (code {})", .0)]
    ConnectionTerminated(u8),

    #[error("no flows provided for session client")]
    NoFlows,

    #[error("session manager health provider terminated")]
    HealthProviderDied,
}
