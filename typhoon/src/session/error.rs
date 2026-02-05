use thiserror::Error;

use crate::{crypto::CryptoError, flow::FlowControllerError};

/// Session controller error type.
#[derive(Error, Debug)]
pub enum SessionControllerError {
    #[error("flow controller error: {}", .0.to_string())]
    FlowError(#[from] FlowControllerError),

    #[error("session decayed: no response after maximum retries")]
    SessionDecayed,

    #[error("session controller channel closed")]
    ChannelClosed,

    #[error("handshake failed after maximum retries")]
    HandshakeFailed,

    #[error("cipher error: {}", .0.to_string())]
    CipherError(#[from] CryptoError),

    #[error("receivers ordering error, one of the flow handlers might have terminated")]
    FutureOrderFailed,
}
