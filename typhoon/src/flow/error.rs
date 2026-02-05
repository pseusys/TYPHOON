use thiserror::Error;

use crate::{cache::CacheError, crypto::CryptoError, utils::socket::SocketError};

#[derive(Error, Debug)]
pub enum FlowControllerError {
    #[error("error creating a flow manager: {}", .0.to_string())]
    SocketError(#[source] SocketError),

    #[error("packet too long to be sent with given configuration: {expected} < {overhead} ({actual} + overhead)")]
    OversizePacket {
        expected: usize,
        actual: usize,
        overhead: usize,
    },

    #[error("error accessing cached cipher: {}", .0.to_string())]
    MissingCache(#[source] CacheError),

    #[error("error encrypting packet tailor: {}", .0.to_string())]
    TailorEncryption(#[source] CryptoError),

    #[error("flow controller channel closed")]
    ChannelClosed,
}
