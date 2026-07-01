use thiserror::Error;

use crate::cache::CacheError;
use crate::crypto::CryptoError;
use crate::utils::socket::SocketError;

/// Errors raised by a [`crate::flow::client::ClientFlowManager`] or [`crate::flow::server::ServerFlowManager`].
#[derive(Error, Debug)]
pub enum FlowControllerError {
    /// The flow manager's underlying UDP socket could not be created or used.
    #[error("error creating a flow manager: {}", .0.to_string())]
    Socket(#[source] SocketError),

    /// The requested payload, plus protocol overhead, exceeds the flow's configured maximum packet size.
    #[error("packet too long to be sent with given configuration: {expected} < {overhead} ({actual} + overhead)")]
    OversizePacket {
        /// Maximum total packet size the flow is configured to send.
        expected: usize,
        /// Size of the payload that was requested to be sent.
        actual: usize,
        /// Fixed protocol overhead (fake header/body, crypto, trailer) added on top of `actual`.
        overhead: usize,
    },

    /// The per-user crypto cache entry for this flow was missing or stale.
    #[error("error accessing cached cipher: {}", .0.to_string())]
    MissingCache(#[source] CacheError),

    /// Encrypting or obfuscating the packet trailer failed.
    #[error("error encrypting packet trailer: {}", .0.to_string())]
    TrailerEncryption(#[source] CryptoError),

    /// A [`crate::flow::FlowConfig`] failed its internal consistency check.
    #[error("flow config assertion failed: {message}")]
    AssertionFailed {
        /// Human-readable description of which check failed.
        message: String,
    },

    /// An operation referenced a user identity that this flow manager has no binding for.
    #[error("user not found in flow manager: {identity}")]
    UserNotFound {
        /// String form of the identity that was not found.
        identity: String,
    },
}
