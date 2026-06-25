use cfg_if::cfg_if;
use thiserror::Error;

use crate::flow::FlowControllerError;
cfg_if! {
    if #[cfg(feature = "client")] {
        use std::net::SocketAddr;
        use crate::certificate::CertificateError;
    }
}
use crate::session::SessionControllerError;
use crate::utils::socket::SocketError;

/// Errors returned by [`crate::socket::ClientSocket`] and [`crate::socket::ClientSocketBuilder`].
#[cfg(feature = "client")]
#[derive(Error, Debug)]
pub enum ClientSocketError {
    /// A flow manager failed to send or receive a packet.
    #[error("flow controller error: {}", .0.to_string())]
    Flow(#[source] FlowControllerError),

    /// The session controller (handshake, encryption, health checks) reported an error.
    #[error("session controller error: {}", .0.to_string())]
    Session(#[source] SessionControllerError),

    /// The underlying UDP socket reported an error.
    #[error("socket error: {}", .0.to_string())]
    Socket(#[source] SocketError),

    /// The client certificate could not be parsed or validated.
    #[error("certificate error: {}", .0.to_string())]
    Certificate(#[source] CertificateError),

    /// A `with_flow_config` address override does not match any address embedded in the certificate.
    #[error("address {0} is not present in the certificate")]
    AddressNotInCertificate(SocketAddr),

    /// The internal receive channel was closed, e.g. because all flow managers have stopped.
    #[error("receive channel closed")]
    ChannelClosed,

    /// The active async runtime feature is not supported for the attempted operation.
    #[error("unsupported runtime: {0}")]
    UnsupportedRuntime(&'static str),
}

/// Errors returned by [`crate::socket::Listener`], [`crate::socket::ClientPool`], and [`crate::socket::ServerBuilder`].
#[cfg(feature = "server")]
#[derive(Error, Debug)]
pub enum ServerSocketError {
    /// A flow manager failed to send or receive a packet.
    #[error("flow controller error: {}", .0.to_string())]
    Flow(#[source] FlowControllerError),

    /// The session controller (handshake, encryption, health checks) reported an error.
    #[error("session controller error: {}", .0.to_string())]
    Session(#[source] SessionControllerError),

    /// The underlying UDP socket reported an error.
    #[error("socket error: {}", .0.to_string())]
    Socket(#[source] SocketError),

    /// `ServerBuilder::build_listener`/`build_pool` was called without adding any flow configuration.
    #[error("no flow configurations provided")]
    NoFlows,

    /// The internal receive channel was closed, e.g. because the listener has stopped.
    #[error("receive channel closed")]
    ChannelClosed,

    /// The listener has already been stopped and can no longer accept or route packets.
    #[error("listener stopped")]
    ListenerStopped,

    /// An operation referenced an identity that has no active session on this listener.
    #[error("unknown client")]
    UnknownClient,

    /// The active async runtime feature is not supported for the attempted operation.
    #[error("unsupported runtime: {0}")]
    UnsupportedRuntime(&'static str),
}
