#[cfg(feature = "client")]
use std::net::SocketAddr;

use thiserror::Error;

#[cfg(feature = "client")]
use crate::certificate::CertificateError;
use crate::flow::FlowControllerError;
use crate::session::SessionControllerError;
use crate::utils::socket::SocketError;

#[cfg(feature = "client")]
#[derive(Error, Debug)]
pub enum ClientSocketError {
    #[error("flow controller error: {}", .0.to_string())]
    FlowError(#[source] FlowControllerError),

    #[error("session controller error: {}", .0.to_string())]
    SessionError(#[source] SessionControllerError),

    #[error("socket error: {}", .0.to_string())]
    SocketError(#[source] SocketError),

    #[error("certificate error: {}", .0.to_string())]
    CertificateError(#[source] CertificateError),

    #[error("address {0} is not present in the certificate")]
    AddressNotInCertificate(SocketAddr),

    #[error("receive channel closed")]
    ChannelClosed,
}

#[derive(Error, Debug)]
pub enum ServerSocketError {
    #[error("flow controller error: {}", .0.to_string())]
    FlowError(#[source] FlowControllerError),

    #[error("session controller error: {}", .0.to_string())]
    SessionError(#[source] SessionControllerError),

    #[error("socket error: {}", .0.to_string())]
    SocketError(#[source] SocketError),

    #[error("no flow configurations provided")]
    NoFlows,

    #[error("receive channel closed")]
    ChannelClosed,

    #[error("listener stopped")]
    ListenerStopped,
}
