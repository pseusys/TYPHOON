use thiserror::Error;

use crate::flow::FlowControllerError;
use crate::session::SessionControllerError;
use crate::utils::socket::SocketError;

#[derive(Error, Debug)]
pub enum ClientSocketError {
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
