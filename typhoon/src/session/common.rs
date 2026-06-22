//! Session manager trait for managing encrypted data transfer and health checking.

#[cfg(feature = "client")]
use std::future::Future;

#[cfg(feature = "client")]
use crate::bytes::DynamicByteBuffer;
#[cfg(feature = "client")]
use crate::session::error::SessionControllerError;

/// Trait for managing session-level packet processing with encryption and health checking.
#[cfg(feature = "client")]
pub trait SessionManager {
    /// Send a packet through the session manager.
    /// If `generated` is true, the packet is already assembled (body + tailer) by the health provider.
    /// If `generated` is false, the packet is raw user data that needs encryption and tailer creation.
    fn send_packet(&self, packet: DynamicByteBuffer, generated: bool) -> impl Future<Output = Result<(), SessionControllerError>> + Send;

    /// Receive user data from the session manager.
    /// Health check packets are processed internally by the health provider and not returned.
    #[cfg(feature = "client")]
    fn receive_packet(&self) -> impl Future<Output = Result<DynamicByteBuffer, SessionControllerError>> + Send;
}

/// Outcome of waiting for a pending shadowride to be consumed by an outgoing data packet,
/// shared by the client- and server-side health check providers.
#[cfg(any(feature = "client", feature = "server"))]
pub(super) enum ShadowrideEvent {
    Timeout,
    Terminated,
    Shadowridden,
}
