/// Session manager trait for managing encrypted data transfer and health checking.
use std::future::Future;

use crate::bytes::DynamicByteBuffer;
use crate::session::error::SessionControllerError;

/// Trait for managing session-level packet processing with encryption and health checking.
pub trait SessionManager {
    /// Send a packet through the session manager.
    /// If `generated` is true, the packet is already assembled (body + tailor) by the health provider.
    /// If `generated` is false, the packet is raw user data that needs encryption and tailor creation.
    fn send_packet(&self, packet: DynamicByteBuffer, generated: bool) -> impl Future<Output = Result<(), SessionControllerError>> + Send;

    /// Receive user data from the session manager.
    /// Health check packets are processed internally by the health provider and not returned.
    #[cfg(feature = "client")]
    fn receive_packet(&self) -> impl Future<Output = Result<DynamicByteBuffer, SessionControllerError>> + Send;
}
