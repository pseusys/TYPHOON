//! Session controller channel types and handles.
//!
//! This module defines the unified communication pattern for session controllers.
//! Both user and health provider use the same `SessionHandle` type (cloned).

use crate::bytes::ByteBuffer;
use crate::utils::channel::{self, ControllerHandle, ControllerInternal};

// ==================== Unified Session API ====================

/// Commands sent to the session controller.
#[derive(Debug, Clone)]
pub enum SessionCommand {
    // User commands
    /// Send user data through the session.
    SendData { data: ByteBuffer },

    // Health commands
    /// Begin shadowride window.
    BeginShadowride { packet_number: u64, next_in: u32 },
    /// End shadowride window.
    EndShadowride,
    /// Send a standalone health check packet.
    SendHealthCheck { packet_number: u64, next_in: u32 },

    // Shared
    /// Graceful shutdown.
    Shutdown,
}

/// Return values from the session controller.
/// Uses simple booleans for success/failure.
#[derive(Debug, Clone)]
pub enum SessionReturn {
    // User returns
    /// Result of SendData command (true = success).
    SendDataResult(bool),

    // Health returns
    /// Result of EndShadowride command (true = shadowride was consumed).
    EndShadowrideResult(bool),
    /// Result of SendHealthCheck command (true = success).
    SendHealthCheckResult(bool),
}

/// Output events from the session controller.
#[derive(Debug, Clone)]
pub enum SessionOutput {
    // User outputs
    /// Received user data (decrypted payload).
    Data(ByteBuffer),

    // Health outputs
    /// A health check response was received from the network.
    HealthResponse { packet_number: u64, next_in: u32 },

    // Shared
    /// The session has been terminated.
    Terminated,
}

// ==================== Type Aliases ====================

/// Internal side for the session controller.
pub type SessionInternal = ControllerInternal<SessionCommand, SessionReturn, SessionOutput>;

/// Handle for communicating with the session controller.
/// Used by both user and health provider. Clone to share.
pub type SessionHandle = ControllerHandle<SessionCommand, SessionReturn, SessionOutput>;
