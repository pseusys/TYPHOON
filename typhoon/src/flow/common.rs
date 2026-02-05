//! Flow controller channel types and handles.
//!
//! This module defines the unified communication pattern for flow controllers.
//! Uses the same generic channel pattern as session controllers.

use crate::bytes::ByteBuffer;
use crate::utils::channel::{ControllerHandle, ControllerInternal};

// ==================== Unified Flow API ====================

/// Commands sent to a flow controller's event loop.
#[derive(Debug, Clone)]
pub enum FlowCommand {
    /// Send a packet through the flow.
    SendPacket(ByteBuffer),
    /// Graceful shutdown.
    Shutdown,
}

/// Return values from the flow controller.
#[derive(Debug, Clone)]
pub enum FlowReturn {
    /// Result of SendPacket command.
    SendPacketResult(bool),
}

/// Output events from the flow controller.
#[derive(Debug, Clone)]
pub enum FlowOutput {
    /// Received a packet from the network.
    Packet(ByteBuffer),
    /// The flow has been terminated.
    Terminated,
}

// ==================== Type Aliases ====================

/// Internal side for the flow controller.
pub type FlowInternal = ControllerInternal<FlowCommand, FlowReturn, FlowOutput>;

/// Handle for communicating with the flow controller.
/// Clone to share between multiple callers.
pub type FlowHandle = ControllerHandle<FlowCommand, FlowReturn, FlowOutput>;
