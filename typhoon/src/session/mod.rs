//! Session management: encryption, health checking, and flow manager coordination.
//!
//! A session manager handles the protocol state machine for one logical connection — key
//! exchange, payload encryption/decryption, and the health-check keepalive cycle — without
//! owning any UDP sockets (those belong to the flow layer).

#[cfg(feature = "client")]
mod client_health;
mod common;
mod error;

#[cfg(feature = "client")]
mod client;
#[cfg(feature = "server")]
pub(crate) mod server;
#[cfg(feature = "server")]
mod server_health;

#[cfg(feature = "client")]
pub use client::ClientSessionManager;
pub use common::SessionManager;
pub use error::SessionControllerError;
