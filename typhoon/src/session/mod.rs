#[cfg(feature = "client")]
mod client_health;
/// Session management: encryption, health checking, and flow manager coordination.
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
