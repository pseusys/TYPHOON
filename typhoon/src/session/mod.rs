/// Session management: encryption, health checking, and flow manager coordination.
mod common;
mod error;
mod health;

#[cfg(feature = "client")]
mod client;
#[cfg(feature = "server")]
pub(crate) mod server;

#[cfg(feature = "client")]
pub use client::ClientSessionManager;
pub use common::SessionManager;
pub use error::SessionControllerError;
