//! Flow managers: UDP send/receive paths, fake-header/body framing, and decoy injection.
//!
//! A flow manager owns one or more UDP sockets and one [`decoy::DecoyProvider`] per active user.
//! Providers are constructed lazily through a [`decoy::DecoyFactory`] closure so each flow or user
//! can use a different concrete strategy at runtime.
//!
//! [`FlowConfig`] controls the fake-body mode and fake-header field layout for a flow.

#[cfg(feature = "client")]
pub mod client;
mod common;
pub mod config;
pub mod decoy;
mod error;
pub mod probe;
#[cfg(feature = "server")]
pub mod server;

#[cfg(feature = "client")]
pub(crate) use common::FlowCryptoProvider;
pub(crate) use common::FlowManager;
pub use config::{FakeBodyMode, FakeHeaderConfig, FieldType, FieldTypeHolder, FlowConfig};
pub use error::FlowControllerError;
pub use probe::{ActiveProbeHandler, ProbeFactory, ProbeFlowSender, probe_factory};
