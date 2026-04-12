//! Certificate I/O helpers: generate, persist, and load TYPHOON key material.
//!
//! # Binary file format
//!
//! Every file produced by this module begins with a 10-byte header:
//!
//! | Offset | Size | Value      | Description |
//! |--------|------|------------|-------------|
//! | 0      | 7    | `TYPHOON`  | Magic bytes |
//! | 7      | 1    | `S` or `C` | Record type: server key pair or client certificate |
//! | 8      | 1    | `F` or `U` | Cipher mode: fast (`F`) or full (`U`) |
//! | 9      | 1    | `1`        | Format version (currently always 1) |
//!
//! The payload following the header depends on record type and cipher mode; see
//! [`ServerKeyPair::save`] and [`ClientCertificate::save`] for exact field tables.

#[cfg(all(test, feature = "server"))]
#[path = "../../tests/certificate/mod.rs"]
mod tests;

mod client;
#[cfg(feature = "server")]
mod server;
mod utils;

pub use client::ClientCertificate;
#[cfg(feature = "server")]
pub use server::ServerKeyPair;
#[cfg(feature = "server")]
pub(crate) use server::ServerSecret;
pub(crate) use utils::ObfuscationBufferContainer;
pub use utils::{CertificateError, ED25519_BYTES, EPK_BYTES, ESK_BYTES, X25519_BYTES};
