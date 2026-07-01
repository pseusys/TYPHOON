//! Certificate I/O helpers: generate, persist, and load TYPHOON key material.
//!
//! # Binary file format
//!
//! Every file produced by this module begins with a 16-byte header:
//!
//! | Offset | Size | Value          | Description |
//! |--------|------|----------------|-------------|
//! | 0      | 7    | `TYPHOON`      | Magic bytes |
//! | 7      | 1    | `S` or `C`     | Record type: server key pair or client certificate |
//! | 8      | 1    | `s`/`h`/`S`/`H`| Build flavor: cipher mode (case: fast lower / full upper) crossed with cipher backend (`s`/`S` = software, `h`/`H` = hardware) |
//! | 9      | 1    | `1`            | Format version (currently always 1) |
//! | 10     | 4    | e.g. `0`       | Protocol major version (big-endian `u32`, from `CARGO_PKG_VERSION`) |
//! | 14     | 2    | e.g. `16`      | `ID` field length in bytes (big-endian `u16`) |
//!
//! The last three fields are non-negotiable protocol settings fixed at compile time: they cannot
//! be renegotiated at runtime, so a mismatch between the build that produced the file and the
//! build loading it would otherwise silently corrupt the wire format instead of failing cleanly.
//! Loading rejects any mismatch with a dedicated [`CertificateError`] variant (e.g.
//! [`CertificateError::FlavorMismatch`], [`CertificateError::VersionMismatch`]). The build-flavor
//! byte packs both axes together rather than using two separate bytes, since there are only four
//! valid combinations (`fast_software`/`fast_hardware`/`full_software`/`full_hardware`) and
//! exactly one is ever active per build (enabling more than one fails to compile with a duplicate
//! `FLAVOR_BYTE` definition).
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

use cfg_if::cfg_if;
pub use client::ClientCertificate;
cfg_if! {
    if #[cfg(feature = "server")] {
        pub use server::ServerKeyPair;
        pub(crate) use server::ServerSecret;
    }
}
pub(crate) use utils::ObfuscationBufferContainer;
pub use utils::{CertificateError, ED25519_BYTES, EPK_BYTES, ESK_BYTES, X25519_BYTES};
