//! TYPHOON — Transfer Your Packets Hidden Over Observed Networks.
//!
//! An obfuscated UDP transport protocol designed to be statistically indistinguishable from
//! generic network traffic. Each wire packet consists of an optional fake body, an optional fake
//! header, an encrypted payload, and an encrypted tailor. Decoy packets (pure random bytes) are
//! injected by the flow layer to obscure timing and volume patterns.
//!
//! # Entry points
//!
//! - **Client**: [`socket::ClientSocketBuilder`] → [`socket::ClientSocket`]
//! - **Server**: [`socket::ListenerBuilder`] → [`socket::Listener`] → [`socket::ClientHandle`]
//!
//! # Feature flags
//!
//! | Flag | Description |
//! |---|---|
//! | `fast_software` | X25519 + XChaCha20-Poly1305 (default) |
//! | `fast_hardware` | X25519 + AES-GCM-256 |
//! | `full_software` | Classic McEliece + XChaCha20-Poly1305 |
//! | `full_hardware` | Classic McEliece + AES-GCM-256 |
//! | `server` | Server-side listener and session management |
//! | `client` | Client-side socket and session management |
//! | `debug` | Debug probe tools (requires `client` + `server`) |
//! | `tokio` | Tokio async runtime |
//! | `async-std` | async-std runtime |

#[cfg(all(feature = "tokio", feature = "async-std"))]
compile_error!("feature 'tokio' and feature 'async-std' cannot be enabled at the same time");

#[cfg(not(any(feature = "tokio", feature = "async-std")))]
compile_error!("one of the features 'tokio' and 'async-std' should be selected");

#[cfg(not(any(feature = "full_software", feature = "full_hardware", feature = "fast_software", feature = "fast_hardware")))]
compile_error!("one of the features 'full_software', 'full_hardware', 'fast_software' and 'fast_hardware' should be selected");

#[cfg(all(feature = "fast_software", feature = "full_software"))]
compile_error!("feature 'fast_software' and feature 'full_software' cannot be enabled at the same time");

#[cfg(all(feature = "fast_hardware", feature = "full_hardware"))]
compile_error!("feature 'fast_hardware' and feature 'full_hardware' cannot be enabled at the same time");

#[cfg(all(feature = "fast_software", feature = "fast_hardware"))]
compile_error!("feature 'fast_software' and feature 'fast_hardware' cannot be enabled at the same time");

#[cfg(not(any(feature = "server", feature = "client")))]
compile_error!("one of the features 'server' and 'client' should be selected");

pub mod bytes;
pub(crate) mod cache;
pub mod certificate;
pub(crate) mod crypto;
#[cfg(feature = "debug")]
pub mod debug;
pub mod defaults;
pub mod flow;
mod session;
pub mod settings;
pub mod socket;
mod tailor;
mod utils;
