//! TYPHOON — Transfer Your Packets Hidden Over Observed Networks.
//!
//! An obfuscated UDP transport protocol designed to be statistically indistinguishable from
//! generic network traffic. Each wire packet consists of an optional fake body, an optional fake
//! header, an encrypted payload, and an encrypted trailer. Decoy packets (pure random bytes) are
//! injected by the flow layer to obscure timing and volume patterns.
//!
//! # Entry points
//!
//! - **Client**: [`socket::ClientSocketBuilder`] → [`socket::ClientSocket`]
//! - **Server**: [`socket::ServerBuilder`] → [`socket::Listener`] → [`socket::ClientHandle`], or
//!   [`socket::ServerBuilder`] → [`socket::ClientPool`] for the multiplexed entrypoint
//!
//! # Examples
//!
//! Runnable, CI-tested examples live in the
//! [`example/`](https://github.com/pseusys/TYPHOON/tree/main/typhoon/example) directory:
//!
//! - [`hello_world.rs`](https://github.com/pseusys/TYPHOON/blob/main/typhoon/example/hello_world.rs) —
//!   minimal client/server round trip; start here.
//! - [`multi_flow.rs`](https://github.com/pseusys/TYPHOON/blob/main/typhoon/example/multi_flow.rs) —
//!   a session spread across several server flow managers.
//! - [`client_pool.rs`](https://github.com/pseusys/TYPHOON/blob/main/typhoon/example/client_pool.rs) —
//!   the multiplexed [`socket::ClientPool`] server entrypoint.
//!
//! Run any of them with `cargo run --example hello_world` from the `typhoon/` directory.
//!
//! # Feature flags
//!
//! | Flag | Description |
//! |---|---|
//! | `fast_software` | XChaCha20-Poly1305 for everything (default) |
//! | `fast_hardware` | AES-GCM-256 for everything |
//! | `full_software` | X25519 for trailer + XChaCha20-Poly1305 for session |
//! | `full_hardware` | X25519 for trailer + AES-GCM-256 for session |
//! | `server` | Server-side listener and session management |
//! | `client` | Client-side socket and session management |
//! | `debug` | Debug probe tools (requires `client` + `server`) |
//! | `capture` | Per-packet trace logging to `typhoon::capture` at `TRACE` level |
//! | `tokio` | Tokio async runtime |
//! | `async-std` | async-std runtime |

#![cfg_attr(docsrs, feature(doc_cfg))]
#![warn(missing_docs)]

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
pub(crate) mod capture;
pub use capture::record_loss;
pub mod certificate;
pub(crate) mod crypto;
#[cfg(feature = "debug")]
#[cfg_attr(docsrs, doc(cfg(feature = "debug")))]
pub mod debug;
pub mod defaults;
pub mod flow;
mod session;
pub mod settings;
pub mod socket;
mod trailer;
mod utils;
