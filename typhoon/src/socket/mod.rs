//! Client and server socket APIs.
//!
//! **Client**: build a [`ClientSocket`] with [`ClientSocketBuilder`]; call `send_bytes` / `receive_bytes`.
//!
//! **Server**: configure a [`ServerBuilder`], then pick an entrypoint:
//! - `build_listener()` → [`Listener`], call `start()`, then `accept()` in a loop to obtain one
//!   [`ClientHandle`] per connection — the caller owns each handle's lifetime.
//! - `build_pool()` → [`ClientPool`], call `start()`, then `receive()` / `send()` against client
//!   identities directly — all handles are owned and dispatched internally.
//!
//! In BSD-socket terms: `Listener` mirrors `listen`/`accept` (one handle per connection);
//! `ClientPool` mirrors `recvfrom`/`sendto` (one multiplexed entrypoint, peers distinguished by
//! identity rather than address — which, unlike a raw UDP peer address, persists across
//! mid-session address changes). Neither inherits TCP's ordering/reliability guarantees; the
//! wire transport is UDP either way.
//!
//! Decoy providers can be customised per-flow on the server (via [`ServerFlowConfiguration::with_decoy`])
//! or globally on the builder (via `with_decoy` / `with_decoy_factory`). The default is
//! `random_decoy_factory()`, which selects among all five built-in providers at random.

#[cfg(feature = "client")]
mod client;
mod error;
#[cfg(feature = "server")]
mod pool;
#[cfg(feature = "server")]
mod server;

use cfg_if::cfg_if;

cfg_if! {
    if #[cfg(feature = "client")] {
        pub use client::{ClientSocket, ClientSocketBuilder};
        pub use error::ClientSocketError;
        pub use crate::certificate::ClientCertificate;
        pub use crate::tailer::ClientConnectionHandler;
    }
}
cfg_if! {
    if #[cfg(feature = "server")] {
        pub use error::ServerSocketError;
        pub use pool::ClientPool;
        pub use server::{ClientHandle, Listener, ServerBuilder, ServerFlowConfiguration};
        pub use crate::certificate::ServerKeyPair;
        pub use crate::tailer::ServerConnectionHandler;
    }
}
