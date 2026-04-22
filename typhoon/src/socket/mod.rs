//! Client and server socket APIs.
//!
//! **Client**: build a [`ClientSocket`] with [`ClientSocketBuilder`]; call `send_bytes` / `receive_bytes`.
//!
//! **Server**: build a [`Listener`] with [`ListenerBuilder`], call `start()`, then `accept()` in a
//! loop to obtain [`ClientHandle`]s. Each handle corresponds to one connected client.
//!
//! Decoy providers can be customised per-flow on the server (via [`ServerFlowConfiguration::with_decoy`])
//! or globally on the builder (via `with_decoy` / `with_decoy_factory`). The default is
//! `random_decoy_factory()`, which selects among all five built-in providers at random.

#[cfg(feature = "client")]
mod client;
mod error;
#[cfg(feature = "server")]
mod server;

use cfg_if::cfg_if;

cfg_if! {
    if #[cfg(feature = "client")] {
        pub use client::{ClientSocket, ClientSocketBuilder};
        pub use error::ClientSocketError;
        pub use crate::certificate::ClientCertificate;
        pub use crate::tailor::ClientConnectionHandler;
    }
}
cfg_if! {
    if #[cfg(feature = "server")] {
        pub use error::ServerSocketError;
        pub use server::{ClientHandle, Listener, ListenerBuilder, ServerFlowConfiguration};
        pub use crate::certificate::ServerKeyPair;
        pub use crate::tailor::ServerConnectionHandler;
    }
}
