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
