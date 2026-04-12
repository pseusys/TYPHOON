#[cfg(feature = "client")]
mod client;
mod error;
#[cfg(feature = "server")]
mod server;

#[cfg(feature = "client")]
pub use client::{ClientSocket, ClientSocketBuilder};
#[cfg(feature = "client")]
pub use error::ClientSocketError;
#[cfg(feature = "server")]
pub use error::ServerSocketError;
#[cfg(feature = "server")]
pub use server::{ClientHandle, Listener, ListenerBuilder, ServerFlowConfiguration};

#[cfg(feature = "client")]
pub use crate::certificate::ClientCertificate;
#[cfg(feature = "server")]
pub use crate::certificate::ServerKeyPair;
#[cfg(feature = "client")]
pub use crate::tailor::ClientConnectionHandler;
#[cfg(feature = "server")]
pub use crate::tailor::ServerConnectionHandler;
