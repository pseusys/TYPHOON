#[cfg(feature = "client")]
mod client;
mod error;
#[cfg(feature = "server")]
mod server;

#[cfg(feature = "client")]
pub use client::{ClientSocket, ClientSocketBuilder, FlowManagerConfiguration};
#[cfg(feature = "client")]
pub use error::ClientSocketError;
#[cfg(feature = "server")]
pub use error::ServerSocketError;
#[cfg(feature = "server")]
pub use server::{ClientHandle, Listener, ListenerBuilder, ServerFlowConfiguration};
