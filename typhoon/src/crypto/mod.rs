mod asymmetric;
#[cfg(feature = "client")]
mod client;
mod error;
#[cfg(feature = "server")]
mod server;
mod symmetric;

use cfg_if::cfg_if;

cfg_if! {
    if #[cfg(feature = "client")] {
        pub(crate) use client::ClientCryptoTool;
        pub(crate) use client::ClientData;
        pub(crate) use symmetric::ObfuscationTranscript;
        pub(crate) use symmetric::SYMMETRIC_KEY_LENGTH as KEY_LENGTH;
    }
}
pub(crate) use error::CryptoError;
cfg_if! {
    if #[cfg(feature = "server")] {
        pub(crate) use server::ServerData;
        pub(crate) use server::{ServerCryptoTool, UserCryptoState, UserServerState};
    }
}
pub(crate) use symmetric::PAYLOAD_CRYPTO_OVERHEAD;
