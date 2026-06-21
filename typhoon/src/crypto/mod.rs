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
        pub(crate) use symmetric::SYMMETRIC_KEY_LENGTH as KEY_LENGTH;
    }
}
cfg_if! {
    if #[cfg(feature = "server")] {
        pub(crate) use server::ServerData;
        pub(crate) use server::{ServerCryptoTool, UserCryptoState, UserServerState};
        pub(crate) use symmetric::{ObfuscationTranscript, verify_transcript_with_key};
    }
}
#[cfg(any(feature = "full_software", feature = "full_hardware"))]
pub(crate) use asymmetric::TAILER_C2S_OVERHEAD;
pub(crate) use error::CryptoError;
pub(crate) use symmetric::PAYLOAD_CRYPTO_OVERHEAD;
#[cfg(any(feature = "fast_software", feature = "fast_hardware"))]
pub(crate) use symmetric::TAILER_C2S_OVERHEAD;
/// Bytes that tailer obfuscation adds to the plaintext tailer, per direction.
pub(crate) use symmetric::TAILER_S2C_OVERHEAD;
