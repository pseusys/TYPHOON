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
pub(crate) use error::CryptoError;
cfg_if! {
    if #[cfg(feature = "server")] {
        pub(crate) use server::ServerData;
        pub(crate) use server::{ServerCryptoTool, UserCryptoState, UserServerState};
    }
}
#[cfg(any(feature = "full_software", feature = "full_hardware"))]
pub(crate) use asymmetric::TAILOR_C2S_OVERHEAD;
#[cfg(any(feature = "fast_software", feature = "fast_hardware"))]
pub(crate) use symmetric::TAILOR_C2S_OVERHEAD;
/// Bytes that tailor obfuscation adds to the plaintext tailor, per direction.
pub(crate) use symmetric::TAILOR_S2C_OVERHEAD;
pub(crate) use symmetric::{ObfuscationTranscript, PAYLOAD_CRYPTO_OVERHEAD, verify_transcript_with_key};
