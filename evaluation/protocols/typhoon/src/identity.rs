//! Eval-side 4-byte identity type for the TYPHOON evaluation binaries.
//!
//! Reduces the per-packet wire-overhead floor by 12 bytes (the protocol default
//! `DEFAULT_TYPHOON_ID_LENGTH = 16`).  Per `PROTOCOL.md §6.5.4`, this drops the
//! data-packet floor 144 → 132 B and the service-packet floor 88 → 76 B so the
//! smallest TYPHOON packets can approach real-protocol ACK / control-packet
//! sizes (e.g. real QUIC ACKs at 70-100 B).
//!
//! Cost: shorter identity → higher per-flow collision probability when many
//! clients share one listener.  Acceptable in eval (one client per run).

use std::fmt::{self, Display};

use rand::{Rng, thread_rng};
use typhoon::bytes::StaticByteBuffer;
use typhoon::flow::decoy::IdentityType;
use typhoon::socket::ServerConnectionHandler;

/// Identity length in bytes.
pub const SHORT_IDENTITY_LENGTH: usize = 4;

/// 4-byte identity backed by an inline byte array.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct ShortIdentity {
    bytes: [u8; SHORT_IDENTITY_LENGTH],
}

impl ShortIdentity {
    /// Construct from a `u32` value in big-endian byte order.
    #[inline]
    pub fn from_u32(value: u32) -> Self {
        Self {
            bytes: value.to_be_bytes(),
        }
    }
}

impl IdentityType for ShortIdentity {
    fn from_bytes(bytes: &[u8]) -> Self {
        let mut arr = [0u8; SHORT_IDENTITY_LENGTH];
        arr.copy_from_slice(&bytes[..SHORT_IDENTITY_LENGTH]);
        Self { bytes: arr }
    }

    #[inline]
    fn to_bytes(&self) -> &[u8] {
        &self.bytes
    }

    #[inline]
    fn length() -> usize {
        SHORT_IDENTITY_LENGTH
    }
}

impl Display for ShortIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:08x}", u32::from_be_bytes(self.bytes))
    }
}

/// Server connection handler for the eval listener: generates a random 4-byte
/// identity per handshake, returns no server initial data, and accepts any
/// client version (eval client + server are always built from the same source).
pub struct EvalServerConnectionHandler;

impl ServerConnectionHandler<ShortIdentity> for EvalServerConnectionHandler {
    fn generate(&self, _initial_data: &[u8]) -> Option<ShortIdentity> {
        Some(ShortIdentity::from_u32(thread_rng().r#gen::<u32>()))
    }

    fn initial_data(&self, _identity: &ShortIdentity) -> StaticByteBuffer {
        StaticByteBuffer::from_slice(&[])
    }

    fn verify_version(&self, _version_bytes: &[u8]) -> bool {
        true
    }
}
