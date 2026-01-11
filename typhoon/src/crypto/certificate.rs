use classic_mceliece_rust::{PublicKey as McEliecePublicKey, SecretKey};
use ed25519_dalek::{SigningKey, VerifyingKey};
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey};

use crate::bytes::ByteBuffer;

#[cfg(feature = "full")]
use x25519_dalek::StaticSecret;

/// Trait for types containing obfuscation key material.
pub trait ObfuscationBufferContainer {
    /// Get obfuscation buffer (OBFS in fast mode, OPK bytes in full mode).
    fn obfuscation_buffer(&self) -> ByteBuffer;
}

/// Server secret: McEliece secret key + Ed25519 signing key (+ X25519 in full mode).
#[cfg(feature = "full")]
pub struct ServerSecret<'a> {
    pub(super) esk: SecretKey<'a>,
    pub(super) vsk: SigningKey,
    pub(super) opk: X25519PublicKey,
    pub(super) osk: StaticSecret,
}

/// Server secret: McEliece secret key + Ed25519 signing key + obfuscation key.
#[cfg(feature = "fast")]
pub struct ServerSecret<'a> {
    pub(super) esk: SecretKey<'a>,
    pub(super) vsk: SigningKey,
    pub(super) obfs: ByteBuffer,
}

impl<'a> ObfuscationBufferContainer for ServerSecret<'a> {
    #[cfg(feature = "full")]
    #[inline]
    fn obfuscation_buffer(&self) -> ByteBuffer {
        ByteBuffer::from(self.opk.as_bytes())
    }

    #[cfg(feature = "fast")]
    #[inline]
    fn obfuscation_buffer(&self) -> ByteBuffer {
        self.obfs.clone()
    }
}

/// Client certificate: McEliece public key + Ed25519 verifying key (+ X25519 in full mode).
#[cfg(feature = "full")]
pub struct Certificate<'a> {
    pub(super) epk: McEliecePublicKey<'a>,
    pub(super) vpk: VerifyingKey,
    pub(super) opk: X25519PublicKey,
}

/// Client certificate: McEliece public key + Ed25519 verifying key + obfuscation key.
#[cfg(feature = "fast")]
pub struct Certificate<'a> {
    pub(super) epk: McEliecePublicKey<'a>,
    pub(super) vpk: VerifyingKey,
    pub(super) obfs: ByteBuffer,
}

impl<'a> ObfuscationBufferContainer for Certificate<'a> {
    #[cfg(feature = "full")]
    #[inline]
    fn obfuscation_buffer(&self) -> ByteBuffer {
        ByteBuffer::from(self.opk.as_bytes())
    }

    #[cfg(feature = "fast")]
    #[inline]
    fn obfuscation_buffer(&self) -> ByteBuffer {
        self.obfs.clone()
    }
}

/// Ephemeral client handshake state: X25519 secret, McEliece shared secret, nonce.
pub struct ClientData {
    pub(super) ephemeral_key: EphemeralSecret,
    pub(super) shared_secret: ByteBuffer,
    pub(super) nonce: ByteBuffer,
}

/// Ephemeral server handshake state: client X25519 public key, McEliece shared secret, nonce.
pub struct ServerData {
    pub(super) ephemeral_key: X25519PublicKey,
    pub(super) shared_secret: ByteBuffer,
    pub(super) nonce: ByteBuffer,
}
