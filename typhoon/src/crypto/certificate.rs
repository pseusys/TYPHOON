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
    pub esk: SecretKey<'a>,
    pub vsk: SigningKey,
    pub opk: X25519PublicKey,
    pub osk: StaticSecret,
}

/// Server secret: McEliece secret key + Ed25519 signing key + obfuscation key.
#[cfg(feature = "fast")]
pub struct ServerSecret<'a> {
    pub esk: SecretKey<'a>,
    pub vsk: SigningKey,
    pub obfs: ByteBuffer,
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
    pub epk: McEliecePublicKey<'a>,
    pub vpk: VerifyingKey,
    pub opk: X25519PublicKey,
}

/// Client certificate: McEliece public key + Ed25519 verifying key + obfuscation key.
#[cfg(feature = "fast")]
pub struct Certificate<'a> {
    pub epk: McEliecePublicKey<'a>,
    pub vpk: VerifyingKey,
    pub obfs: ByteBuffer,
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
    pub ephemeral_key: EphemeralSecret,
    pub shared_secret: ByteBuffer,
    pub nonce: ByteBuffer,
}

/// Ephemeral server handshake state: client X25519 public key, McEliece shared secret, nonce.
pub struct ServerData {
    pub ephemeral_key: X25519PublicKey,
    pub shared_secret: ByteBuffer,
    pub nonce: ByteBuffer,
}
