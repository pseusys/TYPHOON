use std::sync::Arc;

use classic_mceliece_rust::{PublicKey as McEliecePublicKey, SecretKey};
use ed25519_dalek::{SigningKey, VerifyingKey};
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey};

use crate::bytes::{DynamicByteBuffer, StaticByteBuffer};

#[cfg(any(feature = "full_software", feature = "full_hardware"))]
use x25519_dalek::StaticSecret;

/// Trait for types containing obfuscation key material.
pub trait ObfuscationBufferContainer {
    /// Get obfuscation buffer (OBFS in fast mode, OPK bytes in full mode).
    fn obfuscation_buffer(&self) -> StaticByteBuffer;
}

/// Server secret: McEliece secret key + Ed25519 signing key (+ X25519 in full mode).
#[cfg(any(feature = "full_software", feature = "full_hardware"))]
pub struct ServerSecret<'a> {
    pub esk: SecretKey<'a>,
    pub vsk: SigningKey,
    pub opk: X25519PublicKey,
    pub osk: StaticSecret,
}

/// Server secret: McEliece secret key + Ed25519 signing key + obfuscation key.
#[cfg(any(feature = "fast_software", feature = "fast_hardware"))]
pub struct ServerSecret<'a> {
    pub esk: SecretKey<'a>,
    pub vsk: SigningKey,
    pub obfs: StaticByteBuffer,
}

impl<'a> ObfuscationBufferContainer for ServerSecret<'a> {
    #[cfg(any(feature = "full_software", feature = "full_hardware"))]
    #[inline]
    fn obfuscation_buffer(&self) -> StaticByteBuffer {
        StaticByteBuffer::from(self.opk.as_bytes())
    }

    #[cfg(any(feature = "fast_software", feature = "fast_hardware"))]
    #[inline]
    fn obfuscation_buffer(&self) -> StaticByteBuffer {
        self.obfs.clone()
    }
}

/// Client certificate: McEliece public key + Ed25519 verifying key (+ X25519 in full mode).
#[cfg(any(feature = "full_software", feature = "full_hardware"))]
#[derive(Clone)]
pub struct Certificate {
    pub epk: Arc<McEliecePublicKey<'static>>,
    pub vpk: VerifyingKey,
    pub opk: X25519PublicKey,
}

/// Client certificate: McEliece public key + Ed25519 verifying key + obfuscation key.
#[cfg(any(feature = "fast_software", feature = "fast_hardware"))]
#[derive(Clone)]
pub struct Certificate {
    pub epk: Arc<McEliecePublicKey<'static>>,
    pub vpk: VerifyingKey,
    pub obfs: StaticByteBuffer,
}

impl ObfuscationBufferContainer for Certificate {
    #[cfg(any(feature = "full_software", feature = "full_hardware"))]
    #[inline]
    fn obfuscation_buffer(&self) -> StaticByteBuffer {
        StaticByteBuffer::from(self.opk.as_bytes())
    }

    #[cfg(any(feature = "fast_software", feature = "fast_hardware"))]
    #[inline]
    fn obfuscation_buffer(&self) -> StaticByteBuffer {
        self.obfs.clone()
    }
}

/// Ephemeral client handshake state: X25519 secret, McEliece shared secret, nonce.
pub struct ClientData {
    pub ephemeral_key: EphemeralSecret,
    pub shared_secret: StaticByteBuffer,
    pub nonce: StaticByteBuffer,
}

/// Ephemeral server handshake state: client X25519 public key, McEliece shared secret, nonce.
pub struct ServerData {
    pub ephemeral_key: X25519PublicKey,
    pub shared_secret: StaticByteBuffer,
    pub nonce: StaticByteBuffer,
}
