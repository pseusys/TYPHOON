use classic_mceliece_rust::{PublicKey as McEliecePublicKey, SecretKey};
use ed25519_dalek::{SigningKey, VerifyingKey};
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey};

use crate::bytes::ByteBuffer;

pub trait ObfuscationBufferContainer<'a> {
    fn obfuscation_buffer(&'a self) -> ByteBuffer<'a>;
}

// Server secret is a server certificate, should be kept by server:

#[cfg(feature = "full")]
pub struct ServerSecret<'a> {
    pub(super) esk: SecretKey<'a>,
    pub(super) vsk: SigningKey,
    pub(super) opk: X25519PublicKey,
    pub(super) osk: SecretKey<'a>,
}

#[cfg(feature = "fast")]
pub struct ServerSecret<'a> {
    pub(super) esk: SecretKey<'a>,
    pub(super) vsk: SigningKey,
    pub(super) obfs: ByteBuffer<'a>,
}

impl<'a> ObfuscationBufferContainer<'a> for ServerSecret<'a> {
    #[inline]
    #[cfg(feature = "full")]
    fn obfuscation_buffer(&self) -> ByteBuffer<'a> {
        ByteBuffer::from(&self.opk.as_bytes()[..])
    }

    #[inline]
    #[cfg(feature = "fast")]
    fn obfuscation_buffer(&self) -> ByteBuffer<'a> {
        self.obfs.clone()
    }
}

// Certificate is a client certificate, should be kept by client:

#[cfg(feature = "full")]
pub struct Certificate<'a> {
    pub(super) epk: McEliecePublicKey<'a>,
    pub(super) vpk: VerifyingKey,
    pub(super) opk: X25519PublicKey,
}

#[cfg(feature = "fast")]
pub struct Certificate<'a> {
    pub(super) epk: McEliecePublicKey<'a>,
    pub(super) vpk: VerifyingKey,
    pub(super) obfs: ByteBuffer<'a>,
}

impl<'a> ObfuscationBufferContainer<'a> for Certificate<'a> {
    #[inline]
    #[cfg(feature = "full")]
    fn obfuscation_buffer(&self) -> ByteBuffer<'a> {
        ByteBuffer::from(&self.opk.as_bytes()[..])
    }

    #[inline]
    #[cfg(feature = "fast")]
    fn obfuscation_buffer(&self) -> ByteBuffer<'a> {
        self.obfs.clone()
    }
}

// This data should be preserved by client or server during handshake:

pub struct ClientData<'a> {
    pub(super) ephemeral_key: EphemeralSecret,
    pub(super) shared_secret: ByteBuffer<'a>,
    pub(super) nonce: ByteBuffer<'a>,
}

pub struct ServerData<'a> {
    pub(super) ephemeral_key: X25519PublicKey,
    pub(super) shared_secret: ByteBuffer<'a>,
    pub(super) nonce: ByteBuffer<'a>,
}
