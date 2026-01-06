use ed25519_dalek::{SigningKey, VerifyingKey};
use x25519_dalek::EphemeralSecret;

#[cfg(feature = "full")]
use x25519_dalek::{PublicKey, StaticSecret};

#[cfg(feature = "fast")]
use classic_mceliece_rust::PublicKey;

#[cfg(feature = "fast")]
use crate::bytes::ByteBuffer;

// Server data is a server certificate, should be kept by server:

#[cfg(feature = "full")]
pub struct ServerData<'_> {
    pub(super) esk: StaticSecret,
    pub(super) vsk: SigningKey,
}

#[cfg(feature = "fast")]
pub struct ServerData<'a> {
    pub(super) esk: ByteBuffer<'a>,
    pub(super) vsk: SigningKey,
    pub(super) obfs: ByteBuffer<'a>,
}

// Certificate is a client certificate, should be kept by client:

#[cfg(feature = "full")]
pub struct Certificate<'_> {
    pub(super) epk: PublicKey,
    pub(super) vpk: VerifyingKey,
}

#[cfg(feature = "fast")]
pub struct Certificate<'a> {
    pub(super) epk: PublicKey<'a>,
    pub(super) vpk: VerifyingKey,
    pub(super) obfs: ByteBuffer<'a>,
}

// Client data is data that should be preserved by client during handshake:

pub struct ClientData<'a> {
    pub(super) private_key: EphemeralSecret,
    pub(super) shared_secret: ByteBuffer<'a>,
    pub(super) nonce: ByteBuffer<'a>,
}
