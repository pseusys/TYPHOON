//! Server key material: [`ServerKeyPair`] (file I/O) and [`ServerSecret`] (runtime crypto).

#[cfg(test)]
#[path = "../../tests/certificate/server.rs"]
mod tests;

use std::fmt::Debug;
use std::fs::File;
use std::io::{Read, Write};
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

use classic_mceliece_rust::{PublicKey as McEliecePublicKey, SecretKey, keypair_boxed};
use ed25519_dalek::SigningKey;
use rand::RngCore;
#[cfg(any(feature = "full_software", feature = "full_hardware"))]
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

use super::client::ClientCertificate;
#[cfg(any(feature = "full_software", feature = "full_hardware"))]
use super::utils::X25519_BYTES;
use super::utils::{CertificateError, ED25519_BYTES, EPK_BYTES, ESK_BYTES, ObfuscationBufferContainer, TYPE_SERVER, read_header, write_header};
use crate::bytes::FixedByteBuffer;
use crate::utils::random::get_rng;

// ── ServerSecret ──────────────────────────────────────────────────────────────

/// Server secret: McEliece secret key + Ed25519 signing key + X25519 obfuscation keys (full mode).
#[cfg(any(feature = "full_software", feature = "full_hardware"))]
pub(crate) struct ServerSecret<'a> {
    pub esk: SecretKey<'a>,
    pub vsk: SigningKey,
    pub opk: X25519PublicKey,
    pub osk: StaticSecret,
}

/// Server secret: McEliece secret key + Ed25519 signing key + obfuscation key (fast mode).
#[cfg(any(feature = "fast_software", feature = "fast_hardware"))]
pub(crate) struct ServerSecret<'a> {
    pub esk: SecretKey<'a>,
    pub vsk: SigningKey,
    pub obfs: FixedByteBuffer<ED25519_BYTES>,
}

impl<'a> ObfuscationBufferContainer for ServerSecret<'a> {
    #[cfg(any(feature = "full_software", feature = "full_hardware"))]
    #[inline]
    fn obfuscation_buffer(&self) -> FixedByteBuffer<ED25519_BYTES> {
        FixedByteBuffer::from(self.opk.as_bytes())
    }

    #[cfg(any(feature = "fast_software", feature = "fast_hardware"))]
    #[inline]
    fn obfuscation_buffer(&self) -> FixedByteBuffer<ED25519_BYTES> {
        self.obfs
    }
}

// ── ServerKeyPair ─────────────────────────────────────────────────────────────

/// Full server key material: McEliece + Ed25519 + symmetric obfuscation key (fast mode).
///
/// Generated once at server setup, saved to a file, and loaded on each server start.
/// Use [`to_client_certificate`](Self::to_client_certificate) to produce distributable client
/// certificates, and pass to [`ListenerBuilder::new`](crate::socket::ListenerBuilder::new) to
/// start the server.
#[cfg(any(feature = "fast_software", feature = "fast_hardware"))]
#[derive(Debug)]
pub struct ServerKeyPair {
    epk: Arc<McEliecePublicKey<'static>>,
    esk: SecretKey<'static>,
    vsk: SigningKey,
    obfs: FixedByteBuffer<ED25519_BYTES>,
}

/// Full server key material: McEliece + Ed25519 + X25519 obfuscation keys (full mode).
///
/// Generated once at server setup, saved to a file, and loaded on each server start.
/// Use [`to_client_certificate`](Self::to_client_certificate) to produce distributable client
/// certificates, and pass to [`ListenerBuilder::new`](crate::socket::ListenerBuilder::new) to
/// start the server.
#[cfg(any(feature = "full_software", feature = "full_hardware"))]
pub struct ServerKeyPair {
    epk: Arc<McEliecePublicKey<'static>>,
    esk: SecretKey<'static>,
    vsk: SigningKey,
    opk: X25519PublicKey,
    osk: StaticSecret,
}

impl ServerKeyPair {
    /// Generate a fresh server key pair using the system RNG.
    #[cfg(any(feature = "fast_software", feature = "fast_hardware"))]
    pub fn generate() -> Self {
        let rng = &mut get_rng();
        let (pk, sk) = keypair_boxed(rng);
        let mut vsk_bytes = [0u8; ED25519_BYTES];
        rng.fill_bytes(&mut vsk_bytes);
        let vsk = SigningKey::from_bytes(&vsk_bytes);
        let mut obfs_bytes = [0u8; ED25519_BYTES];
        rng.fill_bytes(&mut obfs_bytes);
        Self {
            epk: Arc::new(pk),
            esk: sk,
            vsk,
            obfs: FixedByteBuffer::from(obfs_bytes),
        }
    }

    /// Generate a fresh server key pair using the system RNG.
    #[cfg(any(feature = "full_software", feature = "full_hardware"))]
    pub fn generate() -> Self {
        let rng = &mut get_rng();
        let (pk, sk) = keypair_boxed(rng);
        let mut vsk_bytes = [0u8; ED25519_BYTES];
        rng.fill_bytes(&mut vsk_bytes);
        let vsk = SigningKey::from_bytes(&vsk_bytes);
        let osk = StaticSecret::random_from_rng(rng);
        let opk = X25519PublicKey::from(&osk);
        Self {
            epk: Arc::new(pk),
            esk: sk,
            vsk,
            opk,
            osk,
        }
    }

    /// Derive a client certificate from this key pair, embedding the given server addresses.
    #[cfg(any(feature = "fast_software", feature = "fast_hardware"))]
    pub fn to_client_certificate(&self, addresses: Vec<SocketAddr>) -> ClientCertificate {
        ClientCertificate {
            epk: self.epk.clone(),
            vpk: self.vsk.verifying_key(),
            obfs: self.obfs.clone(),
            addresses,
        }
    }

    /// Derive a client certificate from this key pair, embedding the given server addresses.
    #[cfg(any(feature = "full_software", feature = "full_hardware"))]
    pub fn to_client_certificate(&self, addresses: Vec<SocketAddr>) -> ClientCertificate {
        ClientCertificate {
            epk: self.epk.clone(),
            vpk: self.vsk.verifying_key(),
            opk: self.opk,
            addresses,
        }
    }

    /// Consume the key pair and return the inner [`ServerSecret`] for use with the socket layer.
    #[cfg(all(feature = "server", any(feature = "fast_software", feature = "fast_hardware")))]
    pub(crate) fn into_server_secret(self) -> ServerSecret<'static> {
        ServerSecret {
            esk: self.esk,
            vsk: self.vsk,
            obfs: self.obfs,
        }
    }

    /// Consume the key pair and return the inner [`ServerSecret`] for use with the socket layer.
    #[cfg(all(feature = "server", any(feature = "full_software", feature = "full_hardware")))]
    pub(crate) fn into_server_secret(self) -> ServerSecret<'static> {
        ServerSecret {
            esk: self.esk,
            vsk: self.vsk,
            opk: self.opk,
            osk: self.osk,
        }
    }

    /// Save the server key pair to a binary file (fast mode).
    ///
    /// # File layout (fast mode, `F`)
    ///
    /// | Offset       | Size                 | Field  | Description |
    /// |--------------|----------------------|--------|-------------|
    /// | 0            | 10                   | Header | Magic `TYPHOON`, type `S`, mode `F`, version `1` |
    /// | 10           | 261120 (`EPK_BYTES`) | EPK    | Classic McEliece 348864 public key |
    /// | 261130       | 6492 (`ESK_BYTES`)   | ESK    | Classic McEliece 348864 secret key |
    /// | 267622       | 32 (`ED25519_BYTES`) | VSK    | Ed25519 signing key (seed) |
    /// | 267654       | 32 (`ED25519_BYTES`) | OBFS   | Symmetric tailor obfuscation key |
    /// | **267686**   | —                    | EOF    | |
    #[cfg(any(feature = "fast_software", feature = "fast_hardware"))]
    pub fn save(&self, path: impl AsRef<Path>) -> Result<(), CertificateError> {
        let mut f = File::create(path)?;
        write_header(&mut f, TYPE_SERVER)?;
        f.write_all(self.epk.as_array())?;
        f.write_all(self.esk.as_array())?;
        f.write_all(&self.vsk.to_bytes())?;
        f.write_all(self.obfs.as_ref())?;
        Ok(())
    }

    /// Save the server key pair to a binary file (full mode).
    ///
    /// # File layout (full mode, `U`)
    ///
    /// | Offset       | Size                 | Field  | Description |
    /// |--------------|----------------------|--------|-------------|
    /// | 0            | 10                   | Header | Magic `TYPHOON`, type `S`, mode `U`, version `1` |
    /// | 10           | 261120 (`EPK_BYTES`) | EPK    | Classic McEliece 348864 public key |
    /// | 261130       | 6492 (`ESK_BYTES`)   | ESK    | Classic McEliece 348864 secret key |
    /// | 267622       | 32 (`ED25519_BYTES`) | VSK    | Ed25519 signing key (seed) |
    /// | 267654       | 32 (`X25519_BYTES`)  | OPK    | X25519 long-term public key |
    /// | 267686       | 32 (`X25519_BYTES`)  | OSK    | X25519 static secret key |
    /// | **267718**   | —                    | EOF    | |
    #[cfg(any(feature = "full_software", feature = "full_hardware"))]
    pub fn save(&self, path: impl AsRef<Path>) -> Result<(), CertificateError> {
        let mut f = File::create(path)?;
        write_header(&mut f, TYPE_SERVER)?;
        f.write_all(self.epk.as_array())?;
        f.write_all(self.esk.as_array())?;
        f.write_all(&self.vsk.to_bytes())?;
        f.write_all(self.opk.as_bytes())?;
        f.write_all(self.osk.as_bytes())?;
        Ok(())
    }

    /// Load a server key pair from a binary file produced by [`save`](Self::save) (fast mode).
    #[cfg(any(feature = "fast_software", feature = "fast_hardware"))]
    pub fn load(path: impl AsRef<Path>) -> Result<Self, CertificateError> {
        let mut f = File::open(path)?;
        read_header(&mut f, TYPE_SERVER)?;
        let mut epk_buf = Box::new([0u8; EPK_BYTES]);
        f.read_exact(epk_buf.as_mut())?;
        let mut esk_buf = Box::new([0u8; ESK_BYTES]);
        f.read_exact(esk_buf.as_mut())?;
        let mut vsk_arr = [0u8; ED25519_BYTES];
        f.read_exact(&mut vsk_arr)?;
        let vsk = SigningKey::from_bytes(&vsk_arr);
        let mut obfs_arr = [0u8; ED25519_BYTES];
        f.read_exact(&mut obfs_arr)?;
        Ok(Self {
            epk: Arc::new(McEliecePublicKey::from(epk_buf)),
            esk: SecretKey::from(esk_buf),
            vsk,
            obfs: FixedByteBuffer::from(obfs_arr),
        })
    }

    /// Load a server key pair from a binary file produced by [`save`](Self::save) (full mode).
    #[cfg(any(feature = "full_software", feature = "full_hardware"))]
    pub fn load(path: impl AsRef<Path>) -> Result<Self, CertificateError> {
        let mut f = File::open(path)?;
        read_header(&mut f, TYPE_SERVER)?;
        let mut epk_buf = Box::new([0u8; EPK_BYTES]);
        f.read_exact(epk_buf.as_mut())?;
        let mut esk_buf = Box::new([0u8; ESK_BYTES]);
        f.read_exact(esk_buf.as_mut())?;
        let mut vsk_arr = [0u8; ED25519_BYTES];
        f.read_exact(&mut vsk_arr)?;
        let vsk = SigningKey::from_bytes(&vsk_arr);
        let mut opk_arr = [0u8; X25519_BYTES];
        f.read_exact(&mut opk_arr)?;
        let mut osk_arr = [0u8; X25519_BYTES];
        f.read_exact(&mut osk_arr)?;
        Ok(Self {
            epk: Arc::new(McEliecePublicKey::from(epk_buf)),
            esk: SecretKey::from(esk_buf),
            vsk,
            opk: X25519PublicKey::from(opk_arr),
            osk: StaticSecret::from(osk_arr),
        })
    }
}

// ── Debug impl ────────────────────────────────────────────────────────────────

/// Manual Debug for full-mode ServerKeyPair: StaticSecret does not implement Debug.
#[cfg(any(feature = "full_software", feature = "full_hardware"))]
impl Debug for ServerKeyPair {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        f.debug_struct("ServerKeyPair").field("epk", &"<McEliece public key>").field("esk", &"<McEliece secret key>").field("vsk", &self.vsk).field("opk", &self.opk).field("osk", &"<X25519 static secret>").finish()
    }
}
