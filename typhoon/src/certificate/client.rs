//! Client certificate: public keys + server addresses distributed to clients.

use std::fs::File;
use std::io::{Read, Write};
use std::net::SocketAddr;
use std::sync::Arc;

use classic_mceliece_rust::PublicKey as McEliecePublicKey;
use ed25519_dalek::VerifyingKey;
#[cfg(any(feature = "full_software", feature = "full_hardware"))]
use x25519_dalek::PublicKey as X25519PublicKey;

use crate::bytes::FixedByteBuffer;

use super::utils::{
    CertificateError, ED25519_BYTES, EPK_BYTES, ObfuscationBufferContainer, TYPE_CLIENT,
    read_addresses, read_header, write_addresses, write_header,
};
#[cfg(any(feature = "full_software", feature = "full_hardware"))]
use super::utils::X25519_BYTES;

// ── ClientCertificate ─────────────────────────────────────────────────────────

/// Client-side connection descriptor: crypto public keys + server addresses (fast mode).
///
/// Derived from a [`ServerKeyPair`](super::ServerKeyPair) and distributed to clients out-of-band.
/// Pass directly to [`ClientSocketBuilder::new`](crate::socket::ClientSocketBuilder::new).
#[cfg(any(feature = "fast_software", feature = "fast_hardware"))]
#[derive(Clone, Debug)]
pub struct ClientCertificate {
    pub(crate) epk: Arc<McEliecePublicKey<'static>>,
    pub(crate) vpk: VerifyingKey,
    pub(crate) obfs: FixedByteBuffer<ED25519_BYTES>,
    pub(crate) addresses: Vec<SocketAddr>,
}

/// Client-side connection descriptor: crypto public keys + server addresses (full mode).
///
/// Derived from a [`ServerKeyPair`](super::ServerKeyPair) and distributed to clients out-of-band.
/// Pass directly to [`ClientSocketBuilder::new`](crate::socket::ClientSocketBuilder::new).
#[cfg(any(feature = "full_software", feature = "full_hardware"))]
#[derive(Clone, Debug)]
pub struct ClientCertificate {
    pub(crate) epk: Arc<McEliecePublicKey<'static>>,
    pub(crate) vpk: VerifyingKey,
    pub(crate) opk: X25519PublicKey,
    pub(crate) addresses: Vec<SocketAddr>,
}

impl ClientCertificate {
    /// Return the server addresses embedded in this certificate.
    pub fn addresses(&self) -> &[SocketAddr] {
        &self.addresses
    }

    /// Save the client certificate to a binary file (fast mode).
    ///
    /// # File layout (fast mode, `F`)
    ///
    /// | Offset | Size                 | Field      | Description |
    /// |--------|----------------------|------------|-------------|
    /// | 0      | 10                   | Header     | Magic `TYPHOON`, type `C`, mode `F`, version `1` |
    /// | 10     | 261120 (`EPK_BYTES`) | EPK        | Classic McEliece 348864 public key |
    /// | 261130 | 32 (`ED25519_BYTES`) | VPK        | Ed25519 verifying key |
    /// | 261162 | 32 (`ED25519_BYTES`) | OBFS       | Symmetric tailor obfuscation key |
    /// | 261194 | 2                    | ADDR_COUNT | Number of addresses (big-endian u16) |
    /// | 261196 | varies               | ADDRS      | Address list; each entry: 1-byte family (`4`/`6`), 4 or 16 IP bytes, 2-byte port (big-endian) |
    #[cfg(any(feature = "fast_software", feature = "fast_hardware"))]
    pub fn save(&self, path: impl AsRef<std::path::Path>) -> Result<(), CertificateError> {
        let mut f = File::create(path)?;
        write_header(&mut f, TYPE_CLIENT)?;
        f.write_all(self.epk.as_array())?;
        f.write_all(&self.vpk.to_bytes())?;
        f.write_all(self.obfs.as_ref())?;
        write_addresses(&mut f, &self.addresses)?;
        Ok(())
    }

    /// Save the client certificate to a binary file (full mode).
    ///
    /// # File layout (full mode, `U`)
    ///
    /// | Offset | Size                 | Field      | Description |
    /// |--------|----------------------|------------|-------------|
    /// | 0      | 10                   | Header     | Magic `TYPHOON`, type `C`, mode `U`, version `1` |
    /// | 10     | 261120 (`EPK_BYTES`) | EPK        | Classic McEliece 348864 public key |
    /// | 261130 | 32 (`ED25519_BYTES`) | VPK        | Ed25519 verifying key |
    /// | 261162 | 32 (`X25519_BYTES`)  | OPK        | X25519 long-term public key |
    /// | 261194 | 2                    | ADDR_COUNT | Number of addresses (big-endian u16) |
    /// | 261196 | varies               | ADDRS      | Address list; each entry: 1-byte family (`4`/`6`), 4 or 16 IP bytes, 2-byte port (big-endian) |
    #[cfg(any(feature = "full_software", feature = "full_hardware"))]
    pub fn save(&self, path: impl AsRef<std::path::Path>) -> Result<(), CertificateError> {
        let mut f = File::create(path)?;
        write_header(&mut f, TYPE_CLIENT)?;
        f.write_all(self.epk.as_array())?;
        f.write_all(&self.vpk.to_bytes())?;
        f.write_all(self.opk.as_bytes())?;
        write_addresses(&mut f, &self.addresses)?;
        Ok(())
    }

    /// Load a client certificate from a binary file produced by [`save`](Self::save) (fast mode).
    #[cfg(any(feature = "fast_software", feature = "fast_hardware"))]
    pub fn load(path: impl AsRef<std::path::Path>) -> Result<Self, CertificateError> {
        let mut f = File::open(path)?;
        read_header(&mut f, TYPE_CLIENT)?;
        let mut epk_buf = Box::new([0u8; EPK_BYTES]);
        f.read_exact(epk_buf.as_mut())?;
        let mut vpk_arr = [0u8; ED25519_BYTES];
        f.read_exact(&mut vpk_arr)?;
        let vpk = VerifyingKey::from_bytes(&vpk_arr).map_err(|_| CertificateError::InvalidKeyData)?;
        let mut obfs_arr = [0u8; ED25519_BYTES];
        f.read_exact(&mut obfs_arr)?;
        let addresses = read_addresses(&mut f)?;
        Ok(Self {
            epk: Arc::new(McEliecePublicKey::from(epk_buf)),
            vpk,
            obfs: FixedByteBuffer::from(obfs_arr),
            addresses,
        })
    }

    /// Load a client certificate from a binary file produced by [`save`](Self::save) (full mode).
    #[cfg(any(feature = "full_software", feature = "full_hardware"))]
    pub fn load(path: impl AsRef<std::path::Path>) -> Result<Self, CertificateError> {
        let mut f = File::open(path)?;
        read_header(&mut f, TYPE_CLIENT)?;
        let mut epk_buf = Box::new([0u8; EPK_BYTES]);
        f.read_exact(epk_buf.as_mut())?;
        let mut vpk_arr = [0u8; ED25519_BYTES];
        f.read_exact(&mut vpk_arr)?;
        let vpk = VerifyingKey::from_bytes(&vpk_arr).map_err(|_| CertificateError::InvalidKeyData)?;
        let mut opk_arr = [0u8; X25519_BYTES];
        f.read_exact(&mut opk_arr)?;
        let addresses = read_addresses(&mut f)?;
        Ok(Self {
            epk: Arc::new(McEliecePublicKey::from(epk_buf)),
            vpk,
            opk: X25519PublicKey::from(opk_arr),
            addresses,
        })
    }
}

// ── ObfuscationBufferContainer impl ──────────────────────────────────────────

impl ObfuscationBufferContainer for ClientCertificate {
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

// ── Test accessors ────────────────────────────────────────────────────────────

#[cfg(test)]
impl ClientCertificate {
    pub(crate) fn epk_bytes(&self) -> &[u8] { self.epk.as_array() }
    pub(crate) fn vpk_bytes(&self) -> [u8; 32] { self.vpk.to_bytes() }
    #[cfg(any(feature = "fast_software", feature = "fast_hardware"))]
    pub(crate) fn obfs_bytes(&self) -> &[u8] { self.obfs.as_ref() }
    #[cfg(any(feature = "full_software", feature = "full_hardware"))]
    pub(crate) fn opk_bytes(&self) -> &[u8] { self.opk.as_bytes() }
}
