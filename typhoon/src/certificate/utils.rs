//! Shared constants, header I/O helpers, and error types for certificate files.

use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use classic_mceliece_rust::{CRYPTO_PUBLICKEYBYTES, CRYPTO_SECRETKEYBYTES};

use crate::bytes::StaticByteBuffer;

// ── Stable format constants ──────────────────────────────────────────────────

/// Classic McEliece 348864 public key size in bytes.
pub const EPK_BYTES: usize = 261_120;
/// Classic McEliece 348864 secret key size in bytes.
pub const ESK_BYTES: usize = 6_492;
/// Ed25519 key size in bytes (signing key, verifying key, or obfuscation key).
pub const ED25519_BYTES: usize = 32;
/// X25519 key size in bytes (public or static secret).
pub const X25519_BYTES: usize = 32;

// Compile-time guards: catch upstream constant drift before it silently corrupts files.
const _: () = assert!(EPK_BYTES == CRYPTO_PUBLICKEYBYTES, "EPK_BYTES must match CRYPTO_PUBLICKEYBYTES");
const _: () = assert!(ESK_BYTES == CRYPTO_SECRETKEYBYTES, "ESK_BYTES must match CRYPTO_SECRETKEYBYTES");

// ── File header constants ────────────────────────────────────────────────────

pub(crate) const MAGIC: &[u8; 7] = b"TYPHOON";
pub(crate) const TYPE_SERVER: u8 = b'S';
pub(crate) const TYPE_CLIENT: u8 = b'C';
pub(crate) const FORMAT_VERSION: u8 = 1;

#[cfg(any(feature = "fast_software", feature = "fast_hardware"))]
pub(crate) const MODE_BYTE: u8 = b'F';
#[cfg(any(feature = "full_software", feature = "full_hardware"))]
pub(crate) const MODE_BYTE: u8 = b'U';

// ── CertificateError ─────────────────────────────────────────────────────────

/// Error type for certificate file operations.
#[derive(Debug, thiserror::Error)]
pub enum CertificateError {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("invalid file: bad magic bytes")]
    InvalidMagic,
    #[error("invalid file type: expected '{expected}', got '{got}'")]
    InvalidType { expected: char, got: char },
    #[error("mode mismatch: file was written for a different crypto mode")]
    ModeMismatch,
    #[error("unsupported format version: {0}")]
    UnsupportedVersion(u8),
    #[error("invalid key data in file")]
    InvalidKeyData,
    #[error("certificate contains no server addresses")]
    NoAddresses,
}

// ── Header I/O ────────────────────────────────────────────────────────────────

pub(crate) fn write_header(w: &mut impl Write, record_type: u8) -> Result<(), io::Error> {
    w.write_all(MAGIC)?;
    w.write_all(&[record_type, MODE_BYTE, FORMAT_VERSION])
}

pub(crate) fn read_header(r: &mut impl Read, expected_type: u8) -> Result<(), CertificateError> {
    let mut magic = [0u8; 7];
    r.read_exact(&mut magic)?;
    if &magic != MAGIC {
        return Err(CertificateError::InvalidMagic);
    }
    let mut header = [0u8; 3];
    r.read_exact(&mut header)?;
    let [record_type, mode, version] = header;
    if record_type != expected_type {
        return Err(CertificateError::InvalidType { expected: expected_type as char, got: record_type as char });
    }
    if mode != MODE_BYTE {
        return Err(CertificateError::ModeMismatch);
    }
    if version != FORMAT_VERSION {
        return Err(CertificateError::UnsupportedVersion(version));
    }
    Ok(())
}

// ── Address I/O ───────────────────────────────────────────────────────────────

pub(crate) fn write_addresses(w: &mut impl Write, addrs: &[SocketAddr]) -> Result<(), io::Error> {
    w.write_all(&(addrs.len() as u16).to_be_bytes())?;
    for addr in addrs {
        match addr.ip() {
            IpAddr::V4(ip) => {
                w.write_all(&[4u8])?;
                w.write_all(&ip.octets())?;
            }
            IpAddr::V6(ip) => {
                w.write_all(&[6u8])?;
                w.write_all(&ip.octets())?;
            }
        }
        w.write_all(&addr.port().to_be_bytes())?;
    }
    Ok(())
}

pub(crate) fn read_addresses(r: &mut impl Read) -> Result<Vec<SocketAddr>, CertificateError> {
    let mut count_bytes = [0u8; 2];
    r.read_exact(&mut count_bytes)?;
    let count = u16::from_be_bytes(count_bytes) as usize;
    let mut addrs = Vec::with_capacity(count);
    for _ in 0..count {
        let mut family = [0u8; 1];
        r.read_exact(&mut family)?;
        let ip = match family[0] {
            4 => {
                let mut octets = [0u8; 4];
                r.read_exact(&mut octets)?;
                IpAddr::V4(Ipv4Addr::from(octets))
            }
            6 => {
                let mut octets = [0u8; 16];
                r.read_exact(&mut octets)?;
                IpAddr::V6(Ipv6Addr::from(octets))
            }
            _ => return Err(CertificateError::InvalidKeyData),
        };
        let mut port_bytes = [0u8; 2];
        r.read_exact(&mut port_bytes)?;
        addrs.push(SocketAddr::new(ip, u16::from_be_bytes(port_bytes)));
    }
    Ok(addrs)
}

// ── ObfuscationBufferContainer ────────────────────────────────────────────────

/// Trait for types containing obfuscation key material.
pub(crate) trait ObfuscationBufferContainer {
    /// Get obfuscation buffer (OBFS in fast mode, OPK bytes in full mode).
    fn obfuscation_buffer(&self) -> StaticByteBuffer;
}
