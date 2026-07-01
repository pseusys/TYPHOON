use x25519_dalek::EphemeralSecret;

use crate::bytes::{ByteBuffer, BytePool, DynamicByteBuffer, FixedByteBuffer};
use crate::certificate::ClientCertificate;
#[cfg(any(feature = "fast_software", feature = "fast_hardware"))]
use crate::certificate::ObfuscationBufferContainer;
use crate::crypto::error::{CryptoError, HandshakeError};
use crate::crypto::symmetric::{ObfuscationTranscript, Symmetric};
use crate::trailer::IdentityType;

/// Ephemeral client handshake state: X25519 secret, `McEliece` shared secret, nonce, initial key.
pub(crate) struct ClientData {
    pub ephemeral_key: EphemeralSecret,
    pub shared_secret: FixedByteBuffer<32>,
    pub nonce: FixedByteBuffer<32>,
    pub initial_key: FixedByteBuffer<32>,
}

/// Client-side cryptographic tool for TYPHOON protocol.
#[derive(Clone)]
pub struct ClientCryptoTool<T: IdentityType + Clone> {
    cert: ClientCertificate,
    identity: T,
    key: Symmetric,
    #[cfg(any(feature = "fast_software", feature = "fast_hardware"))]
    obfuscation_key: Symmetric,
}

impl<T: IdentityType + Clone> ClientCryptoTool<T> {
    /// Create a new `ClientCryptoTool` with the given certificate and identity.
    #[cfg(any(feature = "fast_software", feature = "fast_hardware"))]
    pub(crate) fn new(cert: ClientCertificate, identity: T, initial_key: &impl ByteBuffer) -> Self {
        let obfs_buffer = cert.obfuscation_buffer();
        Self {
            cert,
            identity,
            key: Symmetric::new(initial_key),
            obfuscation_key: Symmetric::new_split(&obfs_buffer, initial_key),
        }
    }

    /// Create a new `ClientCryptoTool` with the given certificate and identity.
    #[cfg(any(feature = "full_software", feature = "full_hardware"))]
    pub(crate) fn new(cert: ClientCertificate, identity: T, initial_key: &impl ByteBuffer) -> Self {
        Self {
            cert,
            identity,
            key: Symmetric::new(initial_key),
        }
    }

    /// Get the identity bytes.
    #[inline]
    pub fn identity(&self) -> T {
        self.identity.clone()
    }

    /// Client handshake step 1: generate ephemeral keys, encapsulate with `McEliece`, obfuscate.
    /// If `initial_data` is non-empty, encrypts it with the initial key and appends to the handshake.
    /// Returns (`ClientData`, `handshake_secret`, `initial_encryption_key`).
    pub(crate) fn create_handshake(&self, pool: &BytePool, initial_data: &[u8]) -> (ClientData, DynamicByteBuffer, FixedByteBuffer<32>) {
        self.cert.encapsulate_handshake_client(pool, initial_data)
    }

    /// Client handshake step 2: process server response, verify signature, derive session key.
    /// Returns (`session_key`, `server_initial_data`).
    pub(crate) fn process_handshake_response(&self, data: ClientData, handshake_secret: DynamicByteBuffer, pool: &BytePool) -> Result<(FixedByteBuffer<32>, DynamicByteBuffer), HandshakeError> {
        self.cert.decapsulate_handshake_client(data, handshake_secret, pool)
    }

    /// Encrypt payload data with session key.
    pub fn encrypt_payload(&mut self, plaintext: DynamicByteBuffer, additional_data: Option<&DynamicByteBuffer>) -> Result<DynamicByteBuffer, CryptoError> {
        self.key.encrypt_auth(plaintext, additional_data)
    }

    /// Decrypt payload data with session key.
    pub fn decrypt_payload(&mut self, ciphertext: DynamicByteBuffer, additional_data: Option<&DynamicByteBuffer>) -> Result<DynamicByteBuffer, CryptoError> {
        self.key.decrypt_auth(ciphertext, additional_data)
    }

    /// Obfuscate (encrypt) trailer bytes for sending.
    #[cfg(any(feature = "fast_software", feature = "fast_hardware"))]
    pub fn obfuscate_trailer(&mut self, plaintext: DynamicByteBuffer, _: &BytePool) -> Result<DynamicByteBuffer, CryptoError> {
        self.obfuscation_key.encrypt_auth(plaintext, None::<&DynamicByteBuffer>)
    }

    /// Obfuscate (encrypt) trailer bytes for sending.
    #[cfg(any(feature = "full_software", feature = "full_hardware"))]
    pub fn obfuscate_trailer(&mut self, plaintext: DynamicByteBuffer, pool: &BytePool) -> Result<DynamicByteBuffer, CryptoError> {
        self.cert.encrypt_obfuscate(plaintext, pool).map_err(|e| CryptoError::authentication_error(&e.to_string()))
    }

    /// Deobfuscate (decrypt) received trailer bytes.
    #[cfg(any(feature = "fast_software", feature = "fast_hardware"))]
    pub fn deobfuscate_trailer(&mut self, ciphertext: DynamicByteBuffer, pool: &BytePool) -> Result<(DynamicByteBuffer, ObfuscationTranscript), CryptoError> {
        self.obfuscation_key.decrypt_no_verify(ciphertext, pool)
    }

    /// Deobfuscate (decrypt) received trailer bytes.
    #[cfg(any(feature = "full_software", feature = "full_hardware"))]
    pub fn deobfuscate_trailer(&mut self, ciphertext: DynamicByteBuffer, _pool: &BytePool) -> Result<(DynamicByteBuffer, ObfuscationTranscript), CryptoError> {
        self.key.decrypt_auth(ciphertext, None::<&DynamicByteBuffer>).map(|r| (r, ObfuscationTranscript {}))
    }

    /// Verify the authentication (fast mode).
    #[cfg(any(feature = "fast_software", feature = "fast_hardware"))]
    pub fn verify_trailer(&mut self, transcript: ObfuscationTranscript) -> Result<(), CryptoError> {
        self.obfuscation_key.verify_decrypted(transcript, None::<&DynamicByteBuffer>)
    }

    /// Verify trailer (no-op in full mode).
    #[cfg(any(feature = "full_software", feature = "full_hardware"))]
    #[allow(clippy::unused_self)] // keeps the same call-site shape as the fast-mode variant
    pub fn verify_trailer(&mut self, _: ObfuscationTranscript) -> Result<(), CryptoError> {
        Ok(())
    }

    /// Create a copy of this crypto tool with a different session key.
    #[cfg(any(feature = "fast_software", feature = "fast_hardware"))]
    pub fn with_key(&self, new_key: &impl ByteBuffer) -> Self {
        let obfs_buffer = self.cert.obfuscation_buffer();
        Self {
            cert: self.cert.clone(),
            identity: self.identity.clone(),
            key: Symmetric::new(new_key),
            obfuscation_key: Symmetric::new_split(&obfs_buffer, new_key),
        }
    }

    /// Create a copy of this crypto tool with a different session key.
    #[cfg(any(feature = "full_software", feature = "full_hardware"))]
    pub fn with_key(&self, new_key: &impl ByteBuffer) -> Self {
        Self {
            cert: self.cert.clone(),
            identity: self.identity.clone(),
            key: Symmetric::new(new_key),
        }
    }

    /// Create a copy of this crypto tool with a different session key and identity.
    #[cfg(any(feature = "fast_software", feature = "fast_hardware"))]
    pub fn with_key_and_identity(&self, new_key: &impl ByteBuffer, new_identity: T) -> Self {
        let obfs_buffer = self.cert.obfuscation_buffer();
        Self {
            cert: self.cert.clone(),
            identity: new_identity,
            key: Symmetric::new(new_key),
            obfuscation_key: Symmetric::new_split(&obfs_buffer, new_key),
        }
    }

    /// Create a copy of this crypto tool with a different session key and identity.
    #[cfg(any(feature = "full_software", feature = "full_hardware"))]
    pub fn with_key_and_identity(&self, new_key: &impl ByteBuffer, new_identity: T) -> Self {
        Self {
            cert: self.cert.clone(),
            identity: new_identity,
            key: Symmetric::new(new_key),
        }
    }
}
