use crate::bytes::{BytePool, DynamicByteBuffer, StaticByteBuffer};
use crate::crypto::certificate::{Certificate, ClientData, ObfuscationBufferContainer};
use crate::crypto::error::{CryptoError, HandshakeError};
use crate::crypto::symmetric::{NONCE_LEN, ObfuscationTranscript, SYMMETRIC_ADDITIONAL_AUTH_LEN, SYMMETRIC_BUILT_IN_AUTH_LEN, Symmetric};
use crate::tailor::IdentityType;

/// Client-side cryptographic tool for TYPHOON protocol.
#[derive(Clone)]
pub struct ClientCryptoTool<T: IdentityType + Clone> {
    cert: Certificate,
    identity: T,
    key: Symmetric,
    #[cfg(any(feature = "fast_software", feature = "fast_hardware"))]
    obfuscation_key: Symmetric,
}

impl<T: IdentityType + Clone> ClientCryptoTool<T> {
    /// Create a new ClientCryptoTool with the given certificate and identity.
    #[cfg(any(feature = "fast_software", feature = "fast_hardware"))]
    pub fn new(cert: Certificate, identity: T, initial_key: &StaticByteBuffer) -> Self {
        let obfs_buffer = cert.obfuscation_buffer();
        Self {
            cert,
            identity,
            key: Symmetric::new(initial_key),
            obfuscation_key: Symmetric::new_split(obfs_buffer, initial_key.clone()),
        }
    }

    /// Create a new ClientCryptoTool with the given certificate and identity.
    #[cfg(any(feature = "full_software", feature = "full_hardware"))]
    pub fn new(cert: Certificate, identity: IdentityType, initial_key: &StaticByteBuffer) -> Self {
        Self {
            cert,
            identity,
            key: Symmetric::new(initial_key),
        }
    }

    /// Get certificate.
    #[inline]
    pub fn certificate(&self) -> Certificate {
        self.cert.clone()
    }

    /// Get the identity bytes.
    #[inline]
    pub fn identity(&self) -> T {
        self.identity.clone()
    }

    /// Get the identity length.
    #[inline]
    pub fn identity_len(&self) -> usize {
        T::length()
    }

    /// Overhead added by tailor encryption (nonce + auth tags).
    #[inline]
    pub fn tailor_overhead() -> usize {
        SYMMETRIC_BUILT_IN_AUTH_LEN + NONCE_LEN + SYMMETRIC_ADDITIONAL_AUTH_LEN
    }

    /// Client handshake step 1: generate ephemeral keys, encapsulate with McEliece, obfuscate.
    /// Returns (ClientData, handshake_secret, initial_cipher).
    pub fn create_handshake(&self, pool: &BytePool) -> (ClientData, DynamicByteBuffer, Symmetric) {
        self.cert.encapsulate_handshake_client(pool)
    }

    /// Client handshake step 2: process server response, verify signature, derive session key.
    /// Returns the session key bytes.
    pub fn process_handshake_response(&self, data: ClientData, handshake_secret: DynamicByteBuffer) -> Result<StaticByteBuffer, HandshakeError> {
        self.cert.decapsulate_handshake_client(data, handshake_secret)
    }

    /// Encrypt payload data with session key.
    pub fn encrypt_payload(&mut self, plaintext: DynamicByteBuffer, additional_data: Option<&DynamicByteBuffer>) -> Result<DynamicByteBuffer, CryptoError> {
        self.key.encrypt_auth(plaintext, additional_data)
    }

    /// Decrypt payload data with session key.
    pub fn decrypt_payload(&mut self, ciphertext: DynamicByteBuffer, additional_data: Option<&DynamicByteBuffer>) -> Result<DynamicByteBuffer, CryptoError> {
        self.key.decrypt_auth(ciphertext, additional_data)
    }

    /// Obfuscate (encrypt) tailor bytes for sending.
    #[cfg(any(feature = "fast_software", feature = "fast_hardware"))]
    pub fn obfuscate_tailor(&mut self, plaintext: DynamicByteBuffer, _: &BytePool) -> Result<DynamicByteBuffer, CryptoError> {
        self.obfuscation_key.encrypt_auth(plaintext, None::<&StaticByteBuffer>)
    }

    /// Obfuscate (encrypt) tailor bytes for sending.
    #[cfg(any(feature = "full_software", feature = "full_hardware"))]
    pub fn obfuscate_tailor(&mut self, plaintext: DynamicByteBuffer, pool: &BytePool) -> Result<DynamicByteBuffer, CryptoError> {
        self.cert.encrypt_obfuscate(plaintext, pool).map_err(|e| CryptoError::authentication_error(&e.to_string()))
    }

    /// Deobfuscate (decrypt) received tailor bytes.
    #[cfg(any(feature = "fast_software", feature = "fast_hardware"))]
    pub fn deobfuscate_tailor(&mut self, ciphertext: DynamicByteBuffer) -> Result<(DynamicByteBuffer, ObfuscationTranscript), CryptoError> {
        Ok(self.obfuscation_key.decrypt_no_verify(ciphertext))
    }

    /// Deobfuscate (decrypt) received tailor bytes.
    #[cfg(any(feature = "full_software", feature = "full_hardware"))]
    pub fn deobfuscate_tailor(&mut self, ciphertext: DynamicByteBuffer) -> Result<(DynamicByteBuffer, ObfuscationTranscript), CryptoError> {
        self.key.decrypt_auth(ciphertext, None::<&StaticByteBuffer>).map(|r| (r, ObfuscationTranscript {}))
    }

    /// Verify the authentication (fast mode).
    #[cfg(any(feature = "fast_software", feature = "fast_hardware"))]
    pub fn verify_tailor(&mut self, transcript: ObfuscationTranscript) -> Result<(), CryptoError> {
        self.obfuscation_key.verify_decrypted(transcript, None::<&StaticByteBuffer>)
    }

    /// Verify tailor (no-op in full mode).
    #[cfg(any(feature = "full_software", feature = "full_hardware"))]
    pub fn verify_tailor(&mut self, _: ObfuscationTranscript) -> Result<(), CryptoError> {
        Ok(())
    }
}
