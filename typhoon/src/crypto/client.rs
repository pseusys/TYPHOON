use crate::bytes::StaticByteBuffer;
use crate::bytes::{BytePool, DynamicByteBuffer};
use crate::crypto::certificate::{Certificate, ClientData, ObfuscationBufferContainer};
use crate::crypto::error::{CryptoError, HandshakeError};
use crate::crypto::symmetric::ObfuscationTranscript;
use crate::crypto::symmetric::{Symmetric, NONCE_LEN, SYMMETRIC_ADDITIONAL_AUTH_LEN, SYMMETRIC_BUILT_IN_AUTH_LEN};

/// Client-side cryptographic tool for TYPHOON protocol.
#[derive(Clone)]
pub struct ClientCryptoTool {
    cert: Certificate,
    identity: Vec<u8>,
    key: Symmetric,
    #[cfg(any(feature = "fast_software", feature = "fast_hardware"))]
    obfuscation_key: Symmetric,
}

impl ClientCryptoTool {
    /// Create a new ClientCryptoTool with the given certificate and identity.
    #[cfg(any(feature = "fast_software", feature = "fast_hardware"))]
    pub fn new(cert: Certificate, identity: DynamicByteBuffer, initial_key: &StaticByteBuffer) -> Self {
        let obfs_buffer = cert.obfuscation_buffer();
        Self {
            cert,
            identity: identity.into(),
            key: Symmetric::new(initial_key),
            obfuscation_key: Symmetric::new_split(obfs_buffer, initial_key.clone()),
        }
    }

    /// Create a new ClientCryptoTool with the given certificate and identity.
    #[cfg(any(feature = "full_software", feature = "full_hardware"))]
    pub fn new(cert: Certificate, identity: DynamicByteBuffer, initial_key: &StaticByteBuffer) -> Self {
        Self {
            cert,
            identity: identity.into(),
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
    pub fn identity(&self) -> Vec<u8> {
        self.identity.clone()
    }

    /// Get the identity length.
    #[inline]
    pub fn identity_len(&self) -> usize {
        self.identity.len()
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
        match self.cert.encrypt_obfuscate(plaintext, pool) {
            Ok(res) => Ok(res),
            Err(err) => Err(CryptoError::authentication_error(&err.to_string())),
        }
    }

    /// Deobfuscate (decrypt) received tailor bytes.
    #[cfg(any(feature = "fast_software", feature = "fast_hardware"))]
    pub fn deobfuscate_tailor(&mut self, ciphertext: DynamicByteBuffer) -> Result<(DynamicByteBuffer, ObfuscationTranscript), CryptoError> {
        Ok(self.obfuscation_key.decrypt_no_verify(ciphertext))
    }

    /// Deobfuscate (decrypt) received tailor bytes.
    #[cfg(any(feature = "full_software", feature = "full_hardware"))]
    pub fn deobfuscate_tailor(&mut self, ciphertext: DynamicByteBuffer) -> Result<(DynamicByteBuffer, ObfuscationTranscript), CryptoError> {
        match self.key.decrypt_auth(ciphertext, None::<&StaticByteBuffer>) {
            Ok(res) => Ok((res, ObfuscationTranscript {})),
            Err(err) => Err(err),
        }
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
