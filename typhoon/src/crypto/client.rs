use crate::bytes::StaticByteBuffer;
use crate::bytes::{BytePool, DynamicByteBuffer};
use crate::crypto::certificate::{Certificate, ClientData, ObfuscationBufferContainer};
use crate::crypto::error::{CryptoError, HandshakeError};
use crate::crypto::symmetric::ObfuscationTranscript;
use crate::crypto::symmetric::{NONCE_LEN, SYMMETRIC_ADDITIONAL_AUTH_LEN, SYMMETRIC_BUILT_IN_AUTH_LEN, Symmetric};

#[cfg(feature = "fast")]
use crate::crypto::symmetric::{decrypt_auth, encrypt_auth, verify_auth};

/// Client-side cryptographic tool for TYPHOON protocol.
#[derive(Clone)]
pub struct ClientCryptoTool<'a> {
    cert: Certificate<'a>,
    identity: Vec<u8>,
    key: Symmetric,
    #[cfg(feature = "fast")]
    obfuscation: Symmetric,
    #[cfg(feature = "fast")]
    key_bytes: StaticByteBuffer,
}

impl<'a> ClientCryptoTool<'a> {
    /// Create a new ClientCryptoTool with the given certificate and identity.
    #[cfg(feature = "fast")]
    pub fn new(cert: Certificate<'a>, identity: DynamicByteBuffer, initial_key: &StaticByteBuffer) -> Self {
        let obfs_buffer = cert.obfuscation_buffer();
        Self {
            cert,
            identity: identity.into(),
            key: Symmetric::new(initial_key),
            obfuscation: Symmetric::new(&obfs_buffer),
            key_bytes: initial_key.to_owned(),
        }
    }

    /// Create a new ClientCryptoTool with the given certificate and identity.
    #[cfg(feature = "full")]
    pub fn new(cert: Certificate<'a>, identity: DynamicByteBuffer, initial_key: &StaticByteBuffer) -> Self {
        Self {
            cert,
            identity: identity.into(),
            key: Symmetric::new(initial_key),
        }
    }

    /// Get certificate.
    #[inline]
    pub fn certificate(&self) -> Certificate<'a> {
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
    #[cfg(feature = "fast")]
    pub fn obfuscate_tailor(&mut self, plaintext: DynamicByteBuffer) -> Result<DynamicByteBuffer, CryptoError> {
        Ok(encrypt_auth(&self.key_bytes, plaintext, &self.key_bytes))
    }

    /// Obfuscate (encrypt) tailor bytes for sending.
    #[cfg(feature = "full")]
    pub fn obfuscate_tailor(&mut self, plaintext: DynamicByteBuffer) -> Result<DynamicByteBuffer, CryptoError> {
        self.key.encrypt_auth::<StaticByteBuffer>(plaintext, None)
    }

    /// Deobfuscate (decrypt) received tailor bytes.
    #[cfg(feature = "fast")]
    pub fn deobfuscate_tailor(&mut self, ciphertext: DynamicByteBuffer) -> Result<(DynamicByteBuffer, ObfuscationTranscript), CryptoError> {
        Ok(decrypt_auth(&self.key_bytes, ciphertext))
    }

    /// Deobfuscate (decrypt) received tailor bytes.
    #[cfg(feature = "full")]
    pub fn deobfuscate_tailor(&mut self, ciphertext: DynamicByteBuffer) -> Result<(DynamicByteBuffer, ObfuscationTranscript), CryptoError> {
        match self.key.decrypt_auth::<StaticByteBuffer>(ciphertext, None) {
            Ok(res) => Ok((res, ObfuscationTranscript {})),
            Err(err) => Err(err),
        }
    }

    /// Verify the authentication (fast mode).
    #[cfg(feature = "fast")]
    pub fn verify_tailor(&mut self, transcript: ObfuscationTranscript) -> Result<(), CryptoError> {
        verify_auth(transcript, &self.key_bytes)
    }

    /// Verify tailor (no-op in full mode).
    #[cfg(feature = "full")]
    pub fn verify_tailor(&mut self, _: ObfuscationTranscript) -> Result<(), CryptoError> {
        Ok(())
    }
}
