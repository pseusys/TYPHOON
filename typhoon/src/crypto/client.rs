use x25519_dalek::EphemeralSecret;

use crate::bytes::{ByteBuffer, BytePool, DynamicByteBuffer, FixedByteBuffer};
use crate::certificate::ClientCertificate;
#[cfg(any(feature = "fast_software", feature = "fast_hardware"))]
use crate::certificate::ObfuscationBufferContainer;
use crate::crypto::error::{CryptoError, HandshakeError};
use crate::crypto::symmetric::{NONCE_LEN, ObfuscationTranscript, SYMMETRIC_ADDITIONAL_AUTH_LEN, SYMMETRIC_BUILT_IN_AUTH_LEN, Symmetric};
use crate::flow::FlowCryptoProvider;
use crate::tailor::IdentityType;

/// Ephemeral client handshake state: X25519 secret, McEliece shared secret, nonce, initial key.
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
    /// Create a new ClientCryptoTool with the given certificate and identity.
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

    /// Create a new ClientCryptoTool with the given certificate and identity.
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
    /// If `initial_data` is non-empty, encrypts it with the initial key and appends to the handshake.
    /// Returns (ClientData, handshake_secret, initial_encryption_key).
    pub(crate) fn create_handshake(&self, pool: &BytePool, initial_data: &[u8]) -> (ClientData, DynamicByteBuffer, FixedByteBuffer<32>) {
        self.cert.encapsulate_handshake_client(pool, initial_data)
    }

    /// Client handshake step 2: process server response, verify signature, derive session key.
    /// Returns (session_key, server_initial_data).
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

    /// Obfuscate (encrypt) tailor bytes for sending.
    #[cfg(any(feature = "fast_software", feature = "fast_hardware"))]
    pub fn obfuscate_tailor(&mut self, plaintext: DynamicByteBuffer, _: &BytePool) -> Result<DynamicByteBuffer, CryptoError> {
        self.obfuscation_key.encrypt_auth(plaintext, None::<&DynamicByteBuffer>)
    }

    /// Obfuscate (encrypt) tailor bytes for sending.
    #[cfg(any(feature = "full_software", feature = "full_hardware"))]
    pub fn obfuscate_tailor(&mut self, plaintext: DynamicByteBuffer, pool: &BytePool) -> Result<DynamicByteBuffer, CryptoError> {
        self.cert.encrypt_obfuscate(plaintext, pool).map_err(|e| CryptoError::authentication_error(&e.to_string()))
    }

    /// Deobfuscate (decrypt) received tailor bytes.
    #[cfg(any(feature = "fast_software", feature = "fast_hardware"))]
    pub fn deobfuscate_tailor(&mut self, ciphertext: DynamicByteBuffer, pool: &BytePool) -> Result<(DynamicByteBuffer, ObfuscationTranscript), CryptoError> {
        Ok(self.obfuscation_key.decrypt_no_verify(ciphertext, pool))
    }

    /// Deobfuscate (decrypt) received tailor bytes.
    #[cfg(any(feature = "full_software", feature = "full_hardware"))]
    pub fn deobfuscate_tailor(&mut self, ciphertext: DynamicByteBuffer, _pool: &BytePool) -> Result<(DynamicByteBuffer, ObfuscationTranscript), CryptoError> {
        self.key.decrypt_auth(ciphertext, None::<&DynamicByteBuffer>).map(|r| (r, ObfuscationTranscript {}))
    }

    /// Verify the authentication (fast mode).
    #[cfg(any(feature = "fast_software", feature = "fast_hardware"))]
    pub fn verify_tailor(&mut self, transcript: ObfuscationTranscript) -> Result<(), CryptoError> {
        self.obfuscation_key.verify_decrypted(transcript, None::<&DynamicByteBuffer>)
    }

    /// Verify tailor (no-op in full mode).
    #[cfg(any(feature = "full_software", feature = "full_hardware"))]
    pub fn verify_tailor(&mut self, _: ObfuscationTranscript) -> Result<(), CryptoError> {
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

impl<T: IdentityType + Clone> FlowCryptoProvider for ClientCryptoTool<T> {
    type Identity = T;

    #[inline]
    fn obfuscate_tailor(&mut self, plaintext: DynamicByteBuffer, pool: &BytePool) -> Result<DynamicByteBuffer, CryptoError> {
        self.obfuscate_tailor(plaintext, pool)
    }

    #[inline]
    fn deobfuscate_tailor(&mut self, ciphertext: DynamicByteBuffer, pool: &BytePool) -> Result<(DynamicByteBuffer, ObfuscationTranscript), CryptoError> {
        self.deobfuscate_tailor(ciphertext, pool)
    }

    #[inline]
    fn verify_tailor(&mut self, transcript: ObfuscationTranscript) -> Result<(), CryptoError> {
        self.verify_tailor(transcript)
    }

    #[inline]
    fn tailor_overhead() -> usize {
        Self::tailor_overhead()
    }
}
