use crate::{
    bytes::ByteBuffer,
    crypto::{
        certificate::{Certificate, ClientData, ObfuscationBufferContainer},
        error::{CryptoError, HandshakeError},
        symmetric::{NONCE_LEN, SYMMETRIC_FIRST_AUTH_LEN, SYMMETRIC_SECOND_AUTH_LEN, Symmetric},
        utils::ObfuscationTranscript,
        StandardPassword,
    },
};

/// Client-side cryptographic tool for TYPHOON protocol.
#[derive(Clone)]
pub struct ClientCryptoTool<'a> {
    cert: Certificate<'a>,
    identity: Vec<u8>,
    key: Symmetric,
    #[cfg(feature = "fast")]
    obfuscation: Symmetric,
    #[cfg(feature = "fast")]
    key_bytes: StandardPassword,
}

impl<'a> ClientCryptoTool<'a> {
    /// Create a new ClientCryptoTool with the given certificate and identity.
    #[cfg(feature = "fast")]
    pub fn new(cert: Certificate<'a>, identity: ByteBuffer, initial_key: &ByteBuffer) -> Self {
        let obfs_buffer = cert.obfuscation_buffer();
        Self {
            cert,
            identity: identity.into(),
            key: Symmetric::new(initial_key),
            obfuscation: Symmetric::new(&obfs_buffer),
            key_bytes: initial_key.into(),
        }
    }

    /// Create a new ClientCryptoTool with the given certificate and identity.
    #[cfg(feature = "full")]
    pub fn new(cert: Certificate<'a>, identity: ByteBuffer, initial_key: &ByteBuffer) -> Self {
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
        SYMMETRIC_FIRST_AUTH_LEN + NONCE_LEN + SYMMETRIC_SECOND_AUTH_LEN
    }

    /// Client handshake step 1: generate ephemeral keys, encapsulate with McEliece, obfuscate.
    /// Returns (ClientData, handshake_secret, initial_cipher).
    pub fn create_handshake(&self) -> (ClientData, ByteBuffer, Symmetric) {
        self.cert.encapsulate_handshake_client()
    }

    /// Client handshake step 2: process server response, verify signature, derive session key.
    /// Returns the session key bytes.
    pub fn process_handshake_response(
        &self,
        data: ClientData,
        handshake_secret: ByteBuffer,
    ) -> Result<ByteBuffer, HandshakeError> {
        self.cert.decapsulate_handshake_client(data, handshake_secret)
    }

    /// Encrypt payload data with session key.
    pub fn encrypt_payload(
        &mut self,
        plaintext: ByteBuffer,
        additional_data: Option<&ByteBuffer>,
    ) -> Result<ByteBuffer, CryptoError> {
        self.key.encrypt_auth(plaintext, additional_data)
    }

    /// Decrypt payload data with session key.
    pub fn decrypt_payload(
        &mut self,
        ciphertext: ByteBuffer,
        additional_data: Option<&ByteBuffer>,
    ) -> Result<ByteBuffer, CryptoError> {
        self.key.decrypt_auth(ciphertext, additional_data)
    }

    /// Obfuscate (encrypt) tailor bytes for sending.
    #[cfg(feature = "fast")]
    pub fn obfuscate_tailor(&mut self, plaintext: ByteBuffer) -> Result<ByteBuffer, CryptoError> {
        self.obfuscation
            .encrypt_auth_twice(plaintext, None, &ByteBuffer::from(&self.key_bytes))
    }

    /// Obfuscate (encrypt) tailor bytes for sending.
    #[cfg(feature = "full")]
    pub fn obfuscate_tailor(&mut self, plaintext: ByteBuffer) -> Result<ByteBuffer, CryptoError> {
        self.key.encrypt_auth(plaintext, None)
    }

    /// Deobfuscate (decrypt) received tailor bytes.
    #[cfg(feature = "fast")]
    pub fn deobfuscate_tailor(
        &mut self,
        ciphertext: ByteBuffer,
    ) -> Result<(ByteBuffer, ObfuscationTranscript), CryptoError> {
        match self.obfuscation.decrypt_auth_twice(ciphertext, None) {
            Ok((plaintext, ciphertext_copy, second_auth_transcript)) => Ok((
                plaintext,
                ObfuscationTranscript {
                    ciphertext_copy,
                    second_auth_transcript,
                },
            )),
            Err(err) => Err(err),
        }
    }

    /// Deobfuscate (decrypt) received tailor bytes.
    #[cfg(feature = "full")]
    pub fn deobfuscate_tailor(
        &mut self,
        ciphertext: ByteBuffer,
    ) -> Result<(ByteBuffer, ObfuscationTranscript), CryptoError> {
        match self.key.decrypt_auth(ciphertext, None) {
            Ok(res) => Ok((res, ObfuscationTranscript {})),
            Err(err) => Err(err),
        }
    }

    /// Verify the second authentication (fast mode).
    #[cfg(feature = "fast")]
    pub fn verify_tailor(&mut self, transcript: ObfuscationTranscript) -> Result<(), CryptoError> {
        self.obfuscation.verify_second_auth(
            &transcript.ciphertext_copy,
            None,
            &ByteBuffer::from(&self.key_bytes),
            &transcript.second_auth_transcript,
        )
    }

    /// Verify tailor (no-op in full mode).
    #[cfg(feature = "full")]
    pub fn verify_tailor(&mut self, _: ObfuscationTranscript) -> Result<(), CryptoError> {
        Ok(())
    }
}
