use std::sync::Arc;

use crate::{
    bytes::ByteBuffer,
    crypto::{
        certificate::{ObfuscationBufferContainer, ServerData, ServerSecret},
        error::{CryptoError, HandshakeError},
        symmetric::{NONCE_LEN, SYMMETRIC_FIRST_AUTH_LEN, SYMMETRIC_SECOND_AUTH_LEN, Symmetric},
        utils::ObfuscationTranscript,
        StandardPassword,
    },
};

/// Server-side cryptographic tool for TYPHOON protocol.
#[derive(Clone)]
pub struct ServerCryptoTool<'a> {
    secret: Arc<ServerSecret<'a>>,
    key: Symmetric,
    #[cfg(feature = "fast")]
    obfuscation: Symmetric,
    #[cfg(feature = "fast")]
    key_bytes: StandardPassword,
}

impl<'a> ServerCryptoTool<'a> {
    /// Create a new ServerCryptoTool with the given server secret.
    #[cfg(feature = "fast")]
    pub fn new(secret: Arc<ServerSecret<'a>>, initial_key: &ByteBuffer) -> Self {
        let obfs_buffer = secret.obfuscation_buffer();
        Self {
            secret,
            key: Symmetric::new(initial_key),
            obfuscation: Symmetric::new(&obfs_buffer),
            key_bytes: initial_key.into(),
        }
    }

    /// Create a new ServerCryptoTool with the given server secret.
    #[cfg(feature = "full")]
    pub fn new(secret: Arc<ServerSecret<'a>>, initial_key: &ByteBuffer) -> Self {
        Self {
            secret,
            key: Symmetric::new(initial_key),
        }
    }

    /// Overhead added by tailor encryption (nonce + auth tags).
    #[inline]
    pub fn tailor_overhead() -> usize {
        SYMMETRIC_FIRST_AUTH_LEN + NONCE_LEN + SYMMETRIC_SECOND_AUTH_LEN
    }

    /// Reset the session key after handshake completion.
    #[cfg(feature = "fast")]
    pub fn reset_session_key(&mut self, key: ByteBuffer) {
        self.key_bytes = (&key).into();
        self.key = Symmetric::new(&key);
    }

    /// Reset the session key after handshake completion.
    #[cfg(feature = "full")]
    pub fn reset_session_key(&mut self, key: ByteBuffer) {
        self.key = Symmetric::new(&key);
    }

    /// Server handshake step 1: process client handshake, decapsulate McEliece, derive initial cipher.
    /// Returns (ServerData, initial_cipher).
    pub fn process_client_handshake(&self, handshake_secret: ByteBuffer) -> (ServerData, Symmetric) {
        self.secret.decapsulate_handshake_server(handshake_secret)
    }

    /// Server handshake step 2: create response with ephemeral X25519, sign transcript.
    /// Returns (handshake_secret, session_cipher).
    pub fn create_handshake_response(&self, data: ServerData) -> (ByteBuffer, Symmetric) {
        self.secret.encapsulate_handshake_server(data)
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
        match self.secret.decrypt_deobfuscate(ciphertext) {
            Ok(res) => Ok((res, ObfuscationTranscript {})),
            Err(err) => match err {
                HandshakeError::CryptoError { cause: _, source } => Err(source),
                _ => Err(CryptoError::UnknownError),
            },
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
