use std::sync::Arc;

use crate::{
    bytes::ByteBuffer,
    crypto::{
        certificate::{Certificate, ServerSecret},
        error::{CryptoError, HandshakeError},
        symmetric::{NONCE_LEN, SYMMETRIC_FIRST_AUTH_LEN, SYMMETRIC_SECOND_AUTH_LEN, Symmetric},
    },
};

#[cfg(feature = "fast")]
pub struct ObfuscationTranscript {
    ciphertext_copy: ByteBuffer,
    second_auth_transcript: ByteBuffer,
}

#[cfg(feature = "full")]
pub struct ObfuscationTranscript {}

pub trait CryptoTool {
    fn tailor_overhead() -> usize;

    fn reset_session_key(&mut self, key: ByteBuffer);

    fn obfuscate_tailor(&mut self, plaintext: ByteBuffer) -> Result<ByteBuffer, CryptoError>;
    fn deobfuscate_tailor(&mut self, ciphertext: ByteBuffer) -> Result<(ByteBuffer, ObfuscationTranscript), CryptoError>;
    fn verify_tailor(&mut self, transcript: ObfuscationTranscript) -> Result<(), CryptoError>;
}

#[cfg(feature = "server")]
pub struct ServerCryptoTool<'a> {
    secret: Arc<ServerSecret<'a>>,
    key: Symmetric,
    #[cfg(feature = "fast")]
    obfuscation: Symmetric,
    #[cfg(feature = "fast")]
    key_bytes: ByteBuffer,
}

#[cfg(feature = "server")]
impl<'a> CryptoTool for ServerCryptoTool<'a> {
    fn tailor_overhead() -> usize {
        SYMMETRIC_FIRST_AUTH_LEN + NONCE_LEN + SYMMETRIC_SECOND_AUTH_LEN
    }

    #[cfg(feature = "fast")]
    fn reset_session_key(&mut self, key: ByteBuffer) {
        self.key_bytes = key.copy();
        self.key = Symmetric::new(&key);
    }

    #[cfg(feature = "full")]
    fn reset_session_key(&mut self, key: ByteBuffer) {
        self.key = Symmetric::new(&key);
    }

    #[cfg(feature = "fast")]
    fn obfuscate_tailor(&mut self, plaintext: ByteBuffer) -> Result<ByteBuffer, CryptoError> {
        self.obfuscation.encrypt_auth_twice(plaintext, None, &self.key_bytes)
    }

    #[cfg(feature = "full")]
    fn obfuscate_tailor(&mut self, plaintext: ByteBuffer) -> Result<ByteBuffer, CryptoError> {
        self.key.encrypt_auth(plaintext, None)
    }

    #[cfg(feature = "fast")]
    fn deobfuscate_tailor(&mut self, ciphertext: ByteBuffer) -> Result<(ByteBuffer, ObfuscationTranscript), CryptoError> {
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

    #[cfg(feature = "full")]
    fn deobfuscate_tailor(&mut self, ciphertext: ByteBuffer) -> Result<(ByteBuffer, ObfuscationTranscript), CryptoError> {
        match self.secret.decrypt_deobfuscate(ciphertext) {
            Ok(res) => Ok((res, ObfuscationTranscript {})),
            Err(err) => match err {
                HandshakeError::CryptoError {
                    cause: _,
                    source,
                } => Err(source),
                _ => Err(CryptoError::UnknownError),
            },
        }
    }

    #[cfg(feature = "fast")]
    fn verify_tailor(&mut self, transcript: ObfuscationTranscript) -> Result<(), CryptoError> {
        match self.obfuscation.verify_second_auth(&transcript.ciphertext_copy, None, &self.key_bytes, &transcript.second_auth_transcript) {
            Ok(_) => Ok(()),
            Err(err) => Err(err),
        }
    }

    #[cfg(feature = "full")]
    fn verify_tailor(&mut self, _: ObfuscationTranscript) -> Result<(), CryptoError> {
        Ok(())
    }
}

#[cfg(feature = "server")]
impl Clone for ServerCryptoTool<'_> {
    #[cfg(feature = "fast")]
    fn clone(&self) -> Self {
        Self {
            secret: self.secret.clone(),
            key: self.key.clone(),
            obfuscation: self.obfuscation.clone(),
            key_bytes: self.key_bytes.clone(),
        }
    }

    #[cfg(feature = "full")]
    fn clone(&self) -> Self {
        Self {
            secret: self.secret.clone(),
            key: self.key.clone(),
        }
    }
}

#[cfg(feature = "client")]
pub struct ClientCryptoTool<'a> {
    cert: Arc<Certificate<'a>>,
    key: Symmetric,
    #[cfg(feature = "fast")]
    obfuscation: Symmetric,
    #[cfg(feature = "fast")]
    key_bytes: ByteBuffer,
}

#[cfg(feature = "client")]
impl<'a> CryptoTool for ClientCryptoTool<'a> {
    fn tailor_overhead() -> usize {
        SYMMETRIC_FIRST_AUTH_LEN + NONCE_LEN + SYMMETRIC_SECOND_AUTH_LEN
    }

    #[cfg(feature = "fast")]
    fn reset_session_key(&mut self, key: ByteBuffer) {
        self.key_bytes = key.copy();
        self.key = Symmetric::new(&key);
    }

    #[cfg(feature = "full")]
    fn reset_session_key(&mut self, key: ByteBuffer) {
        self.key = Symmetric::new(&key);
    }

    #[cfg(feature = "fast")]
    fn obfuscate_tailor(&mut self, plaintext: ByteBuffer) -> Result<ByteBuffer, CryptoError> {
        self.obfuscation.encrypt_auth_twice(plaintext, None, &self.key_bytes)
    }

    #[cfg(feature = "full")]
    fn obfuscate_tailor(&mut self, plaintext: ByteBuffer) -> Result<ByteBuffer, CryptoError> {
        self.key.encrypt_auth(plaintext, None)
    }

    #[cfg(feature = "fast")]
    fn deobfuscate_tailor(&mut self, ciphertext: ByteBuffer) -> Result<(ByteBuffer, ObfuscationTranscript), CryptoError> {
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

    #[cfg(feature = "full")]
    fn deobfuscate_tailor(&mut self, ciphertext: ByteBuffer) -> Result<(ByteBuffer, ObfuscationTranscript), CryptoError> {
        match self.key.decrypt_auth(ciphertext, None) {
            Ok(res) => Ok((res, ObfuscationTranscript {})),
            Err(err) => Err(err),
        }
    }

    #[cfg(feature = "fast")]
    fn verify_tailor(&mut self, transcript: ObfuscationTranscript) -> Result<(), CryptoError> {
        match self.obfuscation.verify_second_auth(&transcript.ciphertext_copy, None, &self.key_bytes, &transcript.second_auth_transcript) {
            Ok(_) => Ok(()),
            Err(err) => Err(err),
        }
    }

    #[cfg(feature = "full")]
    fn verify_tailor(&mut self, _: ObfuscationTranscript) -> Result<(), CryptoError> {
        Ok(())
    }
}

#[cfg(feature = "client")]
impl Clone for ClientCryptoTool<'_> {
    #[cfg(feature = "fast")]
    fn clone(&self) -> Self {
        Self {
            cert: self.cert.clone(),
            key: self.key.clone(),
            obfuscation: self.obfuscation.clone(),
            key_bytes: self.key_bytes.clone(),
        }
    }

    #[cfg(feature = "full")]
    fn clone(&self) -> Self {
        Self {
            cert: self.cert.clone(),
            key: self.key.clone(),
        }
    }
}
