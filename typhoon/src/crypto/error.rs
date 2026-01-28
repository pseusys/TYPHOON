use thiserror::Error;

#[cfg(feature = "fast")]
use chacha20poly1305::aead::Error as AeadError;

#[cfg(feature = "full")]
use aes_gcm::aead::Error as AeadError;

#[derive(Error, Debug)]
pub enum CryptoError {
    #[error("symmetric cryptography error at {specification}: {}", source.to_string())]
    EncryptionError {
        specification: String,
        source: AeadError,
    },

    #[error("error authentication: {}", .0)]
    AuthenticationError(String),

    #[error("unknown cryptography error")]
    UnknownError,
}

#[derive(Error, Debug)]
pub enum HandshakeError {
    #[error("cryptography error during {cause}: {}", source.to_string())]
    CryptoError {
        cause: String,
        source: CryptoError,
    },

    #[error("cryptography error during authenticating: {}", .0)]
    AuthenticationError(String),
}

impl CryptoError {
    #[inline]
    pub fn encryption_error(specification: &str, source: AeadError) -> Self {
        Self::EncryptionError {
            specification: specification.to_string(),
            source,
        }
    }

    #[inline]
    pub fn authentication_error(cause: &str) -> Self {
        Self::AuthenticationError(cause.to_string())
    }
}

impl HandshakeError {
    #[inline]
    pub fn handshake_crypto_error(cause: &str, source: CryptoError) -> Self {
        Self::CryptoError {
            cause: cause.to_string(),
            source,
        }
    }

    #[inline]
    pub fn handshake_authentication_error(cause: &str) -> Self {
        Self::AuthenticationError(cause.to_string())
    }
}
