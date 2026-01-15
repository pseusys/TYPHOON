use thiserror::Error;

use crate::bytes::ByteBufferConversionError;

#[cfg(feature = "fast")]
use chacha20poly1305::aead::Error as AeadError;

#[cfg(feature = "full")]
use aes_gcm::aead::Error as AeadError;

#[derive(Error, Debug)]
pub enum CryptoError {
    #[error("error extracting {location}: {}", .source.to_string())]
    ArrayExtractionError {
        location: String,
        source: ByteBufferConversionError,
    },

    #[error("symmetric cryptography error at {specification}: {}", .source.to_string())]
    EncryptionError {
        specification: String,
        source: AeadError,
    },

    #[error("error authentication: {}", .0)]
    AuthenticationError(String),
}

#[derive(Error, Debug)]
pub enum HandshakeError {
    #[error("cryptography error during {cause}: {}", .source.to_string())]
    CryptoError {
        cause: String,
        source: CryptoError,
    },

    #[error("cryptography error during extracting {location}: {}", .source.to_string())]
    ArrayExtractionError {
        location: String,
        source: ByteBufferConversionError,
    },

    #[error("cryptography error during authenticating: {}", .0)]
    AuthenticationError(String),
}

pub(super) fn array_extraction_error(location: &str, source: ByteBufferConversionError) -> CryptoError {
    CryptoError::ArrayExtractionError {
        location: location.to_string(),
        source,
    }
}

pub(super) fn encryption_error(specification: &str, source: AeadError) -> CryptoError {
    CryptoError::EncryptionError {
        specification: specification.to_string(),
        source,
    }
}

pub(super) fn authentication_error(cause: &str) -> CryptoError {
    CryptoError::AuthenticationError(cause.to_string())
}

pub(super) fn handshake_crypto_error(cause: &str, source: CryptoError) -> HandshakeError {
    HandshakeError::CryptoError {
        cause: cause.to_string(),
        source,
    }
}

pub(super) fn handshake_array_extraction_error(location: &str, source: ByteBufferConversionError) -> HandshakeError {
    HandshakeError::ArrayExtractionError {
        location: location.to_string(),
        source,
    }
}

pub(super) fn handshake_authentication_error(cause: &str) -> HandshakeError {
    HandshakeError::AuthenticationError(cause.to_string())
}
