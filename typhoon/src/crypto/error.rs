use thiserror::Error;

use crate::bytes::buffer::ByteBufferConversionError;

#[cfg(feature = "fast")]
use chacha20poly1305::aead::Error as AeadError;

#[cfg(feature = "full")]
use aes_gcm::aead::Error as AeadError;

#[derive(Error, Debug)]
pub enum CryptoError {
    #[error("error generating error from bytebuffer: {}", .0.to_string())]
    ArrayExtractionError(#[source] ByteBufferConversionError),

    #[error("error encrypting data: {}", .0.to_string())]
    EncryptionError(#[source] AeadError),

    #[error("error authenticating data: {}", .0)]
    AuthenticationError(String),
}
