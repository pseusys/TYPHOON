use std::io;

use thiserror::Error;

/// Result type alias for TYPHOON operations.
pub type TyphoonResult<T> = Result<T, TyphoonError>;

/// Error types for TYPHOON protocol operations.
#[derive(Debug, Error)]
pub enum TyphoonError {
    /// Handshake failed during connection establishment.
    #[error("Handshake failed: {0}")]
    HandshakeFailed(String),

    /// Session has expired or been terminated.
    #[error("Session expired")]
    SessionExpired,

    /// Session is not active.
    #[error("Session not active")]
    SessionNotActive,

    /// Invalid packet structure or contents.
    #[error("Invalid packet: {0}")]
    InvalidPacket(String),

    /// Tailor decryption or verification failed.
    #[error("Tailor verification failed: {0}")]
    TailorVerificationFailed(String),

    /// Payload decryption failed.
    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),

    /// Encryption operation failed.
    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),

    /// Network I/O error.
    #[error("Network error: {0}")]
    NetworkError(#[from] io::Error),

    /// Operation timed out.
    #[error("Timeout: {0}")]
    Timeout(String),

    /// Maximum retries exceeded during decay cycle.
    #[error("Max retries exceeded ({0} attempts)")]
    MaxRetriesExceeded(u32),

    /// Invalid session ID.
    #[error("Invalid session ID")]
    InvalidSessionId,

    /// Session with given ID not found.
    #[error("Session not found: {0:?}")]
    SessionNotFound([u8; 16]),

    /// Buffer capacity exceeded.
    #[error("Buffer overflow: {0}")]
    BufferOverflow(String),

    /// Invalid packet number (replay protection).
    #[error("Invalid packet number: expected > {expected}, got {actual}")]
    InvalidPacketNumber { expected: u32, actual: u32 },

    /// Flow manager not available.
    #[error("No available flow")]
    NoAvailableFlow,

    /// Certificate validation failed.
    #[error("Certificate validation failed: {0}")]
    CertificateValidationFailed(String),

    /// Signature verification failed.
    #[error("Signature verification failed")]
    SignatureVerificationFailed,

    /// Key derivation failed.
    #[error("Key derivation failed: {0}")]
    KeyDerivationFailed(String),

    /// Channel communication error.
    #[error("Channel error: {0}")]
    ChannelError(String),

    /// Internal error.
    #[error("Internal error: {0}")]
    InternalError(String),
}

impl TyphoonError {
    /// Check if this error is recoverable (operation can be retried).
    pub fn is_recoverable(&self) -> bool {
        matches!(
            self,
            TyphoonError::Timeout(_)
                | TyphoonError::NetworkError(_)
                | TyphoonError::NoAvailableFlow
        )
    }

    /// Check if this error is fatal (session should be terminated).
    pub fn is_fatal(&self) -> bool {
        matches!(
            self,
            TyphoonError::SessionExpired
                | TyphoonError::MaxRetriesExceeded(_)
                | TyphoonError::HandshakeFailed(_)
                | TyphoonError::SignatureVerificationFailed
                | TyphoonError::CertificateValidationFailed(_)
        )
    }
}

impl From<String> for TyphoonError {
    fn from(msg: String) -> Self {
        TyphoonError::InternalError(msg)
    }
}

impl From<&str> for TyphoonError {
    fn from(msg: &str) -> Self {
        TyphoonError::InternalError(msg.to_string())
    }
}

impl From<Box<dyn std::error::Error + Send + Sync>> for TyphoonError {
    fn from(err: Box<dyn std::error::Error + Send + Sync>) -> Self {
        TyphoonError::InternalError(err.to_string())
    }
}
