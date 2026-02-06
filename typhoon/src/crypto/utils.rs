use crate::bytes::DynamicByteBuffer;

/// Transcript for delayed tailor verification (fast mode only).
#[cfg(feature = "fast")]
pub struct ObfuscationTranscript {
    pub(crate) ciphertext_copy: DynamicByteBuffer,
    pub(crate) second_auth_transcript: DynamicByteBuffer,
}

/// Transcript placeholder (full mode).
#[cfg(feature = "full")]
pub struct ObfuscationTranscript {}
