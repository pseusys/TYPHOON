use generic_array::{GenericArray, typenum::U32};

use crate::bytes::ByteBuffer;

pub type StandardPassword = GenericArray<u8, U32>;

/// Transcript for delayed tailor verification (fast mode only).
#[cfg(feature = "fast")]
pub struct ObfuscationTranscript {
    pub(crate) ciphertext_copy: ByteBuffer,
    pub(crate) second_auth_transcript: ByteBuffer,
}

/// Transcript placeholder (full mode).
#[cfg(feature = "full")]
pub struct ObfuscationTranscript {}

impl Into<StandardPassword> for &ByteBuffer {
    #[inline]
    fn into(self) -> StandardPassword {
        GenericArray::from_array::<32>(self.into())
    }
}

impl From<&StandardPassword> for ByteBuffer {
    #[inline]
    fn from(value: &StandardPassword) -> Self {
        ByteBuffer::from(value.as_slice())
    }
}
