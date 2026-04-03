#[cfg(test)]
#[path = "../../tests/bytes/static.rs"]
mod tests;

use std::fmt::{Debug, Display};
use std::hash::{Hash, Hasher};
use std::sync::Arc;

use crate::bytes::common::ByteBuffer;

/// Immutable owned byte buffer with Arc-based sharing.
/// Send + Sync - can be safely shared across threads.
/// Used for cryptographic keys and other immutable data.
#[derive(Clone)]
pub struct StaticByteBuffer {
    data: Arc<[u8]>,
}

impl StaticByteBuffer {
    /// Create an owned buffer from a slice.
    #[inline]
    pub fn from_slice(data: &[u8]) -> Self {
        Self {
            data: Arc::from(data),
        }
    }

    /// Create an owned buffer from a fixed-size array.
    #[inline]
    pub fn from_array<const N: usize>(arr: &[u8; N]) -> Self {
        Self::from_slice(arr.as_slice())
    }

    /// Create an empty owned buffer of given size (zeroed).
    #[inline]
    pub fn empty(size: usize) -> Self {
        Self {
            data: Arc::from(vec![0u8; size]),
        }
    }
}

// SAFETY: Arc<[u8]> is thread-safe for sharing immutable data.
unsafe impl Send for StaticByteBuffer {}
unsafe impl Sync for StaticByteBuffer {}

impl ByteBuffer for StaticByteBuffer {
    #[inline]
    fn len(&self) -> usize {
        self.data.len()
    }

    #[inline]
    fn get(&self, at: usize) -> &u8 {
        assert!(at < self.len(), "index out of bounds: {} >= {}", at, self.len());
        &self.data[at]
    }

    #[inline]
    fn slice(&self) -> &[u8] {
        &self.data
    }

    #[inline]
    fn slice_start(&self, start: usize) -> &[u8] {
        assert!(start <= self.len(), "start out of bounds");
        &self.data[start..]
    }

    #[inline]
    fn slice_end(&self, end: usize) -> &[u8] {
        assert!(end <= self.len(), "end out of bounds");
        &self.data[..end]
    }

    #[inline]
    fn slice_both(&self, start: usize, end: usize) -> &[u8] {
        assert!(start <= end && end <= self.len(), "invalid slice bounds");
        &self.data[start..end]
    }

    #[inline]
    fn split(&self, divide: usize) -> (&[u8], &[u8]) {
        assert!(divide <= self.len(), "divide point out of bounds");
        (&self.data[..divide], &self.data[divide..])
    }
}

impl AsRef<[u8]> for StaticByteBuffer {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        &self.data
    }
}

impl From<Vec<u8>> for StaticByteBuffer {
    #[inline]
    fn from(value: Vec<u8>) -> Self {
        Self {
            data: Arc::from(value),
        }
    }
}

impl From<&[u8]> for StaticByteBuffer {
    #[inline]
    fn from(value: &[u8]) -> Self {
        Self::from_slice(value)
    }
}

impl<const N: usize> From<&[u8; N]> for StaticByteBuffer {
    #[inline]
    fn from(value: &[u8; N]) -> Self {
        Self::from_array(value)
    }
}

impl<const N: usize> From<[u8; N]> for StaticByteBuffer {
    #[inline]
    fn from(value: [u8; N]) -> Self {
        Self::from_array(&value)
    }
}

impl Into<Vec<u8>> for StaticByteBuffer {
    #[inline]
    fn into(self) -> Vec<u8> {
        self.data.to_vec()
    }
}

impl Into<Vec<u8>> for &StaticByteBuffer {
    #[inline]
    fn into(self) -> Vec<u8> {
        self.data.to_vec()
    }
}

impl<const N: usize> Into<[u8; N]> for &StaticByteBuffer {
    #[inline]
    fn into(self) -> [u8; N] {
        match <[u8; N]>::try_from(&self.data[..]) {
            Ok(res) => res,
            Err(err) => panic!("error converting StaticByteBuffer to array [u8; {}], actual length {}: {}", N, self.len(), err),
        }
    }
}

impl PartialEq for StaticByteBuffer {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.data == other.data
    }
}

impl Eq for StaticByteBuffer {}

impl Hash for StaticByteBuffer {
    #[inline]
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.data.hash(state);
    }
}

impl Display for StaticByteBuffer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for byte in self.data.iter() {
            write!(f, "{:02x}", byte)?;
        }
        Ok(())
    }
}

impl Debug for StaticByteBuffer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StaticByteBuffer").field("length", &self.len()).field("data", &self.data.as_ref()).finish()
    }
}
