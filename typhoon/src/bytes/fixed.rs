#[cfg(test)]
#[path = "../../tests/bytes/fixed.rs"]
mod tests;

/// Stack-allocated fixed-size byte buffer for compile-time-known sizes (e.g. cryptographic keys).
/// Zero heap allocation; `Copy` semantics — 32-byte copies are cheaper than atomic Arc ops.
use std::fmt::{Debug, Display};
use std::hash::{Hash, Hasher};

use crate::bytes::common::ByteBuffer;

/// Fixed-size byte buffer backed by a `[u8; N]` stack array.
/// Implements [`ByteBuffer`] so it can be passed wherever a byte buffer is expected.
/// Unlike [`StaticByteBuffer`](super::StaticByteBuffer), no heap allocation occurs.
#[derive(Clone, Copy)]
pub struct FixedByteBuffer<const N: usize> {
    data: [u8; N],
}

impl<const N: usize> FixedByteBuffer<N> {
    /// Create a zeroed buffer.
    #[inline]
    pub fn zeroed() -> Self {
        Self { data: [0u8; N] }
    }

    /// Create from a fixed-size array.
    #[inline]
    pub fn from_array(arr: [u8; N]) -> Self {
        Self { data: arr }
    }

    /// Get a reference to the inner array.
    #[inline]
    pub fn as_array(&self) -> &[u8; N] {
        &self.data
    }
}

impl<const N: usize> ByteBuffer for FixedByteBuffer<N> {
    #[inline]
    fn len(&self) -> usize {
        N
    }

    #[inline]
    fn get(&self, at: usize) -> &u8 {
        assert!(at < N, "index out of bounds: {at} >= {N}");
        &self.data[at]
    }

    #[inline]
    fn slice(&self) -> &[u8] {
        &self.data
    }

    #[inline]
    fn slice_start(&self, start: usize) -> &[u8] {
        assert!(start <= N, "start out of bounds");
        &self.data[start..]
    }

    #[inline]
    fn slice_end(&self, end: usize) -> &[u8] {
        assert!(end <= N, "end out of bounds");
        &self.data[..end]
    }

    #[inline]
    fn slice_both(&self, start: usize, end: usize) -> &[u8] {
        assert!(start <= end && end <= N, "invalid slice bounds");
        &self.data[start..end]
    }

    #[inline]
    fn split(&self, divide: usize) -> (&[u8], &[u8]) {
        assert!(divide <= N, "divide point out of bounds");
        (&self.data[..divide], &self.data[divide..])
    }
}

impl<const N: usize> AsRef<[u8]> for FixedByteBuffer<N> {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        &self.data
    }
}

impl<const N: usize> From<[u8; N]> for FixedByteBuffer<N> {
    #[inline]
    fn from(arr: [u8; N]) -> Self {
        Self { data: arr }
    }
}

impl<const N: usize> From<&[u8; N]> for FixedByteBuffer<N> {
    #[inline]
    fn from(arr: &[u8; N]) -> Self {
        Self { data: *arr }
    }
}

impl<const N: usize> From<FixedByteBuffer<N>> for [u8; N] {
    #[inline]
    fn from(buf: FixedByteBuffer<N>) -> [u8; N] {
        buf.data
    }
}

impl<const N: usize> Default for FixedByteBuffer<N> {
    #[inline]
    fn default() -> Self {
        Self::zeroed()
    }
}

impl<const N: usize> PartialEq for FixedByteBuffer<N> {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.data == other.data
    }
}

impl<const N: usize> Eq for FixedByteBuffer<N> {}

impl<const N: usize> Hash for FixedByteBuffer<N> {
    #[inline]
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.data.hash(state);
    }
}

impl<const N: usize> Display for FixedByteBuffer<N> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for byte in &self.data {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl<const N: usize> Debug for FixedByteBuffer<N> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FixedByteBuffer").field("length", &N).field("data", &self.data).finish()
    }
}
