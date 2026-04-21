/// Immutable byte buffer trait for read-only access to buffer data.
/// Implemented by both OwnedByteBuffer (immutable, Send+Sync) and ManagedByteBuffer (mutable, Send).
pub trait ByteBuffer: AsRef<[u8]> + Clone + Send {
    /// Returns the length of the current view in bytes.
    fn len(&self) -> usize;

    /// Returns true if buffer length is zero.
    #[inline]
    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Get byte at `at` index. Panics if out of bounds.
    fn get(&self, at: usize) -> &u8;

    /// Get immutable slice of entire buffer.
    fn slice(&self) -> &[u8];

    /// Get immutable slice from `start` offset to end.
    fn slice_start(&self, start: usize) -> &[u8];

    /// Get immutable slice from beginning to `end` offset.
    fn slice_end(&self, end: usize) -> &[u8];

    /// Get immutable slice from `start` to `end` offset.
    fn slice_both(&self, start: usize, end: usize) -> &[u8];

    /// Split into two immutable slices at `divide` point. Returns (left, right).
    fn split(&self, divide: usize) -> (&[u8], &[u8]);
}

/// Mutable byte buffer trait for read-write access to buffer data.
/// Only implemented by ManagedByteBuffer (pool-attached, mutable, Send).
pub trait ByteBufferMut: ByteBuffer + AsMut<[u8]> {
    /// Set byte at `at` index to `value`. Panics if out of bounds.
    fn set(&self, at: usize, value: u8);

    /// Get mutable slice of entire buffer.
    #[allow(clippy::mut_from_ref)]
    fn slice_mut(&self) -> &mut [u8];

    /// Get mutable slice from `start` offset to end.
    #[allow(clippy::mut_from_ref)]
    fn slice_start_mut(&self, start: usize) -> &mut [u8];

    /// Get mutable slice from beginning to `end` offset.
    #[allow(clippy::mut_from_ref)]
    fn slice_end_mut(&self, end: usize) -> &mut [u8];

    /// Get mutable slice from `start` to `end` offset.
    #[allow(clippy::mut_from_ref)]
    fn slice_both_mut(&self, start: usize, end: usize) -> &mut [u8];

    /// Split into two mutable slices at `divide` point. Returns (left, right).
    #[allow(clippy::mut_from_ref)]
    fn split_mut(&self, divide: usize) -> (&mut [u8], &mut [u8]);

    /// Create view with start shifted forward by `start` bytes.
    fn rebuffer_start(&self, start: usize) -> Self;

    /// Create view with end at `end` offset from current start.
    fn rebuffer_end(&self, end: usize) -> Self;

    /// Create view with both `start` and `end` adjusted from current start.
    fn rebuffer_both(&self, start: usize, end: usize) -> Self;

    /// Expand view backward by `size` bytes (into header space).
    fn expand_start(&self, size: usize) -> Self;

    /// Expand view forward by `size` bytes (into trailer space).
    fn expand_end(&self, size: usize) -> Self;

    /// Split into two buffer views at `divide` point. Returns (left, right).
    fn split_buf(&self, divide: usize) -> (Self, Self);

    /// Append `other` slice to end. Returns expanded view.
    fn append(&self, other: &[u8]) -> Self;

    /// Prepend `other` slice to start. Returns expanded view.
    fn prepend(&self, other: &[u8]) -> Self;

    /// Ensure buffer has at least `size` bytes, expanding or shrinking as needed.
    fn ensure_size(&self, size: usize) -> Self;
}
