#[cfg(test)]
#[path = "../../tests/bytes/buffer.rs"]
mod tests;

use std::cell::UnsafeCell;
use std::marker::PhantomData;
use std::ptr::copy_nonoverlapping;
use std::slice::{from_raw_parts, from_raw_parts_mut};
use std::sync::Arc;

use crate::bytes::holder::BufferHolder;
use crate::bytes::pool::PoolReturn;
crate::bytes::utils::{allocate_ptr, preserve_vector};

/// A byte buffer with Arc-based reference counting.
/// Send but not Sync - can be moved between threads but not shared.
pub struct ByteBuffer {
    holder: Arc<BufferHolder>,
    length: usize,
    start: usize,
    end: usize,
    _not_sync: PhantomData<UnsafeCell<()>>,
}

impl ByteBuffer {
    pub(crate) fn new(data: *mut u8, capacity: usize, before_cap: usize, size: usize, after_cap: usize, return_tx: Option<PoolReturn>) -> Self {
        let buffer_end = before_cap + size;
        ByteBuffer {
            holder: Arc::new(BufferHolder::new(data, capacity, return_tx)),
            length: buffer_end + after_cap,
            start: before_cap,
            end: buffer_end,
            _not_sync: PhantomData,
        }
    }

    #[inline]
    pub(crate) fn precise(before_cap: usize, size: usize, after_cap: usize, data: *mut u8, capacity: usize, return_tx: Option<PoolReturn>) -> Self {
        Self::new(data, capacity, before_cap, size, after_cap, return_tx)
    }

    /// Create a non-pooled buffer of given `size` bytes.
    #[inline]
    pub fn empty(size: usize) -> Self {
        Self::new(allocate_ptr(size), size, 0, size, 0, None)
    }

    /// Create a deep copy of the buffer data. Returns a new independent buffer.
    #[inline]
    pub fn copy(&self) -> Self {
        ByteBuffer {
            holder: Arc::new(self.holder.copy()),
            length: self.length,
            start: self.start,
            end: self.end,
            _not_sync: PhantomData,
        }
    }

    #[inline]
    fn data_ptr(&self) -> *mut u8 {
        self.holder.data
    }

    /// Returns the length of the current view in bytes.
    #[inline]
    pub fn len(&self) -> usize {
        self.end - self.start
    }

    /// Returns true if buffer length is zero.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.end == self.start
    }
}

impl ByteBuffer {
    /// Get byte at `at` index. Panics if out of bounds.
    #[inline]
    pub fn get(&self, at: usize) -> &u8 {
        assert!(at < self.len(), "index out of bounds: {} >= {}", at, self.len());
        unsafe { &*self.data_ptr().add(self.start + at) }
    }

    /// Set byte at `at` index to `value`. Panics if out of bounds.
    #[inline]
    pub fn set(&self, at: usize, value: u8) {
        assert!(at < self.len(), "index out of bounds: {} >= {}", at, self.len());
        unsafe {
            *self.data_ptr().add(self.start + at) = value;
        }
    }

    /// Get immutable slice of entire buffer.
    #[inline]
    pub fn slice(&self) -> &[u8] {
        unsafe { from_raw_parts(self.data_ptr().add(self.start), self.len()) }
    }

    /// Get mutable slice of entire buffer.
    #[inline]
    pub fn slice_mut(&self) -> &mut [u8] {
        unsafe { from_raw_parts_mut(self.data_ptr().add(self.start), self.len()) }
    }

    /// Get immutable slice from `start` offset to end.
    #[inline]
    pub fn slice_start(&self, start: usize) -> &[u8] {
        assert!(start <= self.len(), "start out of bounds");
        unsafe { from_raw_parts(self.data_ptr().add(self.start + start), self.len() - start) }
    }

    /// Get mutable slice from `start` offset to end.
    #[inline]
    pub fn slice_start_mut(&self, start: usize) -> &mut [u8] {
        assert!(start <= self.len(), "start out of bounds");
        unsafe { from_raw_parts_mut(self.data_ptr().add(self.start + start), self.len() - start) }
    }

    /// Get immutable slice from beginning to `end` offset.
    #[inline]
    pub fn slice_end(&self, end: usize) -> &[u8] {
        assert!(end <= self.len(), "end out of bounds");
        unsafe { from_raw_parts(self.data_ptr().add(self.start), end) }
    }

    /// Get mutable slice from beginning to `end` offset.
    #[inline]
    pub fn slice_end_mut(&self, end: usize) -> &mut [u8] {
        assert!(end <= self.len(), "end out of bounds");
        unsafe { from_raw_parts_mut(self.data_ptr().add(self.start), end) }
    }

    /// Get immutable slice from `start` to `end` offset.
    #[inline]
    pub fn slice_both(&self, start: usize, end: usize) -> &[u8] {
        assert!(start <= end && end <= self.len(), "invalid slice bounds");
        unsafe { from_raw_parts(self.data_ptr().add(self.start + start), end - start) }
    }

    /// Get mutable slice from `start` to `end` offset.
    #[inline]
    pub fn slice_both_mut(&self, start: usize, end: usize) -> &mut [u8] {
        assert!(start <= end && end <= self.len(), "invalid slice bounds");
        unsafe { from_raw_parts_mut(self.data_ptr().add(self.start + start), end - start) }
    }

    /// Split into two immutable slices at `divide` point. Returns (left, right).
    #[inline]
    pub fn split(&self, divide: usize) -> (&[u8], &[u8]) {
        assert!(divide <= self.len(), "divide point out of bounds");
        unsafe {
            let ptr = self.data_ptr().add(self.start);
            (from_raw_parts(ptr, divide), from_raw_parts(ptr.add(divide), self.len() - divide))
        }
    }

    /// Split into two mutable slices at `divide` point. Returns (left, right).
    #[inline]
    pub fn split_mut(&self, divide: usize) -> (&mut [u8], &mut [u8]) {
        assert!(divide <= self.len(), "divide point out of bounds");
        unsafe {
            let ptr = self.data_ptr().add(self.start);
            (from_raw_parts_mut(ptr, divide), from_raw_parts_mut(ptr.add(divide), self.len() - divide))
        }
    }
}

impl ByteBuffer {
    /// Create view with start shifted forward by `start` bytes.
    pub fn rebuffer_start(&self, start: usize) -> Self {
        let new_start = self.start + start;
        assert!(new_start <= self.end, "ByteBuffer has negative length ({} > {new_start})!", self.end);
        ByteBuffer {
            holder: Arc::clone(&self.holder),
            length: self.length,
            start: new_start,
            end: self.end,
            _not_sync: PhantomData,
        }
    }

    /// Create view with end at `end` offset from current start.
    pub fn rebuffer_end(&self, end: usize) -> Self {
        let new_end = self.start + end;
        assert!(new_end <= self.length, "ByteBuffer exceeded its forward capacity ({new_end} > {})!", self.length);
        ByteBuffer {
            holder: Arc::clone(&self.holder),
            length: self.length,
            start: self.start,
            end: new_end,
            _not_sync: PhantomData,
        }
    }

    /// Create view with both `start` and `end` adjusted from current start.
    pub fn rebuffer_both(&self, start: usize, end: usize) -> Self {
        let new_start = self.start + start;
        let new_end = self.start + end;
        assert!(new_start <= new_end, "ByteBuffer has negative length ({new_end} > {new_start})!");
        assert!(new_end <= self.length, "ByteBuffer exceeded its forward capacity ({new_end} > {})!", self.length);
        ByteBuffer {
            holder: Arc::clone(&self.holder),
            length: self.length,
            start: new_start,
            end: new_end,
            _not_sync: PhantomData,
        }
    }

    /// Expand view backward by `size` bytes (into header space).
    pub fn expand_start(&self, size: usize) -> Self {
        assert!(size <= self.start, "ByteBuffer has negative length ({size} > {})!", self.start);
        let new_start = self.start - size;
        ByteBuffer {
            holder: Arc::clone(&self.holder),
            length: self.length,
            start: new_start,
            end: self.end,
            _not_sync: PhantomData,
        }
    }

    /// Expand view forward by `size` bytes (into trailer space).
    pub fn expand_end(&self, size: usize) -> Self {
        let new_end = self.end + size;
        assert!(new_end <= self.length, "ByteBuffer exceeded its forward capacity ({new_end} > {})!", self.length);
        ByteBuffer {
            holder: Arc::clone(&self.holder),
            length: self.length,
            start: self.start,
            end: new_end,
            _not_sync: PhantomData,
        }
    }

    /// Split into two ByteBuffer views at `divide` point. Returns (left, right).
    pub fn split_buf(&self, divide: usize) -> (Self, Self) {
        let new_divide = self.start + divide;
        assert!(new_divide <= self.end, "ByteBuffer has negative length ({new_divide} > {})!", self.end);
        (
            ByteBuffer {
                holder: Arc::clone(&self.holder),
                length: self.length,
                start: self.start,
                end: new_divide,
                _not_sync: PhantomData,
            },
            ByteBuffer {
                holder: Arc::clone(&self.holder),
                length: self.length,
                start: new_divide,
                end: self.end,
                _not_sync: PhantomData,
            },
        )
    }

    /// Append `other` slice to end. Returns expanded view.
    pub fn append(&self, other: &[u8]) -> Self {
        let other_length = other.len();
        let new_end = self.end + other_length;
        assert!(new_end <= self.length, "ByteBuffer backward capacity insufficient ({new_end} > {})!", self.length);
        unsafe {
            copy_nonoverlapping(other.as_ptr(), self.data_ptr().add(self.end), other_length);
        }
        ByteBuffer {
            holder: Arc::clone(&self.holder),
            length: self.length,
            start: self.start,
            end: new_end,
            _not_sync: PhantomData,
        }
    }

    /// Append `other` buffer contents to end. Returns expanded view.
    pub fn append_buf(&self, other: &ByteBuffer) -> Self {
        self.append(other.slice())
    }

    /// Prepend `other` slice to start. Returns expanded view.
    pub fn prepend(&self, other: &[u8]) -> Self {
        let other_length = other.len();
        assert!(other_length <= self.start, "ByteBuffer forward capacity insufficient ({other_length} > {})!", self.start);
        let new_start = self.start - other_length;
        unsafe {
            copy_nonoverlapping(other.as_ptr(), self.data_ptr().add(new_start), other_length);
        }
        ByteBuffer {
            holder: Arc::clone(&self.holder),
            length: self.length,
            start: new_start,
            end: self.end,
            _not_sync: PhantomData,
        }
    }

    /// Prepend `other` buffer contents to start. Returns expanded view.
    pub fn prepend_buf(&self, other: &ByteBuffer) -> Self {
        self.prepend(other.slice())
    }

    /// Ensure buffer has at least `size` bytes, expanding or shrinking as needed.
    pub fn ensure_size(&self, size: usize) -> Self {
        if size > self.len() {
            self.expand_end(size - self.len())
        } else {
            ByteBuffer {
                holder: Arc::clone(&self.holder),
                length: self.length,
                start: self.start,
                end: self.start + size,
                _not_sync: PhantomData,
            }
        }
    }
}

impl AsMut<[u8]> for ByteBuffer {
    #[inline]
    fn as_mut(&mut self) -> &mut [u8] {
        self.slice_mut()
    }
}

impl AsRef<[u8]> for ByteBuffer {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        self.slice()
    }
}

impl From<Vec<u8>> for ByteBuffer {
    fn from(value: Vec<u8>) -> Self {
        let length = value.len();
        let capacity = value.capacity();
        Self::new(preserve_vector(value), capacity, 0, length, capacity - length, None)
    }
}

impl From<&[u8]> for ByteBuffer {
    fn from(value: &[u8]) -> Self {
        let vector = value.to_vec();
        vector.into()
    }
}

impl Into<Vec<u8>> for ByteBuffer {
    #[inline]
    fn into(self) -> Vec<u8> {
        self.slice().to_vec()
    }
}

impl Clone for ByteBuffer {
    #[inline]
    fn clone(&self) -> Self {
        ByteBuffer {
            holder: Arc::clone(&self.holder),
            length: self.length,
            start: self.start,
            end: self.end,
            _not_sync: PhantomData,
        }
    }
}
