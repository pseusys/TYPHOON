#[cfg(test)]
#[path = "../../tests/bytes/dynamic.rs"]
mod tests;

use std::cell::UnsafeCell;
use std::fmt::Debug;
use std::marker::PhantomData;
use std::slice::{from_raw_parts, from_raw_parts_mut};
use std::sync::Arc;

use rand::Fill;

use crate::bytes::common::{ByteBuffer, ByteBufferMut};
use crate::bytes::holder::BufferHolder;
use crate::bytes::r#static::StaticByteBuffer;
use crate::bytes::pool::PoolReturn;
use crate::bytes::utils::{allocate_ptr, copy_slice};

/// A mutable byte buffer with Arc-based reference counting.
/// Send but not Sync - can be moved between threads but not shared.
/// Pool-attached buffers are returned to the pool on drop.
pub struct DynamicByteBuffer {
    holder: Arc<BufferHolder>,
    length: usize,
    start: usize,
    end: usize,
    _not_sync: PhantomData<UnsafeCell<()>>,
}

impl DynamicByteBuffer {
    // TODO: last arg non-optional
    pub fn new(data: *mut u8, capacity: usize, before_cap: usize, size: usize, after_cap: usize, return_tx: Option<PoolReturn>) -> Self {
        let buffer_end = before_cap + size;
        DynamicByteBuffer {
            holder: Arc::new(BufferHolder::new(data, capacity, return_tx)),
            length: buffer_end + after_cap,
            start: before_cap,
            end: buffer_end,
            _not_sync: PhantomData,
        }
    }

    #[inline]
    pub(super) fn data_ptr(&self) -> *mut u8 {
        self.holder.data
    }

    /// Convert to an immutable StaticByteBuffer (deep copy, capacity trimmed).
    #[inline]
    pub fn copy(&self) -> Self {
        DynamicByteBuffer {
            holder: Arc::new(self.holder.copy()),
            length: self.length,
            start: self.start,
            end: self.end,
            _not_sync: PhantomData,
        }
    }

    /// Convert to an immutable StaticByteBuffer (deep copy, capacity trimmed).
    #[inline]
    pub fn to_owned(&self) -> StaticByteBuffer {
        StaticByteBuffer::from_slice(self.slice())
    }

    /// Append `other` buffer contents to end. Returns expanded view.
    #[inline]
    pub fn append_buf(&self, other: &impl ByteBuffer) -> Self {
        self.append(other.slice())
    }

    /// Prepend `other` buffer contents to start. Returns expanded view.
    #[inline]
    pub fn prepend_buf(&self, other: &impl ByteBuffer) -> Self {
        self.prepend(other.slice())
    }
}

impl ByteBuffer for DynamicByteBuffer {
    #[inline]
    fn len(&self) -> usize {
        self.end - self.start
    }

    #[inline]
    fn get(&self, at: usize) -> &u8 {
        assert!(at < self.len(), "index out of bounds: {} >= {}", at, self.len());
        unsafe { &*self.data_ptr().add(self.start + at) }
    }

    #[inline]
    fn slice(&self) -> &[u8] {
        unsafe { from_raw_parts(self.data_ptr().add(self.start), self.len()) }
    }

    #[inline]
    fn slice_start(&self, start: usize) -> &[u8] {
        assert!(start <= self.len(), "start out of bounds");
        unsafe { from_raw_parts(self.data_ptr().add(self.start + start), self.len() - start) }
    }

    #[inline]
    fn slice_end(&self, end: usize) -> &[u8] {
        assert!(end <= self.len(), "end out of bounds");
        unsafe { from_raw_parts(self.data_ptr().add(self.start), end) }
    }

    #[inline]
    fn slice_both(&self, start: usize, end: usize) -> &[u8] {
        assert!(start <= end && end <= self.len(), "invalid slice bounds");
        unsafe { from_raw_parts(self.data_ptr().add(self.start + start), end - start) }
    }

    #[inline]
    fn split(&self, divide: usize) -> (&[u8], &[u8]) {
        assert!(divide <= self.len(), "divide point out of bounds");
        unsafe {
            let ptr = self.data_ptr().add(self.start);
            (from_raw_parts(ptr, divide), from_raw_parts(ptr.add(divide), self.len() - divide))
        }
    }
}

impl ByteBufferMut for DynamicByteBuffer {
    #[inline]
    fn set(&self, at: usize, value: u8) {
        assert!(at < self.len(), "index out of bounds: {} >= {}", at, self.len());
        unsafe {
            *self.data_ptr().add(self.start + at) = value;
        }
    }

    #[inline]
    fn slice_mut(&self) -> &mut [u8] {
        unsafe { from_raw_parts_mut(self.data_ptr().add(self.start), self.len()) }
    }

    #[inline]
    fn slice_start_mut(&self, start: usize) -> &mut [u8] {
        assert!(start <= self.len(), "start out of bounds");
        unsafe { from_raw_parts_mut(self.data_ptr().add(self.start + start), self.len() - start) }
    }

    #[inline]
    fn slice_end_mut(&self, end: usize) -> &mut [u8] {
        assert!(end <= self.len(), "end out of bounds");
        unsafe { from_raw_parts_mut(self.data_ptr().add(self.start), end) }
    }

    #[inline]
    fn slice_both_mut(&self, start: usize, end: usize) -> &mut [u8] {
        assert!(start <= end && end <= self.len(), "invalid slice bounds");
        unsafe { from_raw_parts_mut(self.data_ptr().add(self.start + start), end - start) }
    }

    #[inline]
    fn split_mut(&self, divide: usize) -> (&mut [u8], &mut [u8]) {
        assert!(divide <= self.len(), "divide point out of bounds");
        unsafe {
            let ptr = self.data_ptr().add(self.start);
            (from_raw_parts_mut(ptr, divide), from_raw_parts_mut(ptr.add(divide), self.len() - divide))
        }
    }

    fn rebuffer_start(&self, start: usize) -> Self {
        let new_start = self.start + start;
        assert!(new_start <= self.end, "DynamicByteBuffer has negative length ({} > {new_start})!", self.end);
        DynamicByteBuffer {
            holder: Arc::clone(&self.holder),
            length: self.length,
            start: new_start,
            end: self.end,
            _not_sync: PhantomData,
        }
    }

    fn rebuffer_end(&self, end: usize) -> Self {
        let new_end = self.start + end;
        assert!(new_end <= self.length, "DynamicByteBuffer exceeded its forward capacity ({new_end} > {})!", self.length);
        DynamicByteBuffer {
            holder: Arc::clone(&self.holder),
            length: self.length,
            start: self.start,
            end: new_end,
            _not_sync: PhantomData,
        }
    }

    fn rebuffer_both(&self, start: usize, end: usize) -> Self {
        let new_start = self.start + start;
        let new_end = self.start + end;
        assert!(new_start <= new_end, "DynamicByteBuffer has negative length ({new_end} > {new_start})!");
        assert!(new_end <= self.length, "DynamicByteBuffer exceeded its forward capacity ({new_end} > {})!", self.length);
        DynamicByteBuffer {
            holder: Arc::clone(&self.holder),
            length: self.length,
            start: new_start,
            end: new_end,
            _not_sync: PhantomData,
        }
    }

    fn expand_start(&self, size: usize) -> Self {
        assert!(size <= self.start, "DynamicByteBuffer has negative length ({size} > {})!", self.start);
        let new_start = self.start - size;
        DynamicByteBuffer {
            holder: Arc::clone(&self.holder),
            length: self.length,
            start: new_start,
            end: self.end,
            _not_sync: PhantomData,
        }
    }

    fn expand_end(&self, size: usize) -> Self {
        let new_end = self.end + size;
        assert!(new_end <= self.length, "DynamicByteBuffer exceeded its forward capacity ({new_end} > {})!", self.length);
        DynamicByteBuffer {
            holder: Arc::clone(&self.holder),
            length: self.length,
            start: self.start,
            end: new_end,
            _not_sync: PhantomData,
        }
    }

    fn split_buf(&self, divide: usize) -> (Self, Self) {
        let new_divide = self.start + divide;
        assert!(new_divide <= self.end, "DynamicByteBuffer has negative length ({new_divide} > {})!", self.end);
        (
            DynamicByteBuffer {
                holder: Arc::clone(&self.holder),
                length: self.length,
                start: self.start,
                end: new_divide,
                _not_sync: PhantomData,
            },
            DynamicByteBuffer {
                holder: Arc::clone(&self.holder),
                length: self.length,
                start: new_divide,
                end: self.end,
                _not_sync: PhantomData,
            },
        )
    }

    fn append(&self, other: &[u8]) -> Self {
        let new_end = self.end + other.len();
        assert!(new_end <= self.length, "DynamicByteBuffer backward capacity insufficient ({new_end} > {})!", self.length);
        copy_slice(unsafe { self.data_ptr().add(self.end) }, other);
        DynamicByteBuffer {
            holder: Arc::clone(&self.holder),
            length: self.length,
            start: self.start,
            end: new_end,
            _not_sync: PhantomData,
        }
    }

    fn prepend(&self, other: &[u8]) -> Self {
        let other_length = other.len();
        assert!(other_length <= self.start, "DynamicByteBuffer forward capacity insufficient ({other_length} > {})!", self.start);
        let new_start = self.start - other_length;
        copy_slice(unsafe { self.data_ptr().add(new_start) }, other);
        DynamicByteBuffer {
            holder: Arc::clone(&self.holder),
            length: self.length,
            start: new_start,
            end: self.end,
            _not_sync: PhantomData,
        }
    }

    fn ensure_size(&self, size: usize) -> Self {
        if size > self.len() {
            self.expand_end(size - self.len())
        } else {
            DynamicByteBuffer {
                holder: Arc::clone(&self.holder),
                length: self.length,
                start: self.start,
                end: self.start + size,
                _not_sync: PhantomData,
            }
        }
    }
}

impl AsMut<[u8]> for DynamicByteBuffer {
    #[inline]
    fn as_mut(&mut self) -> &mut [u8] {
        self.slice_mut()
    }
}

impl AsRef<[u8]> for DynamicByteBuffer {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        self.slice()
    }
}

impl Into<Vec<u8>> for DynamicByteBuffer {
    #[inline]
    fn into(self) -> Vec<u8> {
        self.slice().to_vec()
    }
}

impl<const N: usize> Into<[u8; N]> for &DynamicByteBuffer {
    #[inline]
    fn into(self) -> [u8; N] {
        match <[u8; N]>::try_from(&self.slice()[..]) {
            Ok(res) => res,
            Err(err) => panic!("error converting DynamicByteBuffer to array [u8; {N}], actual buffer length {}: {}", self.len(), err),
        }
    }
}

impl PartialEq for DynamicByteBuffer {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.slice() == other.slice()
    }
}

impl Fill for DynamicByteBuffer {
    fn try_fill<R: rand::Rng + ?Sized>(&mut self, rng: &mut R) -> Result<(), rand::Error> {
        rng.try_fill_bytes(self.slice_mut())
    }
}

impl Debug for DynamicByteBuffer {
    #[inline]
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DynamicByteBuffer")
            .field("length", &self.length)
            .field("start", &self.start)
            .field("end", &self.end)
            .field("view_length", &self.len())
            .field("data", &self.slice())
            .finish()
    }
}

impl Clone for DynamicByteBuffer {
    #[inline]
    fn clone(&self) -> Self {
        DynamicByteBuffer {
            holder: Arc::clone(&self.holder),
            length: self.length,
            start: self.start,
            end: self.end,
            _not_sync: PhantomData,
        }
    }
}
