#[cfg(test)]
#[path = "../../tests/bytes/pool.rs"]
mod tests;

use std::sync::Arc;

use crossbeam::queue::ArrayQueue;

use crate::bytes::dynamic::DynamicByteBuffer;
use crate::bytes::utils::{allocate_ptr, copy_slice, free_ptr};

/// Shared storage for pooled buffers.
pub(crate) struct PoolStorage {
    buffers: ArrayQueue<*mut u8>,
    capacity: usize,
}

// SAFETY: ArrayQueue allows atomic operations.
unsafe impl Send for PoolStorage {}
unsafe impl Sync for PoolStorage {}

impl PoolStorage {
    /// Return buffer to pool, or free if at capacity.
    #[inline]
    pub(crate) fn try_return(&self, ptr: *mut u8) {
        if self.buffers.push(ptr).is_err() {
            free_ptr(ptr, self.capacity);
        }
    }

    #[inline]
    pub(crate) fn try_take(&self, size: usize) -> *mut u8 {
        self.buffers.pop().unwrap_or_else(|| allocate_ptr(size))
    }
}

pub(crate) type PoolReturn = Arc<PoolStorage>;

/// Thread-safe pool of reusable byte buffers.
pub struct BytePool {
    before_cap: usize,
    size: usize,
    after_cap: usize,
    storage: Arc<PoolStorage>,
}

impl BytePool {
    /// Create a new pool.
    /// - `before_cap`: header space before main data
    /// - `size`: main data capacity
    /// - `after_cap`: trailer space after main data
    /// - `initial`: pre-allocated buffer count
    /// - `max_pooled`: maximum buffers to keep in pool
    pub fn new(before_cap: usize, size: usize, after_cap: usize, initial: usize, max_pooled: usize) -> Self {
        let capacity = before_cap + size + after_cap;
        let actual_max = max_pooled.max(initial);

        let buffers = ArrayQueue::new(actual_max);
        for _ in 0..initial {
            buffers.push(allocate_ptr(capacity)).expect("Should never happen actually.");
        }

        BytePool {
            before_cap,
            size,
            after_cap,
            storage: Arc::new(PoolStorage {
                buffers,
                capacity,
            }),
        }
    }

    /// Get a buffer from pool or allocate new one.
    /// - `size`: optional size limit (must be <= pool's size), None for full size
    ///
    /// Returns a DynamicByteBuffer that auto-returns to pool on drop.
    #[inline]
    pub fn allocate(&self, size: Option<usize>) -> DynamicByteBuffer {
        match size {
            Some(res) => self.allocate_precise(res, self.before_cap, self.after_cap),
            None => self.allocate_precise(self.size, self.before_cap, self.after_cap),
        }
    }

    /// Allocate a buffer sized for receiving raw packets from the network.
    /// Uses the maximum available active view (size + after_cap) to accommodate
    /// on-wire packets that are larger than the user-data MTU due to protocol overhead.
    /// The before_cap headroom is preserved for subsequent send-path expand_start calls.
    #[inline]
    pub fn allocate_for_recv(&self) -> DynamicByteBuffer {
        self.allocate_precise(self.size + self.after_cap, self.before_cap, 0)
    }

    #[inline]
    pub fn allocate_precise(&self, size: usize, before_cap: usize, after_cap: usize) -> DynamicByteBuffer {
        let requested_size = before_cap + size + after_cap;
        assert!(requested_size <= self.storage.capacity, "Requested size greater than pool capacity ({requested_size} > {})!", self.storage.capacity);
        let actual_after_cap = self.storage.capacity + after_cap - requested_size;

        let data = self.storage.try_take(self.storage.capacity);
        DynamicByteBuffer::new(data, self.storage.capacity, before_cap, size, actual_after_cap, Arc::clone(&self.storage))
    }

    #[inline]
    pub fn allocate_precise_from_slice_with_capacity(&self, data: &[u8], before_cap: usize, after_cap: usize) -> DynamicByteBuffer {
        let buff = self.allocate_precise(data.len(), before_cap, after_cap);
        if !data.is_empty() {
            copy_slice(unsafe { buff.data_ptr().add(before_cap) }, data);
        }
        buff
    }

    #[inline]
    pub fn allocate_precise_from_array_with_capacity<const N: usize>(&self, arr: &[u8; N], before_cap: usize, after_cap: usize) -> DynamicByteBuffer {
        self.allocate_precise_from_slice_with_capacity(arr.as_slice(), before_cap, after_cap)
    }
}
