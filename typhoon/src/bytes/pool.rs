#[cfg(test)]
#[path = "../../tests/bytes/pool.rs"]
mod tests;

use std::sync::Arc;

use crossbeam::queue::ArrayQueue;

use crate::bytes::dynamic::DynamicByteBuffer;
use crate::bytes::utils::{allocate_ptr, free_ptr};

/// Shared storage for pooled buffers.
pub struct PoolStorage {
    buffers: ArrayQueue<*mut u8>,
    capacity: usize,
}

// SAFETY: ArrayQueue allows atomic operations.
unsafe impl Send for PoolStorage {}
unsafe impl Sync for PoolStorage {}

impl PoolStorage {
    /// Return buffer to pool, or free if at capacity.
    pub fn try_return(&self, ptr: *mut u8) {
        if let Err(_) = self.buffers.push(ptr) {
            free_ptr(ptr, self.capacity);
        }
    }

    pub fn try_take(&self, size: usize) -> *mut u8 {
        self.buffers.pop().unwrap_or_else(|| allocate_ptr(size))
    }
}

pub type PoolReturn = Arc<PoolStorage>;

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
    /// Returns a DynamicByteBuffer that auto-returns to pool on drop.
    pub fn allocate(&self, size: Option<usize>) -> DynamicByteBuffer {
        let (remaining_size, remaining_after_cap) = match size {
            Some(res) => {
                assert!(res <= self.size, "Requested size greater than initial size ({res} > {})!", self.size);
                (res, self.size + self.after_cap - res)
            }
            None => (self.size, self.after_cap),
        };

        let data = self.storage.try_take(self.storage.capacity);
        DynamicByteBuffer::new(data, self.storage.capacity, self.before_cap, remaining_size, remaining_after_cap, Some(Arc::clone(&self.storage)))
    }
}
