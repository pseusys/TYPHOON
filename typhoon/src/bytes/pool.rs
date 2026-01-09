#[cfg(test)]
#[path = "../../tests/bytes/pool.rs"]
mod tests;

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use crate::bytes::buffer::ByteBuffer;
use crate::bytes::utils::{allocate_ptr, free_ptr};

/// Shared storage for pooled buffers.
pub(crate) struct PoolStorage {
    buffers: Mutex<VecDeque<*mut u8>>,
    capacity: usize,
    max_pooled: usize,
}

// SAFETY: Mutex protects all access to the VecDeque.
unsafe impl Send for PoolStorage {}
unsafe impl Sync for PoolStorage {}

impl PoolStorage {
    /// Return buffer to pool, or free if at capacity.
    pub(crate) fn try_return(&self, ptr: *mut u8) {
        let mut buffers = self.buffers.lock().expect("mutex poisoned");
        if buffers.len() < self.max_pooled {
            buffers.push_front(ptr);
        } else {
            drop(buffers);
            free_ptr(ptr, self.capacity);
        }
    }

    fn try_take(&self) -> Option<*mut u8> {
        self.buffers.lock().expect("mutex poisoned").pop_front()
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

        let mut buffers = VecDeque::with_capacity(actual_max);
        for _ in 0..initial {
            buffers.push_back(allocate_ptr(capacity));
        }

        let storage = Arc::new(PoolStorage {
            buffers: Mutex::new(buffers),
            capacity,
            max_pooled: actual_max,
        });
        BytePool {
            before_cap,
            size,
            after_cap,
            storage,
        }
    }

    /// Get a buffer from pool or allocate new one.
    /// - `size`: optional size limit (must be <= pool's size), None for full size
    /// Returns a ByteBuffer that auto-returns to pool on drop.
    pub fn allocate(&self, size: Option<usize>) -> ByteBuffer {
        let (remaining_size, remaining_after_cap) = match size {
            Some(res) => {
                assert!(res <= self.size, "Requested size greater than initial size ({res} > {})!", self.size);
                (res, self.size + self.after_cap - res)
            }
            None => (self.size, self.after_cap),
        };

        let data = self.storage.try_take().unwrap_or_else(|| allocate_ptr(self.storage.capacity));
        ByteBuffer::precise(self.before_cap, remaining_size, remaining_after_cap, data, self.storage.capacity, Some(Arc::clone(&self.storage)))
    }
}
