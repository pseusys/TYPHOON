use crate::bytes::pool::PoolReturn;

/// Owns buffer memory and manages its lifecycle.
pub struct BufferHolder {
    pub data: *mut u8,
    pub capacity: usize,
    pool_handle: PoolReturn,
}

impl BufferHolder {
    #[inline]
    pub fn new(data: *mut u8, capacity: usize, return_tx: PoolReturn) -> Self {
        Self {
            data,
            capacity,
            pool_handle: return_tx,
        }
    }

    #[inline]
    pub fn copy(&self) -> Self {
        let new_ptr = self.pool_handle.try_take(self.capacity);
        unsafe {
            std::ptr::copy_nonoverlapping(self.data, new_ptr, self.capacity);
        }
        Self {
            data: new_ptr,
            capacity: self.capacity,
            pool_handle: self.pool_handle.clone(),
        }
    }
}

// SAFETY: `BufferHolder` owns its data pointer exclusively at the *holder* level.
// `DynamicByteBuffer::clone()` shares the same `Arc<BufferHolder>` across multiple
// buffer views (zero-copy windowing), so the *pointer* is no longer exclusive after a clone.
// Concurrent mutation through two clones residing in different threads is undefined behaviour.
// The caller's invariant: never concurrently mutate overlapping views of a shared holder.
// `DynamicByteBuffer` is `!Sync` to prevent shared references across threads; `Send` is
// permitted only for exclusive ownership transfer — not for concurrent access.
unsafe impl Send for BufferHolder {}
unsafe impl Sync for BufferHolder {}

impl Drop for BufferHolder {
    fn drop(&mut self) {
        self.pool_handle.try_return(self.data);
    }
}
