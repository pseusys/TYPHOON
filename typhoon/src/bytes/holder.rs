use crate::bytes::pool::PoolReturn;
use crate::bytes::utils::{allocate_ptr, free_ptr};

/// Owns buffer memory and manages its lifecycle.
pub struct BufferHolder {
    pub data: *mut u8,
    pub capacity: usize,
    pool_handle: Option<PoolReturn>,
}

impl BufferHolder {
    #[inline]
    pub fn new(data: *mut u8, capacity: usize, return_tx: Option<PoolReturn>) -> Self {
        Self {
            data,
            capacity,
            pool_handle: return_tx,
        }
    }

    #[inline]
    pub fn copy(&self) -> Self {
        let new_ptr = match &self.pool_handle {
            Some(res) => res.try_take(self.capacity),
            None => allocate_ptr(self.capacity),
        };
        unsafe {
            std::ptr::copy_nonoverlapping(self.data, new_ptr, self.capacity);
        }
        Self {
            data: new_ptr,
            capacity: self.capacity,
            pool_handle: None,
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
        match self.pool_handle.take() {
            Some(res) => res.try_return(self.data),
            None => free_ptr(self.data, self.capacity),
        }
    }
}
