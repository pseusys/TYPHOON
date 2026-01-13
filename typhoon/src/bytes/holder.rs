use crate::bytes::pool::PoolReturn;
use crate::bytes::utils::free_ptr;

/// Owns buffer memory and manages its lifecycle.
pub(super) struct BufferHolder {
    pub(super) data: *mut u8,
    pub(super) capacity: usize,
    return_tx: Option<PoolReturn>,
}

impl BufferHolder {
    #[inline]
    pub(super) fn new(data: *mut u8, capacity: usize, return_tx: Option<PoolReturn>) -> Self {
        Self {
            data,
            capacity,
            return_tx,
        }
    }
}

// SAFETY: Data pointer is exclusively owned by this holder.
unsafe impl Send for BufferHolder {}
unsafe impl Sync for BufferHolder {}

impl Drop for BufferHolder {
    fn drop(&mut self) {
        if let Some(storage) = self.return_tx.take() {
            storage.try_return(self.data);
        } else {
            free_ptr(self.data, self.capacity);
        }
    }
}
