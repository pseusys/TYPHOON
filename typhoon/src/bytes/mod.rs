use lazy_static::lazy_static;

pub mod buffer;
mod holder;
pub mod pool;
pub mod utils;

pub use buffer::ByteBuffer;
pub use pool::BytePool;

static INITIAL_POOL_SIZE: usize = 5;
static MAX_POOL_SIZE: usize = 64;
pub static HEADER_OVERHEAD: usize = 64;

lazy_static! {
    static ref PACKET_POOL: BytePool = BytePool::new(HEADER_OVERHEAD, u16::MAX as usize, 0, INITIAL_POOL_SIZE, MAX_POOL_SIZE);
}

/// Get a buffer from the global packet pool.
pub fn get_buffer(initial_size: Option<usize>) -> ByteBuffer {
    PACKET_POOL.allocate(initial_size)
}
