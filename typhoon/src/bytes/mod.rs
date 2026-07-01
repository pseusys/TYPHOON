//! Zero-copy byte buffers: a pooled, prefix/suffix-aware buffer for the hot path, plus fixed- and
//! variable-size owned buffers for everything else.
//!
//! [`ByteBuffer`] / [`ByteBufferMut`] are the read-only / read-write access traits implemented by
//! every buffer type here, so code that only needs to read or write bytes can stay generic over
//! which concrete buffer it was handed.
//!
//! - [`DynamicByteBuffer`]: the workhorse type. Allocated from a [`BytePool`] with header
//!   (`before_cap`) and trailer (`after_cap`) headroom, so flow managers can prepend a fake header
//!   or append an encrypted trailer without copying the payload. Pool-attached buffers return to
//!   the pool on drop. `Send`, not `Sync`.
//! - [`FixedByteBuffer<N>`]: a stack-allocated `[u8; N]`, `Copy`. Used where the size is known at
//!   compile time and is small enough that copying beats an atomic refcount (keys, nonces,
//!   identities).
//! - [`StaticByteBuffer`]: a heap-allocated, `Arc`-shared immutable buffer, `Send` + `Sync`. Used
//!   for certificates and other data that outlives a single buffer pool.
//! - [`BytePool`]: the thread-safe LIFO free-list backing [`DynamicByteBuffer`] allocation.

mod common;
mod dynamic;
mod fixed;
mod holder;
mod pool;
mod r#static;
mod utils;

pub use common::{ByteBuffer, ByteBufferMut};
pub use dynamic::DynamicByteBuffer;
pub use fixed::FixedByteBuffer;
pub use pool::BytePool;
pub use r#static::StaticByteBuffer;
