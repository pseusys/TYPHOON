use lazy_static::lazy_static;

use crate::bytes::{ByteBuffer, ByteBufferMut, BytePool, DynamicByteBuffer};

lazy_static! {
    static ref TEST_POOL: BytePool = BytePool::new(32, 256, 32, 4, 16);
}

/// Allocate a buffer from pool and copy data into it.
fn pool_buf(pool: &BytePool, data: &[u8]) -> DynamicByteBuffer {
    pool.allocate_precise_from_slice_with_capacity(data, 0, 0)
}

/// Allocate an empty (zeroed) buffer from pool.
fn pool_empty(pool: &BytePool, size: usize) -> DynamicByteBuffer {
    pool.allocate_precise(size, 0, 0)
}

// Test: empty buffer has correct size and is not empty.
#[test]
fn test_empty_buffer() {
    let buf = pool_empty(&TEST_POOL, 100);
    assert_eq!(buf.len(), 100);
    assert!(!buf.is_empty());
}

// Test: zero-size buffer is empty.
#[test]
fn test_empty_zero_size() {
    let buf = pool_empty(&TEST_POOL, 0);
    assert_eq!(buf.len(), 0);
    assert!(buf.is_empty());
}

// Test: buffer created from data has correct data.
#[test]
fn test_from_data() {
    let buf = pool_buf(&TEST_POOL, &[1u8, 2, 3, 4, 5]);
    assert_eq!(buf.len(), 5);
    assert_eq!(buf.slice(), &[1, 2, 3, 4, 5]);
}

// Test: buffer converts to Vec correctly.
#[test]
fn test_into_vec() {
    let buf = pool_buf(&TEST_POOL, &[1u8, 2, 3, 4, 5]);
    let result: Vec<u8> = buf.into();
    assert_eq!(result, vec![1, 2, 3, 4, 5]);
}

// Test: get/set byte access works correctly.
#[test]
fn test_get_set() {
    let buf = pool_empty(&TEST_POOL, 10);
    buf.set(0, 42);
    buf.set(5, 100);
    assert_eq!(*buf.get(0), 42);
    assert_eq!(*buf.get(5), 100);
}

// Test: get out of bounds panics.
#[test]
#[should_panic(expected = "index out of bounds")]
fn test_get_out_of_bounds() {
    let buf = pool_empty(&TEST_POOL, 10);
    let _ = buf.get(10);
}

// Test: set out of bounds panics.
#[test]
#[should_panic(expected = "index out of bounds")]
fn test_set_out_of_bounds() {
    let buf = pool_empty(&TEST_POOL, 10);
    buf.set(10, 42);
}

// Test: mutable slice allows modification.
#[test]
fn test_slice_mut() {
    let buf = pool_empty(&TEST_POOL, 5);
    let slice = buf.slice_mut();
    slice[0] = 1;
    slice[4] = 5;
    assert_eq!(buf.slice(), &[1, 0, 0, 0, 5]);
}

// Test: slice_start returns suffix from offset.
#[test]
fn test_slice_start() {
    let buf = pool_buf(&TEST_POOL, &[1u8, 2, 3, 4, 5]);
    assert_eq!(buf.slice_start(2), &[3, 4, 5]);
}

// Test: slice_end returns prefix up to offset.
#[test]
fn test_slice_end() {
    let buf = pool_buf(&TEST_POOL, &[1u8, 2, 3, 4, 5]);
    assert_eq!(buf.slice_end(3), &[1, 2, 3]);
}

// Test: slice_both returns range [start, end).
#[test]
fn test_slice_both() {
    let buf = pool_buf(&TEST_POOL, &[1u8, 2, 3, 4, 5]);
    assert_eq!(buf.slice_both(1, 4), &[2, 3, 4]);
}

// Test: split returns two immutable slice halves.
#[test]
fn test_split() {
    let buf = pool_buf(&TEST_POOL, &[1u8, 2, 3, 4, 5]);
    let (left, right) = buf.split(2);
    assert_eq!(left, &[1, 2]);
    assert_eq!(right, &[3, 4, 5]);
}

// Test: split_mut returns two mutable slice halves.
#[test]
fn test_split_mut() {
    let buf = pool_empty(&TEST_POOL, 5);
    let (left, right) = buf.split_mut(2);
    left[0] = 1;
    left[1] = 2;
    right[0] = 3;
    right[1] = 4;
    right[2] = 5;
    assert_eq!(buf.slice(), &[1, 2, 3, 4, 5]);
}

// Test: copy creates independent buffer (deep copy).
#[test]
fn test_copy() {
    let buf = pool_buf(&TEST_POOL, &[1u8, 2, 3, 4, 5]);
    let copy = buf.copy();

    assert_eq!(buf.slice(), copy.slice());

    copy.set(0, 99);
    assert_eq!(*buf.get(0), 1);
    assert_eq!(*copy.get(0), 99);
}

// Test: clone shares underlying memory (shallow copy).
#[test]
fn test_clone_shares_memory() {
    let buf = pool_buf(&TEST_POOL, &[1u8, 2, 3, 4, 5]);
    let clone = buf.clone();

    clone.set(0, 99);
    assert_eq!(*buf.get(0), 99);
}

// Test: rebuffer_start shifts view start forward.
#[test]
fn test_rebuffer_start() {
    let buf = pool_buf(&TEST_POOL, &[1u8, 2, 3, 4, 5]);
    let rebuffered = buf.rebuffer_start(2);
    assert_eq!(rebuffered.len(), 3);
    assert_eq!(rebuffered.slice(), &[3, 4, 5]);
}

// Test: rebuffer_end sets view end offset.
#[test]
fn test_rebuffer_end() {
    let buf = pool_buf(&TEST_POOL, &[1u8, 2, 3, 4, 5]);
    let rebuffered = buf.rebuffer_end(3);
    assert_eq!(rebuffered.len(), 3);
    assert_eq!(rebuffered.slice(), &[1, 2, 3]);
}

// Test: rebuffer_both adjusts both start and end.
#[test]
fn test_rebuffer_both() {
    let buf = pool_buf(&TEST_POOL, &[1u8, 2, 3, 4, 5]);
    let rebuffered = buf.rebuffer_both(1, 4);
    assert_eq!(rebuffered.len(), 3);
    assert_eq!(rebuffered.slice(), &[2, 3, 4]);
}

// Test: split_buf returns two DynamicByteBuffer views.
#[test]
fn test_split_buf() {
    let buf = pool_buf(&TEST_POOL, &[1u8, 2, 3, 4, 5]);
    let (left, right) = buf.split_buf(2);
    assert_eq!(left.slice(), &[1, 2]);
    assert_eq!(right.slice(), &[3, 4, 5]);
}

// Test: AsRef<[u8]> trait implementation.
#[test]
fn test_as_ref() {
    let buf = pool_buf(&TEST_POOL, &[1u8, 2, 3]);
    let slice: &[u8] = buf.as_ref();
    assert_eq!(slice, &[1, 2, 3]);
}

// Test: AsMut<[u8]> trait implementation.
#[test]
fn test_as_mut() {
    let mut buf = pool_buf(&TEST_POOL, &[1u8, 2, 3]);
    let slice: &mut [u8] = buf.as_mut();
    slice[0] = 99;
    assert_eq!(buf.slice(), &[99, 2, 3]);
}

// Test: allocate with capacity creates buffer with extra capacity.
#[test]
fn test_allocate_with_capacity() {
    let buf = TEST_POOL.allocate_precise_from_slice_with_capacity(&[1u8, 2, 3], 5, 10);
    assert_eq!(buf.len(), 3);
    assert_eq!(buf.slice(), &[1, 2, 3]);

    let prepended = buf.prepend(&[0, 0]);
    assert_eq!(prepended.slice(), &[0, 0, 1, 2, 3]);

    let appended = prepended.append(&[4, 5, 6]);
    assert_eq!(appended.slice(), &[0, 0, 1, 2, 3, 4, 5, 6]);
}

// Test: to_owned creates a StaticByteBuffer.
#[test]
fn test_to_owned() {
    let buf = pool_buf(&TEST_POOL, &[1u8, 2, 3, 4, 5]);
    let owned = buf.to_owned();

    assert_eq!(owned.len(), 5);
    assert_eq!(owned.slice(), &[1, 2, 3, 4, 5]);
}
