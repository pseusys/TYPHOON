use crate::bytes::{ByteBuffer, StaticByteBuffer};

// Test: empty buffer has correct size and is not empty.
#[test]
fn test_empty_buffer() {
    let buf = StaticByteBuffer::empty(100);
    assert_eq!(buf.len(), 100);
    assert!(!buf.is_empty());
}

// Test: zero-size buffer is empty.
#[test]
fn test_empty_zero_size() {
    let buf = StaticByteBuffer::empty(0);
    assert_eq!(buf.len(), 0);
    assert!(buf.is_empty());
}

// Test: buffer created from Vec has correct data.
#[test]
fn test_from_vec() {
    let data = vec![1u8, 2, 3, 4, 5];
    let buf: StaticByteBuffer = data.into();
    assert_eq!(buf.len(), 5);
    assert_eq!(buf.slice(), &[1, 2, 3, 4, 5]);
}

// Test: buffer created from slice has correct data.
#[test]
fn test_from_slice() {
    let data = [1u8, 2, 3, 4, 5];
    let buf: StaticByteBuffer = data.as_slice().into();
    assert_eq!(buf.len(), 5);
    assert_eq!(buf.slice(), &[1, 2, 3, 4, 5]);
}

// Test: buffer converts back to Vec correctly.
#[test]
fn test_into_vec() {
    let data = vec![1u8, 2, 3, 4, 5];
    let buf: StaticByteBuffer = data.into();
    let result: Vec<u8> = buf.into();
    assert_eq!(result, vec![1, 2, 3, 4, 5]);
}

// Test: get byte access works correctly.
#[test]
fn test_get() {
    let data = vec![42u8, 0, 0, 0, 0, 100];
    let buf: StaticByteBuffer = data.into();
    assert_eq!(*buf.get(0), 42);
    assert_eq!(*buf.get(5), 100);
}

// Test: get out of bounds panics.
#[test]
#[should_panic(expected = "index out of bounds")]
fn test_get_out_of_bounds() {
    let buf = StaticByteBuffer::empty(10);
    let _ = buf.get(10);
}

// Test: slice_start returns suffix from offset.
#[test]
fn test_slice_start() {
    let data = vec![1u8, 2, 3, 4, 5];
    let buf: StaticByteBuffer = data.into();
    assert_eq!(buf.slice_start(2), &[3, 4, 5]);
}

// Test: slice_end returns prefix up to offset.
#[test]
fn test_slice_end() {
    let data = vec![1u8, 2, 3, 4, 5];
    let buf: StaticByteBuffer = data.into();
    assert_eq!(buf.slice_end(3), &[1, 2, 3]);
}

// Test: slice_both returns range [start, end).
#[test]
fn test_slice_both() {
    let data = vec![1u8, 2, 3, 4, 5];
    let buf: StaticByteBuffer = data.into();
    assert_eq!(buf.slice_both(1, 4), &[2, 3, 4]);
}

// Test: split returns two immutable slice halves.
#[test]
fn test_split() {
    let data = vec![1u8, 2, 3, 4, 5];
    let buf: StaticByteBuffer = data.into();
    let (left, right) = buf.split(2);
    assert_eq!(left, &[1, 2]);
    assert_eq!(right, &[3, 4, 5]);
}

// Test: clone shares underlying Arc data.
#[test]
fn test_clone() {
    let data = vec![1u8, 2, 3, 4, 5];
    let buf: StaticByteBuffer = data.into();
    let clone = buf.clone();
    assert_eq!(buf.slice(), clone.slice());
}

// Test: AsRef<[u8]> trait implementation.
#[test]
fn test_as_ref() {
    let data = vec![1u8, 2, 3];
    let buf: StaticByteBuffer = data.into();
    let slice: &[u8] = buf.as_ref();
    assert_eq!(slice, &[1, 2, 3]);
}

// Test: from_array creates buffer from fixed-size array.
#[test]
fn test_from_array() {
    let arr = [1u8, 2, 3, 4, 5];
    let buf = StaticByteBuffer::from_array(&arr);
    assert_eq!(buf.len(), 5);
    assert_eq!(buf.slice(), &[1, 2, 3, 4, 5]);
}

// Test: From<[u8; N]> trait implementation.
#[test]
fn test_from_array_trait() {
    let buf: StaticByteBuffer = (&[1u8, 2, 3, 4, 5]).into();
    assert_eq!(buf.len(), 5);
    assert_eq!(buf.slice(), &[1, 2, 3, 4, 5]);
}

// Test: Into<[u8; N]> trait implementation.
#[test]
fn test_into_array() {
    let data = vec![1u8, 2, 3, 4, 5];
    let buf: StaticByteBuffer = data.into();
    let arr: [u8; 5] = (&buf).into();
    assert_eq!(arr, [1, 2, 3, 4, 5]);
}

// Test: PartialEq implementation.
#[test]
fn test_partial_eq() {
    let buf1: StaticByteBuffer = vec![1u8, 2, 3].into();
    let buf2: StaticByteBuffer = vec![1u8, 2, 3].into();
    let buf3: StaticByteBuffer = vec![1u8, 2, 4].into();
    assert_eq!(buf1, buf2);
    assert_ne!(buf1, buf3);
}

// Test: Debug implementation.
#[test]
fn test_debug() {
    let data = vec![1u8, 2, 3];
    let buf: StaticByteBuffer = data.into();
    let debug_str = format!("{buf:?}");
    assert!(debug_str.contains("StaticByteBuffer"));
    assert!(debug_str.contains("length"));
}

// Test: Send + Sync markers (compile-time check).
#[test]
fn test_send_sync() {
    fn assert_send<T: Send>() {}
    fn assert_sync<T: Sync>() {}
    assert_send::<StaticByteBuffer>();
    assert_sync::<StaticByteBuffer>();
}

// Test: Can be used across threads.
#[test]
fn test_thread_safety() {
    use std::thread;

    let data = vec![1u8, 2, 3, 4, 5];
    let buf: StaticByteBuffer = data.into();
    let buf_clone = buf.clone();

    let handle = thread::spawn(move || {
        assert_eq!(buf_clone.slice(), &[1, 2, 3, 4, 5]);
    });

    assert_eq!(buf.slice(), &[1, 2, 3, 4, 5]);
    handle.join().unwrap();
}
