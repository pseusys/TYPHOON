use crate::bytes::ByteBuffer;

#[test]
fn test_empty_buffer() {
    let buf = ByteBuffer::empty(100);
    assert_eq!(buf.len(), 100);
    assert!(!buf.is_empty());
}

#[test]
fn test_empty_zero_size() {
    let buf = ByteBuffer::empty(0);
    assert_eq!(buf.len(), 0);
    assert!(buf.is_empty());
}

#[test]
fn test_from_vec() {
    let data = vec![1u8, 2, 3, 4, 5];
    let buf: ByteBuffer = data.into();
    assert_eq!(buf.len(), 5);
    assert_eq!(buf.slice(), &[1, 2, 3, 4, 5]);
}

#[test]
fn test_from_slice() {
    let data = [1u8, 2, 3, 4, 5];
    let buf: ByteBuffer = data.as_slice().into();
    assert_eq!(buf.len(), 5);
    assert_eq!(buf.slice(), &[1, 2, 3, 4, 5]);
}

#[test]
fn test_into_vec() {
    let data = vec![1u8, 2, 3, 4, 5];
    let buf: ByteBuffer = data.into();
    let result: Vec<u8> = buf.into();
    assert_eq!(result, vec![1, 2, 3, 4, 5]);
}

#[test]
fn test_get_set() {
    let buf = ByteBuffer::empty(10);
    buf.set(0, 42);
    buf.set(5, 100);
    assert_eq!(*buf.get(0), 42);
    assert_eq!(*buf.get(5), 100);
}

#[test]
#[should_panic(expected = "index out of bounds")]
fn test_get_out_of_bounds() {
    let buf = ByteBuffer::empty(10);
    let _ = buf.get(10);
}

#[test]
#[should_panic(expected = "index out of bounds")]
fn test_set_out_of_bounds() {
    let buf = ByteBuffer::empty(10);
    buf.set(10, 42);
}

#[test]
fn test_slice_mut() {
    let buf = ByteBuffer::empty(5);
    let slice = buf.slice_mut();
    slice[0] = 1;
    slice[4] = 5;
    assert_eq!(buf.slice(), &[1, 0, 0, 0, 5]);
}

#[test]
fn test_slice_start() {
    let data = vec![1u8, 2, 3, 4, 5];
    let buf: ByteBuffer = data.into();
    assert_eq!(buf.slice_start(2), &[3, 4, 5]);
}

#[test]
fn test_slice_end() {
    let data = vec![1u8, 2, 3, 4, 5];
    let buf: ByteBuffer = data.into();
    assert_eq!(buf.slice_end(3), &[1, 2, 3]);
}

#[test]
fn test_slice_both() {
    let data = vec![1u8, 2, 3, 4, 5];
    let buf: ByteBuffer = data.into();
    assert_eq!(buf.slice_both(1, 4), &[2, 3, 4]);
}

#[test]
fn test_split() {
    let data = vec![1u8, 2, 3, 4, 5];
    let buf: ByteBuffer = data.into();
    let (left, right) = buf.split(2);
    assert_eq!(left, &[1, 2]);
    assert_eq!(right, &[3, 4, 5]);
}

#[test]
fn test_split_mut() {
    let buf = ByteBuffer::empty(5);
    let (left, right) = buf.split_mut(2);
    left[0] = 1;
    left[1] = 2;
    right[0] = 3;
    right[1] = 4;
    right[2] = 5;
    assert_eq!(buf.slice(), &[1, 2, 3, 4, 5]);
}

#[test]
fn test_copy() {
    let data = vec![1u8, 2, 3, 4, 5];
    let buf: ByteBuffer = data.into();
    let copy = buf.copy();

    assert_eq!(buf.slice(), copy.slice());

    copy.set(0, 99);
    assert_eq!(*buf.get(0), 1);
    assert_eq!(*copy.get(0), 99);
}

#[test]
fn test_clone_shares_memory() {
    let data = vec![1u8, 2, 3, 4, 5];
    let buf: ByteBuffer = data.into();
    let clone = buf.clone();

    clone.set(0, 99);
    assert_eq!(*buf.get(0), 99);
}

#[test]
fn test_rebuffer_start() {
    let data = vec![1u8, 2, 3, 4, 5];
    let buf: ByteBuffer = data.into();
    let rebuffered = buf.rebuffer_start(2);
    assert_eq!(rebuffered.len(), 3);
    assert_eq!(rebuffered.slice(), &[3, 4, 5]);
}

#[test]
fn test_rebuffer_end() {
    let data = vec![1u8, 2, 3, 4, 5];
    let buf: ByteBuffer = data.into();
    let rebuffered = buf.rebuffer_end(3);
    assert_eq!(rebuffered.len(), 3);
    assert_eq!(rebuffered.slice(), &[1, 2, 3]);
}

#[test]
fn test_rebuffer_both() {
    let data = vec![1u8, 2, 3, 4, 5];
    let buf: ByteBuffer = data.into();
    let rebuffered = buf.rebuffer_both(1, 4);
    assert_eq!(rebuffered.len(), 3);
    assert_eq!(rebuffered.slice(), &[2, 3, 4]);
}

#[test]
fn test_split_buf() {
    let data = vec![1u8, 2, 3, 4, 5];
    let buf: ByteBuffer = data.into();
    let (left, right) = buf.split_buf(2);
    assert_eq!(left.slice(), &[1, 2]);
    assert_eq!(right.slice(), &[3, 4, 5]);
}

#[test]
fn test_as_ref() {
    let data = vec![1u8, 2, 3];
    let buf: ByteBuffer = data.into();
    let slice: &[u8] = buf.as_ref();
    assert_eq!(slice, &[1, 2, 3]);
}

#[test]
fn test_as_mut() {
    let data = vec![1u8, 2, 3];
    let mut buf: ByteBuffer = data.into();
    let slice: &mut [u8] = buf.as_mut();
    slice[0] = 99;
    assert_eq!(buf.slice(), &[99, 2, 3]);
}
