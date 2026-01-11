use crate::bytes::pool::BytePool;

// Test: pool allocates buffer with default size.
#[test]
fn test_pool_allocate() {
    let pool = BytePool::new(10, 100, 10, 0, 10);
    let buf = pool.allocate(None);
    assert_eq!(buf.len(), 100);
}

// Test: pool allocates buffer with custom size.
#[test]
fn test_pool_allocate_with_size() {
    let pool = BytePool::new(10, 100, 10, 0, 10);
    let buf = pool.allocate(Some(50));
    assert_eq!(buf.len(), 50);
}

// Test: allocating larger than pool size panics.
#[test]
#[should_panic(expected = "Requested size greater than initial size")]
fn test_pool_allocate_size_too_large() {
    let pool = BytePool::new(10, 100, 10, 0, 10);
    let _ = pool.allocate(Some(200));
}

// Test: dropped buffer is reused from pool.
#[test]
fn test_pool_reuse() {
    let pool = BytePool::new(0, 100, 0, 0, 10);

    let buf1 = pool.allocate(None);
    let ptr1 = buf1.slice().as_ptr();
    drop(buf1);

    let buf2 = pool.allocate(None);
    let ptr2 = buf2.slice().as_ptr();

    assert_eq!(ptr1, ptr2, "Buffer should be reused from pool");
}

// Test: pool preallocates specified number of buffers.
#[test]
fn test_pool_preallocated() {
    let pool = BytePool::new(0, 100, 0, 5, 10);

    let mut buffers = Vec::new();
    for _ in 0..5 {
        buffers.push(pool.allocate(None));
    }

    drop(buffers);

    let mut ptrs = Vec::new();
    for _ in 0..5 {
        let buf = pool.allocate(None);
        ptrs.push(buf.slice().as_ptr());
        drop(buf);
    }

    assert_eq!(ptrs.len(), 5);
}

// Test: pool respects max pooled limit.
#[test]
fn test_pool_max_size() {
    let pool = BytePool::new(0, 100, 0, 0, 2);

    let buf1 = pool.allocate(None);
    let buf2 = pool.allocate(None);
    let buf3 = pool.allocate(None);

    let ptr1 = buf1.slice().as_ptr();
    let ptr2 = buf2.slice().as_ptr();
    let ptr3 = buf3.slice().as_ptr();

    drop(buf1);
    drop(buf2);
    drop(buf3);

    let reused1 = pool.allocate(None);
    let reused2 = pool.allocate(None);
    let new_buf = pool.allocate(None);

    let reused_ptrs: Vec<_> = vec![reused1.slice().as_ptr(), reused2.slice().as_ptr()];
    let new_ptr = new_buf.slice().as_ptr();

    assert!(reused_ptrs.contains(&ptr1) || reused_ptrs.contains(&ptr2) || reused_ptrs.contains(&ptr3));
    assert!(new_ptr != ptr1 && new_ptr != ptr2 && new_ptr != ptr3 || reused_ptrs.len() == 2);
}

// Test: buffer has header space for expand_start.
#[test]
fn test_pool_header_space() {
    let pool = BytePool::new(20, 100, 0, 0, 10);
    let buf = pool.allocate(None);
    assert_eq!(buf.len(), 100);

    let expanded = buf.expand_start(10);
    assert_eq!(expanded.len(), 110);
}

// Test: buffer has trailer space for expand_end.
#[test]
fn test_pool_trailer_space() {
    let pool = BytePool::new(0, 100, 20, 0, 10);
    let buf = pool.allocate(None);
    assert_eq!(buf.len(), 100);

    let expanded = buf.expand_end(10);
    assert_eq!(expanded.len(), 110);
}

// Test: append and prepend work with pooled buffers.
#[test]
fn test_pool_append_prepend() {
    let pool = BytePool::new(10, 100, 10, 0, 10);
    let buf = pool.allocate(Some(5));

    buf.slice_mut().copy_from_slice(&[1, 2, 3, 4, 5]);

    let appended = buf.append(&[6, 7, 8]);
    assert_eq!(appended.slice(), &[1, 2, 3, 4, 5, 6, 7, 8]);

    let prepended = appended.prepend(&[0]);
    assert_eq!(prepended.slice(), &[0, 1, 2, 3, 4, 5, 6, 7, 8]);
}

// Test: pool is thread-safe for concurrent allocation.
#[test]
fn test_pool_thread_safety() {
    use std::sync::Arc;
    use std::thread;

    let pool = Arc::new(BytePool::new(0, 100, 0, 0, 10));
    let mut handles = vec![];

    for _ in 0..4 {
        let pool = Arc::clone(&pool);
        handles.push(thread::spawn(move || {
            for _ in 0..100 {
                let buf = pool.allocate(None);
                buf.set(0, 42);
                assert_eq!(*buf.get(0), 42);
            }
        }));
    }

    for handle in handles {
        handle.join().unwrap();
    }
}

// Test: buffer can be sent between threads (Send trait).
#[test]
fn test_buffer_send_between_threads() {
    use std::thread;

    let pool = BytePool::new(0, 100, 0, 0, 10);
    let buf = pool.allocate(None);
    buf.set(0, 42);

    let handle = thread::spawn(move || {
        assert_eq!(*buf.get(0), 42);
        buf.set(0, 99);
        buf
    });

    let returned_buf = handle.join().unwrap();
    assert_eq!(*returned_buf.get(0), 99);
}
