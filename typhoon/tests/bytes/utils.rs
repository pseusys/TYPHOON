use crate::bytes::utils::{allocate_ptr, copy_ptr, free_ptr, preserve_vector};

// Test: allocate_ptr returns zeroed memory.
#[test]
fn test_allocate_ptr() {
    let ptr = allocate_ptr(100);
    assert!(!ptr.is_null());

    unsafe {
        for i in 0..100 {
            assert_eq!(*ptr.add(i), 0);
        }
    }

    free_ptr(ptr, 100);
}

// Test: copy_ptr creates independent copy.
#[test]
fn test_copy_ptr() {
    let src = allocate_ptr(10);
    unsafe {
        for i in 0..10 {
            *src.add(i) = i as u8;
        }
    }

    let dst = copy_ptr(src, 10);
    assert!(!dst.is_null());
    assert_ne!(src, dst);

    unsafe {
        for i in 0..10 {
            assert_eq!(*dst.add(i), i as u8);
        }
    }

    free_ptr(src, 10);
    free_ptr(dst, 10);
}

// Test: preserve_vector converts Vec to raw pointer.
#[test]
fn test_preserve_vector() {
    let vec = vec![1u8, 2, 3, 4, 5];
    let ptr = preserve_vector(vec);

    unsafe {
        assert_eq!(*ptr, 1);
        assert_eq!(*ptr.add(4), 5);
    }

    free_ptr(ptr, 5);
}

// Test: free_ptr deallocates memory without crash.
#[test]
fn test_free_ptr() {
    let ptr = allocate_ptr(1000);
    free_ptr(ptr, 1000);
}
