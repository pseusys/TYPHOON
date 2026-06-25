#[cfg(test)]
#[path = "../../tests/bytes/utils.rs"]
mod tests;

use std::ptr::{copy_nonoverlapping, slice_from_raw_parts_mut};

pub(crate) fn preserve_vector(vector: Vec<u8>) -> *mut u8 {
    vector.leak().as_mut_ptr()
}

pub(crate) fn allocate_ptr(size: usize) -> *mut u8 {
    preserve_vector(vec![0u8; size])
}

pub(crate) fn copy_slice(ptr: *mut u8, slice: &[u8]) {
    unsafe {
        copy_nonoverlapping(slice.as_ptr(), ptr, slice.len());
    }
}

pub(crate) fn free_ptr(ptr: *mut u8, length: usize) {
    drop(unsafe { Box::from_raw(slice_from_raw_parts_mut(ptr, length)) });
}
