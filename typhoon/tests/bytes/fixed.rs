use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

use crate::bytes::{ByteBuffer, FixedByteBuffer};

// ── Construction ─────────────────────────────────────────────────────────────

#[test]
fn test_zeroed() {
    let buf = FixedByteBuffer::<8>::zeroed();
    assert_eq!(buf.slice(), &[0u8; 8]);
}

#[test]
fn test_from_array() {
    let arr = [1u8, 2, 3, 4];
    let buf = FixedByteBuffer::<4>::from_array(arr);
    assert_eq!(buf.slice(), &[1, 2, 3, 4]);
}

#[test]
fn test_as_array() {
    let arr = [10u8, 20, 30];
    let buf = FixedByteBuffer::<3>::from_array(arr);
    assert_eq!(buf.as_array(), &arr);
}

#[test]
fn test_default_is_zeroed() {
    let buf = FixedByteBuffer::<6>::default();
    assert_eq!(buf.slice(), &[0u8; 6]);
}

#[test]
fn test_copy_semantics() {
    let buf = FixedByteBuffer::<4>::from_array([1, 2, 3, 4]);
    let copy = buf;
    let _ = copy.as_array();  // ensure copy compiles fine
    // Original is unchanged (Copy not Clone-from-ref).
    assert_eq!(buf.slice(), &[1, 2, 3, 4]);
}

// ── ByteBuffer trait ─────────────────────────────────────────────────────────

#[test]
fn test_len() {
    assert_eq!(FixedByteBuffer::<12>::zeroed().len(), 12);
    assert_eq!(FixedByteBuffer::<1>::zeroed().len(), 1);
}

#[test]
fn test_get() {
    let buf = FixedByteBuffer::<4>::from_array([10, 20, 30, 40]);
    assert_eq!(*buf.get(0), 10);
    assert_eq!(*buf.get(3), 40);
}

#[test]
#[should_panic(expected = "index out of bounds")]
fn test_get_out_of_bounds() {
    let buf = FixedByteBuffer::<4>::zeroed();
    let _ = buf.get(4);
}

#[test]
fn test_slice() {
    let arr = [5u8, 6, 7, 8];
    let buf = FixedByteBuffer::<4>::from_array(arr);
    assert_eq!(buf.slice(), &arr);
}

#[test]
fn test_slice_start() {
    let buf = FixedByteBuffer::<4>::from_array([1, 2, 3, 4]);
    assert_eq!(buf.slice_start(2), &[3, 4]);
    assert_eq!(buf.slice_start(0), &[1, 2, 3, 4]);
}

#[test]
fn test_slice_end() {
    let buf = FixedByteBuffer::<4>::from_array([1, 2, 3, 4]);
    assert_eq!(buf.slice_end(2), &[1, 2]);
    assert_eq!(buf.slice_end(4), &[1, 2, 3, 4]);
}

#[test]
fn test_slice_both() {
    let buf = FixedByteBuffer::<6>::from_array([0, 1, 2, 3, 4, 5]);
    assert_eq!(buf.slice_both(1, 4), &[1, 2, 3]);
    assert_eq!(buf.slice_both(0, 6), &[0, 1, 2, 3, 4, 5]);
}

#[test]
fn test_split() {
    let buf = FixedByteBuffer::<4>::from_array([1, 2, 3, 4]);
    let (a, b) = buf.split(2);
    assert_eq!(a, &[1, 2]);
    assert_eq!(b, &[3, 4]);
}

#[test]
fn test_as_ref() {
    let buf = FixedByteBuffer::<3>::from_array([9, 8, 7]);
    let r: &[u8] = buf.as_ref();
    assert_eq!(r, &[9, 8, 7]);
}

// ── Conversions ──────────────────────────────────────────────────────────────

#[test]
fn test_from_arr_trait() {
    let buf: FixedByteBuffer<4> = [1u8, 2, 3, 4].into();
    assert_eq!(buf.slice(), &[1, 2, 3, 4]);
}

#[test]
fn test_from_arr_ref_trait() {
    let arr = [7u8, 8, 9];
    let buf = FixedByteBuffer::<3>::from(&arr);
    assert_eq!(buf.slice(), &[7, 8, 9]);
}

#[test]
fn test_into_array() {
    let buf = FixedByteBuffer::<3>::from_array([11, 22, 33]);
    let arr: [u8; 3] = buf.into();
    assert_eq!(arr, [11, 22, 33]);
}

// ── Equality, hashing ────────────────────────────────────────────────────────

#[test]
fn test_partial_eq() {
    let a = FixedByteBuffer::<4>::from_array([1, 2, 3, 4]);
    let b = FixedByteBuffer::<4>::from_array([1, 2, 3, 4]);
    let c = FixedByteBuffer::<4>::from_array([1, 2, 3, 5]);
    assert_eq!(a, b);
    assert_ne!(a, c);
}

#[test]
fn test_hash_equal_for_equal_values() {
    let a = FixedByteBuffer::<4>::from_array([1, 2, 3, 4]);
    let b = FixedByteBuffer::<4>::from_array([1, 2, 3, 4]);
    let mut ha = DefaultHasher::new();
    let mut hb = DefaultHasher::new();
    a.hash(&mut ha);
    b.hash(&mut hb);
    assert_eq!(ha.finish(), hb.finish());
}

// ── Formatting ───────────────────────────────────────────────────────────────

#[test]
fn test_display_hex() {
    let buf = FixedByteBuffer::<3>::from_array([0xde, 0xad, 0xbe]);
    assert_eq!(format!("{buf}"), "deadbe");
}

#[test]
fn test_debug_includes_length() {
    let buf = FixedByteBuffer::<2>::from_array([0, 1]);
    let s = format!("{buf:?}");
    assert!(s.contains("length"), "debug output should include 'length': {s}");
}
