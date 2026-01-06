#[inline]
pub fn xor_bytes(a: &mut [u8], b: &[u8]) {
    for (x, y) in a.iter_mut().zip(b.iter()) {
        *x ^= *y;
    }
}
