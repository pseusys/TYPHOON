use rand::rngs::OsRng;
use rand::{CryptoRng, Rng};

use crate::bytes::FixedByteBuffer;

pub trait SupportRng {
    fn random_byte_array<const T: usize>(&mut self) -> [u8; T];

    fn random_byte_buffer<const T: usize>(&mut self) -> FixedByteBuffer<T>;

    fn random_item<'a, T>(&mut self, slice: &'a [T]) -> Option<&'a T>;
}

impl SupportRng for OsRng {
    fn random_byte_array<const T: usize>(&mut self) -> [u8; T] {
        let mut empty_buffer = [0u8; T];
        self.fill(empty_buffer.as_mut_slice());
        empty_buffer
    }

    fn random_byte_buffer<const T: usize>(&mut self) -> FixedByteBuffer<T> {
        FixedByteBuffer::from_array(self.random_byte_array::<T>())
    }

    fn random_item<'a, T>(&mut self, slice: &'a [T]) -> Option<&'a T> {
        if slice.is_empty() {
            None
        } else {
            Some(&slice[self.gen_range(0..slice.len())])
        }
    }
}

#[inline]
pub fn get_rng() -> impl Rng + CryptoRng + SupportRng {
    OsRng
}
