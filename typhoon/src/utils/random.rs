use rand::rngs::OsRng;
use rand::{CryptoRng, Rng};

use crate::bytes::StaticByteBuffer;

pub trait SupportRng {
    fn random_byte_array<const T: usize>(&mut self) -> [u8; T];

    fn random_byte_buffer<const T: usize>(&mut self) -> StaticByteBuffer;

    fn random_item<'a, T>(&mut self, vector: &'a Vec<T>) -> Option<&'a T>;
}

impl SupportRng for OsRng {
    fn random_byte_array<const T: usize>(&mut self) -> [u8; T] {
        let mut empty_buffer = [0u8; T];
        self.fill(empty_buffer.as_mut_slice());
        empty_buffer
    }

    fn random_byte_buffer<const T: usize>(&mut self) -> StaticByteBuffer {
        StaticByteBuffer::from_slice(self.random_byte_array::<T>().as_slice())
    }

    fn random_item<'a, T>(&mut self, vector: &'a Vec<T>) -> Option<&'a T> {
        if vector.is_empty() {
            None
        } else {
            Some(&vector[self.gen_range(0..vector.len())])
        }
    }
}

#[inline]
pub fn get_rng() -> impl Rng + CryptoRng + SupportRng {
    OsRng
}
