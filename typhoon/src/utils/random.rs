use rand::rngs::OsRng;
use rand::{CryptoRng, Rng};

use crate::bytes::StaticByteBuffer;

pub trait SupportRng {
    fn random_byte_array<const T: usize>(&mut self) -> [u8; T];

    fn random_byte_buffer<const T: usize>(&mut self) -> StaticByteBuffer;
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
}

#[inline]
pub fn get_rng() -> impl Rng + CryptoRng + SupportRng {
    OsRng
}
