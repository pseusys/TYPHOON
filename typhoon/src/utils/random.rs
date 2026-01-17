use generic_array::{ArrayLength, GenericArray};
use rand::rngs::OsRng;
use rand::{CryptoRng, Rng};

pub trait SupportRng {
    fn random_byte_array<T: ArrayLength>(&mut self) -> GenericArray<u8, T>;
}

impl SupportRng for OsRng {
    fn random_byte_array<T: ArrayLength>(&mut self) -> GenericArray<u8, T> {
        let mut empty_array = GenericArray::<u8, T>::default();
        self.fill(&mut empty_array[..]);
        empty_array
    }
}

#[inline]
pub fn get_rng() -> impl Rng + CryptoRng + SupportRng {
    OsRng
}
