use generic_array::{ArrayLength, GenericArray};
use rand::{CryptoRng, Error, Rng, RngCore};

#[cfg(not(test))]
use rand::rngs::OsRng;

pub trait SupportRng {
    fn random_byte_array<T: ArrayLength>(&mut self) -> GenericArray<u8, T>;
}

#[cfg(not(test))]
impl SupportRng for OsRng {
    fn random_byte_array<T: ArrayLength>(&mut self) -> GenericArray<u8, T> {
        let mut empty_array = GenericArray::<u8, T>::default();
        self.fill(&mut empty_array[..]);
        empty_array
    }
}

#[cfg(test)]
struct MockRng;

#[cfg(test)]
impl RngCore for MockRng {
    fn next_u32(&mut self) -> u32 {
        0u32
    }

    fn next_u64(&mut self) -> u64 {
        0u64
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        dest.fill(0u8)
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Error> {
        Ok(self.fill_bytes(dest))
    }
}

#[cfg(test)]
impl CryptoRng for MockRng {}

#[cfg(test)]
impl SupportRng for MockRng {
    fn random_byte_array<T: ArrayLength>(&mut self) -> GenericArray<u8, T> {
        GenericArray::<u8, T>::default()
    }
}

#[inline]
#[cfg(test)]
pub(crate) fn get_rng() -> impl Rng + CryptoRng + SupportRng {
    MockRng
}

#[inline]
#[cfg(not(test))]
pub(crate) fn get_rng() -> impl Rng + CryptoRng + SupportRng {
    OsRng
}
