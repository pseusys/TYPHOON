use rand::CryptoRng;
use rand::Rng;

#[cfg(not(test))]
use rand::rngs::OsRng;

pub const DEFAULT_KEY_LENGTH: usize = 32;

pub trait SupportRng {
    fn generate_key(&mut self) -> [u8; DEFAULT_KEY_LENGTH];
}

#[cfg(not(test))]
impl SupportRng for OsRng {
    fn generate_key(&mut self) -> [u8; DEFAULT_KEY_LENGTH] {
        let mut key = [0u8; DEFAULT_KEY_LENGTH];
        self.fill(&mut key);
        key
    }
}

#[cfg(test)]
struct MockRng;

#[cfg(test)]
impl rand::RngCore for MockRng {
    fn next_u32(&mut self) -> u32 {
        0u32
    }

    fn next_u64(&mut self) -> u64 {
        0u64
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        dest.fill(0u8)
    }
    
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
        Ok(self.fill_bytes(dest))
    }
}

#[cfg(test)]
impl CryptoRng for MockRng {}

#[cfg(test)]
impl SupportRng for MockRng {
    fn generate_key(&mut self) -> [u8; DEFAULT_KEY_LENGTH] {
        [0u8; DEFAULT_KEY_LENGTH]
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
