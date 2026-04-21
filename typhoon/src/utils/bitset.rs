#[cfg(test)]
#[path = "../../tests/utils/bitset.rs"]
mod tests;

/// Lock-free atomic bitset of arbitrary width, backed by a `Box<[AtomicU64]>`.
use std::sync::atomic::{AtomicU64, Ordering};

use rand::Rng;

use crate::utils::random::get_rng;

/// A fixed-capacity bitset whose individual bits can be set atomically from any thread.
/// The capacity is determined at construction time; out-of-range bit indices are silently ignored.
pub struct AtomicBitSet {
    words: Box<[AtomicU64]>,
}

impl AtomicBitSet {
    /// Create a new bitset capable of holding `num_bits` bits, all initially clear.
    pub fn new(num_bits: usize) -> Self {
        let num_words = num_bits.div_ceil(64);
        let words = (0..num_words).map(|_| AtomicU64::new(0)).collect::<Vec<_>>().into_boxed_slice();
        Self {
            words,
        }
    }

    /// Atomically set bit `bit`. No-op if `bit` is out of range.
    #[inline]
    pub fn set(&self, bit: usize) {
        let word = bit / 64;
        if word < self.words.len() {
            self.words[word].fetch_or(1u64 << (bit % 64), Ordering::Relaxed);
        }
    }

    /// Return a uniformly random index of a set bit in `[0, num_bits)`.
    /// Falls back to `0` if no bits are set (e.g. no flows seen yet).
    /// Uses reservoir sampling so no heap allocation is required.
    pub fn random_set_index(&self, num_bits: usize) -> usize {
        let max_word = num_bits.div_ceil(64).min(self.words.len());
        let mut result = 0usize;
        let mut count = 0u64;

        for w in 0..max_word {
            let mut word = self.words[w].load(Ordering::Relaxed);
            while word != 0 {
                let bit = word.trailing_zeros() as usize;
                let global = w * 64 + bit;
                if global < num_bits {
                    count += 1;
                    // Reservoir sampling: replace current result with probability 1/count.
                    if get_rng().gen_range(0..count) == 0 {
                        result = global;
                    }
                }
                word &= word - 1; // clear lowest set bit
            }
        }

        result
    }
}
