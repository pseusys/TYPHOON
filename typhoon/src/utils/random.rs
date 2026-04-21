use rand::RngCore;
use rand::rngs::OsRng;
use rand::CryptoRng;
#[cfg(feature = "client")]
use rand::Rng;
#[cfg(test)]
use rand::SeedableRng;

use crate::bytes::FixedByteBuffer;

/// Extension methods on top of the standard `Rng` interface.
pub trait SupportRng {
    fn random_byte_array<const T: usize>(&mut self) -> [u8; T];

    fn random_byte_buffer<const T: usize>(&mut self) -> FixedByteBuffer<T>;

    #[cfg(feature = "client")]
    fn random_item<'a, T>(&mut self, slice: &'a [T]) -> Option<&'a T>;
}

// ── TyphoonRng ────────────────────────────────────────────────────────────────

/// Unified RNG wrapper used throughout the codebase.
///
/// In production this is always backed by `OsRng`.  In test builds, calling
/// [`set_test_rng_seed`] replaces it with a deterministic `StdRng` for the
/// current thread, making packet-construction randomness reproducible.
pub enum TyphoonRng {
    Os(OsRng),
    #[cfg(test)]
    Seeded(rand::rngs::StdRng),
}

impl RngCore for TyphoonRng {
    fn next_u32(&mut self) -> u32 {
        match self {
            TyphoonRng::Os(r) => r.next_u32(),
            #[cfg(test)]
            TyphoonRng::Seeded(r) => r.next_u32(),
        }
    }

    fn next_u64(&mut self) -> u64 {
        match self {
            TyphoonRng::Os(r) => r.next_u64(),
            #[cfg(test)]
            TyphoonRng::Seeded(r) => r.next_u64(),
        }
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        match self {
            TyphoonRng::Os(r) => r.fill_bytes(dest),
            #[cfg(test)]
            TyphoonRng::Seeded(r) => r.fill_bytes(dest),
        }
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
        match self {
            TyphoonRng::Os(r) => r.try_fill_bytes(dest),
            #[cfg(test)]
            TyphoonRng::Seeded(r) => r.try_fill_bytes(dest),
        }
    }
}

/// `TyphoonRng` is considered crypto-safe: the production variant uses `OsRng`
/// directly, and the seeded variant is only reachable in test builds where the
/// caller explicitly opts in to determinism.
impl CryptoRng for TyphoonRng {}

impl SupportRng for TyphoonRng {
    fn random_byte_array<const T: usize>(&mut self) -> [u8; T] {
        let mut buf = [0u8; T];
        self.fill_bytes(&mut buf);
        buf
    }

    fn random_byte_buffer<const T: usize>(&mut self) -> FixedByteBuffer<T> {
        FixedByteBuffer::from_array(self.random_byte_array::<T>())
    }

    #[cfg(feature = "client")]
    fn random_item<'a, T>(&mut self, slice: &'a [T]) -> Option<&'a T> {
        if slice.is_empty() {
            None
        } else {
            Some(&slice[self.gen_range(0..slice.len())])
        }
    }
}

// ── Test seed management ──────────────────────────────────────────────────────

#[cfg(test)]
use std::cell::RefCell;

// Per-thread seeded RNG used when a test calls [`set_test_rng_seed`].
// Each [`get_rng`] call forks an independent `StdRng` from this state so
// callers advance independently but the overall sequence is deterministic.
#[cfg(test)]
thread_local! {
    static TEST_RNG: RefCell<Option<rand::rngs::StdRng>> = const { RefCell::new(None) };
}

/// Seed the per-thread deterministic RNG for the current test.
///
/// After calling this, every [`get_rng`] call on this thread returns a
/// deterministic `StdRng` forked from the shared state rather than `OsRng`.
/// Call with different seeds in different tests to get independent sequences.
#[cfg(test)]
pub fn set_test_rng_seed(seed: u64) {
    TEST_RNG.with(|r| *r.borrow_mut() = Some(rand::rngs::StdRng::seed_from_u64(seed)));
}

#[cfg(test)]
/// Reset the per-thread RNG back to `OsRng` (undo [`set_test_rng_seed`]).
pub fn clear_test_rng() {
    TEST_RNG.with(|r| *r.borrow_mut() = None);
}

// ── Factory ───────────────────────────────────────────────────────────────────

/// Return a `TyphoonRng` for this call site.
///
/// In production: always `OsRng`.
/// In tests: if [`set_test_rng_seed`] was called, forks a deterministic
/// `StdRng` from the thread-local state (so each call gets an independent
/// but reproducible sequence); otherwise falls back to `OsRng`.
#[inline]
pub fn get_rng() -> TyphoonRng {
    #[cfg(test)]
    {
        let forked = TEST_RNG.with(|r| {
            r.borrow_mut().as_mut().map(|rng| {
                rand::rngs::StdRng::seed_from_u64(rng.next_u64())
            })
        });
        if let Some(seeded) = forked {
            return TyphoonRng::Seeded(seeded);
        }
    }
    TyphoonRng::Os(OsRng)
}
