#[cfg(feature = "client")]
use rand::Rng;
#[cfg(test)]
use rand::SeedableRng;
use rand::rngs::OsRng;
use rand::{CryptoRng, RngCore};

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
        let forked = TEST_RNG.with(|r| r.borrow_mut().as_mut().map(|rng| rand::rngs::StdRng::seed_from_u64(rng.next_u64())));
        if let Some(seeded) = forked {
            return TyphoonRng::Seeded(seeded);
        }
    }
    TyphoonRng::Os(OsRng)
}

#[cfg(test)]
#[path = "../../tests/utils/random.rs"]
mod tests;

/// Sample a chunk size around `chunk` with two-sided `jitter`, clamped to `[1, max_payload]`, `chunk == 0` is the sentinel for "saturate the MTU".
#[cfg(feature = "client")]
#[inline]
pub fn jittered_chunk_size(max_payload: usize, chunk: usize, jitter: f64) -> usize {
    let target = if chunk == 0 { max_payload } else { chunk };
    if max_payload <= 1 {
        return max_payload;
    }
    let target_f = target as f64;
    let delta = (target_f * jitter).round() as usize;
    let lo = target.saturating_sub(delta).max(1);
    let hi = target.saturating_add(delta).min(max_payload);
    if lo >= hi {
        return hi;
    }
    get_rng().gen_range(lo..=hi)
}


/// Picks one of several branches at random, weighted by the per-branch weights, and
/// evaluates the chosen branch as an expression (its value is the value of the macro).
///
/// Each branch is either `weight => body` or just `body` (implied weight `1u32`).
/// Weights must be `u32` expressions; bodies must all evaluate to the same type.
/// Branches are separated by commas; trailing block bodies may omit the comma.
#[macro_export]
macro_rules! weighted_random {
    // ── Final step: emit the weighted dispatch ────────────────────────────────
    (@parse {} -> ($($weights:expr,)*) ($($bodies:expr,)*)) => {{
        use weighted_rand::builder::NewBuilder as _;
        let __weights: &[u32] = &[$( ($weights) as u32 ),*];
        let __table = weighted_rand::builder::WalkerTableBuilder::new(__weights).build();
        let mut __rng = $crate::utils::random::get_rng();
        let __idx = __table.next_rng(&mut __rng);
        'wr: {
            let mut __i = 0usize;
            $(
                if __idx == __i { break 'wr ($bodies); }
                #[allow(unused_assignments)]
                { __i += 1; }
            )*
            unreachable!()
        }
    }};

    // ── Skip leading comma (allows trailing/leading commas naturally) ─────────
    (@parse {, $($rest:tt)*} -> ($($weights:expr,)*) ($($bodies:expr,)*)) => {
        $crate::weighted_random!(@parse {$($rest)*} -> ($($weights,)*) ($($bodies,)*))
    };

    // ── `weight => { block }` followed by more (no trailing comma needed) ─────
    (@parse {$weight:expr => $body:block $($rest:tt)*} -> ($($weights:expr,)*) ($($bodies:expr,)*)) => {
        $crate::weighted_random!(@parse {$($rest)*} -> ($($weights,)* $weight,) ($($bodies,)* $body,))
    };

    // ── Bare `{ block }` followed by more (no trailing comma needed) ──────────
    (@parse {$body:block $($rest:tt)*} -> ($($weights:expr,)*) ($($bodies:expr,)*)) => {
        $crate::weighted_random!(@parse {$($rest)*} -> ($($weights,)* 1u32,) ($($bodies,)* $body,))
    };

    // ── `weight => expr, ...` ─────────────────────────────────────────────────
    (@parse {$weight:expr => $body:expr, $($rest:tt)*} -> ($($weights:expr,)*) ($($bodies:expr,)*)) => {
        $crate::weighted_random!(@parse {$($rest)*} -> ($($weights,)* $weight,) ($($bodies,)* $body,))
    };
    // ── final `weight => expr` (no trailing comma) ────────────────────────────
    (@parse {$weight:expr => $body:expr} -> ($($weights:expr,)*) ($($bodies:expr,)*)) => {
        $crate::weighted_random!(@parse {} -> ($($weights,)* $weight,) ($($bodies,)* $body,))
    };

    // ── bare `expr, ...` ──────────────────────────────────────────────────────
    (@parse {$body:expr, $($rest:tt)*} -> ($($weights:expr,)*) ($($bodies:expr,)*)) => {
        $crate::weighted_random!(@parse {$($rest)*} -> ($($weights,)* 1u32,) ($($bodies,)* $body,))
    };
    // ── final bare `expr` (no trailing comma) ─────────────────────────────────
    (@parse {$body:expr} -> ($($weights:expr,)*) ($($bodies:expr,)*)) => {
        $crate::weighted_random!(@parse {} -> ($($weights,)* 1u32,) ($($bodies,)* $body,))
    };

    // ── Catch-all: malformed @parse input fails fast (prevents infinite recursion
    //    via the entry arm below).
    (@parse $($_rest:tt)*) => {
        ::core::compile_error!(
            "malformed `weighted_random!` input — expected comma-separated `weight => expr` or `expr` branches"
        )
    };

    // ── Entry point ───────────────────────────────────────────────────────────
    ($($input:tt)*) => {
        $crate::weighted_random!(@parse {$($input)*} -> () ())
    };
}
