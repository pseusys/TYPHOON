#[cfg(feature = "server")]
pub mod bitset;
pub mod random;
pub mod socket;
pub mod sync;

use std::time::{SystemTime, UNIX_EPOCH};

/// Current Unix timestamp in milliseconds.
#[inline]
pub fn unix_timestamp_ms() -> u128 {
    SystemTime::now().duration_since(UNIX_EPOCH).expect("Time went backwards").as_millis()
}
