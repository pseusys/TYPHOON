//! Internal runtime utilities: lock-free bitsets, RNG helpers, the socket wrapper, and the
//! runtime-agnostic async primitives in `sync`.

#[cfg(feature = "server")]
pub mod bitset;
pub mod random;
pub mod socket;
pub mod sync;

use std::str::from_utf8;
use std::time::{SystemTime, UNIX_EPOCH};

/// Current Unix timestamp in milliseconds.
#[inline]
pub fn unix_timestamp_ms() -> u128 {
    SystemTime::now().duration_since(UNIX_EPOCH).expect("Time went backwards").as_millis()
}

/// Parse a version byte slice of the form `"major[.minor[.patch[-tag]]]"` into `(major, minor, patch)`.
/// Bytes after the first null are ignored. Components that cannot be parsed default to `0`.
pub(crate) fn parse_version(bytes: &[u8]) -> (u64, u64, u64) {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    let s = from_utf8(&bytes[..end]).unwrap_or("").trim();
    let base = s.split('-').next().unwrap_or(s);
    let mut parts = base.split('.');
    let major = parts.next().and_then(|s| s.parse().ok()).unwrap_or(0);
    let minor = parts.next().and_then(|s| s.parse().ok()).unwrap_or(0);
    let patch = parts.next().and_then(|s| s.parse().ok()).unwrap_or(0);
    (major, minor, patch)
}
