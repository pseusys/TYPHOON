//! Shared evaluation helpers for the TYPHOON eval client/server binaries.
//!
//! - `profile`: runtime-configurable traffic profiles selected via the
//!   `TRAFFIC_PROFILE` environment variable.
//! - `identity`: 4-byte `ShortIdentity` type + matching server handler used
//!   by both binaries to lower the per-packet wire-overhead floor.

pub mod identity;
pub mod profile;
