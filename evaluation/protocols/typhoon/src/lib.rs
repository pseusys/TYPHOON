//! Shared evaluation helpers for the TYPHOON eval client/server binaries.
//!
//! Currently exposes the `profile` module — runtime-configurable traffic
//! profiles selected via the `TRAFFIC_PROFILE` environment variable.

pub mod profile;
