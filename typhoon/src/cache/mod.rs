//! Lock-free snapshot-based primitives for sharing per-session state across flow managers
//! without per-packet locking: `CachedValue` for single values, `SharedMap`/`CachedMap` for the
//! global user table.

mod common;
#[cfg(feature = "server")]
mod map;
mod value;

pub(crate) use common::CacheError;
#[cfg(feature = "server")]
pub(crate) use map::{CachedMap, CachedMapEntryTemplate, SharedMap};
#[cfg(feature = "client")]
pub(crate) use value::CachedValue;
pub use value::DerivedValue;
#[cfg(any(feature = "client", all(test, feature = "server")))]
pub(crate) use value::SharedValue;
