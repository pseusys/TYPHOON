//! Core Settings struct for type-safe configuration access.

use std::env::var;

use log::warn;

use super::builder::SettingsBuilder;
use super::override_map::{Key, OverrideMap, SettingType};
use crate::bytes::BytePool;
use crate::utils::sync::AsyncExecutor;

/// Try to read an environment variable and parse it as type T.
/// Returns None if the variable is not set or cannot be parsed.
fn try_env_override<T: SettingType>(key: &Key<T>) -> Option<T> {
    let env_str = var(key.name).ok()?;
    T::try_parse(&env_str).or_else(|| {
        warn!("Environment variable '{}' set to '{}' cannot be parsed, using default", key.name, env_str);
        None
    })
}

/// Configuration settings with type-safe access.
///
/// Values are resolved in this order:
/// 1. Explicit overrides set via SettingsBuilder
/// 2. Environment variables (if not disabled)
/// 3. Default value from the Key definition
pub struct Settings<AE: AsyncExecutor> {
    overrides: OverrideMap,
    executor: AE,
    pool: BytePool,
}

impl<AE: AsyncExecutor> Settings<AE> {
    /// Create a new Settings instance from its components.
    pub(super) fn new(overrides: OverrideMap, executor: AE, pool: BytePool) -> Self {
        Self {
            overrides,
            executor,
            pool,
        }
    }

    /// Get a setting value with compile-time type safety.
    ///
    /// Resolution order: override -> environment -> default
    #[inline]
    pub fn get<T: SettingType + Copy>(&self, key: &Key<T>) -> T {
        if let Some(value) = self.overrides.get(key.name) {
            return T::from_value(*value);
        }

        if let Some(value) = try_env_override(key) {
            return value;
        }

        key.default
    }

    /// Set a setting value with compile-time type safety.
    #[inline]
    pub fn set<T: SettingType>(&mut self, key: &Key<T>, value: T) {
        self.overrides.insert(key.name, value.to_value());
    }

    /// Get a reference to the byte pool.
    #[inline]
    pub fn pool(&self) -> &BytePool {
        &self.pool
    }

    /// Get a reference to the async executor.
    #[inline]
    pub fn executor(&self) -> &AE {
        &self.executor
    }
}

impl<AE: AsyncExecutor> Default for Settings<AE> {
    #[inline]
    fn default() -> Self {
        SettingsBuilder::new().build()
    }
}
