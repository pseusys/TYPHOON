//! Core Settings struct for type-safe configuration access.

#[cfg(test)]
#[path = "../../tests/settings/assertions.rs"]
mod tests;

use std::env::var;

use log::warn;

use super::builder::SettingsBuilder;
use super::error::SettingsError;
use super::override_map::{Key, OverrideMap, SettingType};
use super::statics::keys;
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
    mtu: usize,
}

impl<AE: AsyncExecutor> Settings<AE> {
    /// Create a new Settings instance from its components.
    pub(super) fn new(overrides: OverrideMap, executor: AE, pool: BytePool, mtu: usize) -> Self {
        Self {
            overrides,
            executor,
            pool,
            mtu,
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

    /// Get the MTU (max packet size) for flow managers.
    #[inline]
    pub fn mtu(&self) -> usize {
        self.mtu
    }

    /// Get a reference to the async executor.
    #[inline]
    pub fn executor(&self) -> &AE {
        &self.executor
    }

    /// Validate that all settings satisfy protocol invariants.
    pub(super) fn assert(&self) -> Result<(), SettingsError> {
        // Helper to check min <= max for u64 key pairs.
        let assert_min_max_u64 = |min_key: &Key<u64>, max_key: &Key<u64>| -> Result<(), SettingsError> {
            let min_val = self.get(min_key);
            let max_val = self.get(max_key);
            if min_val > max_val {
                return Err(SettingsError::AssertionFailed {
                    message: format!("{} ({}) must be <= {} ({})", min_key.name, min_val, max_key.name, max_val),
                });
            }
            Ok(())
        };

        // Helper to check min <= max for f64 key pairs.
        let assert_min_max_f64 = |min_key: &Key<f64>, max_key: &Key<f64>| -> Result<(), SettingsError> {
            let min_val = self.get(min_key);
            let max_val = self.get(max_key);
            if min_val > max_val {
                return Err(SettingsError::AssertionFailed {
                    message: format!("{} ({}) must be <= {} ({})", min_key.name, min_val, max_key.name, max_val),
                });
            }
            Ok(())
        };

        // Helper to check a u64 default is within [min, max].
        let assert_default_in_range = |min_key: &Key<u64>, default_key: &Key<u64>, max_key: &Key<u64>| -> Result<(), SettingsError> {
            let min_val = self.get(min_key);
            let default_val = self.get(default_key);
            let max_val = self.get(max_key);
            if default_val < min_val || default_val > max_val {
                return Err(SettingsError::AssertionFailed {
                    message: format!(
                        "{} ({}) must be within [{} ({}), {} ({})]",
                        default_key.name, default_val, min_key.name, min_val, max_key.name, max_val
                    ),
                });
            }
            Ok(())
        };

        // Helper to check f64 is in exclusive range (0, 1).
        let assert_unit_exclusive = |key: &Key<f64>| -> Result<(), SettingsError> {
            let val = self.get(key);
            if val <= 0.0 || val >= 1.0 {
                return Err(SettingsError::AssertionFailed {
                    message: format!("{} ({}) must be in (0, 1)", key.name, val),
                });
            }
            Ok(())
        };

        // Helper to check f64 is in inclusive range [0, 1].
        let assert_unit_inclusive = |key: &Key<f64>| -> Result<(), SettingsError> {
            let val = self.get(key);
            if val < 0.0 || val > 1.0 {
                return Err(SettingsError::AssertionFailed {
                    message: format!("{} ({}) must be in [0, 1]", key.name, val),
                });
            }
            Ok(())
        };

        // Helper to check f64 is positive.
        let assert_positive = |key: &Key<f64>| -> Result<(), SettingsError> {
            let val = self.get(key);
            if val <= 0.0 {
                return Err(SettingsError::AssertionFailed {
                    message: format!("{} ({}) must be positive", key.name, val),
                });
            }
            Ok(())
        };

        // Min <= Max pairs
        assert_min_max_u64(&keys::FAKE_BODY_LENGTH_MIN, &keys::FAKE_BODY_LENGTH_MAX)?;
        assert_min_max_u64(&keys::FAKE_HEADER_LENGTH_MIN, &keys::FAKE_HEADER_LENGTH_MAX)?;
        assert_min_max_u64(&keys::HEALTH_CHECK_NEXT_IN_MIN, &keys::HEALTH_CHECK_NEXT_IN_MAX)?;
        assert_min_max_u64(&keys::TIMEOUT_MIN, &keys::TIMEOUT_MAX)?;
        assert_min_max_u64(&keys::RTT_MIN, &keys::RTT_MAX)?;
        assert_min_max_u64(&keys::DECOY_LENGTH_MIN, &keys::DECOY_LENGTH_MAX)?;
        assert_min_max_u64(&keys::DECOY_HEAVY_DELAY_MIN, &keys::DECOY_HEAVY_DELAY_MAX)?;
        assert_min_max_u64(&keys::DECOY_NOISY_DELAY_MIN, &keys::DECOY_NOISY_DELAY_MAX)?;
        assert_min_max_u64(&keys::DECOY_SPARSE_DELAY_MIN, &keys::DECOY_SPARSE_DELAY_MAX)?;
        assert_min_max_u64(&keys::DECOY_SPARSE_LENGTH_MIN, &keys::DECOY_SPARSE_LENGTH_MAX)?;
        assert_min_max_u64(&keys::DECOY_SMOOTH_DELAY_MIN, &keys::DECOY_SMOOTH_DELAY_MAX)?;
        assert_min_max_u64(&keys::DECOY_SMOOTH_LENGTH_MIN, &keys::DECOY_SMOOTH_LENGTH_MAX)?;
        assert_min_max_u64(&keys::DECOY_MAINTENANCE_LENGTH_MIN, &keys::DECOY_MAINTENANCE_LENGTH_MAX)?;
        assert_min_max_u64(&keys::DECOY_MAINTENANCE_DELAY_MIN, &keys::DECOY_MAINTENANCE_DELAY_MAX)?;
        assert_min_max_u64(&keys::DECOY_REPLICATION_DELAY_MIN, &keys::DECOY_REPLICATION_DELAY_MAX)?;
        assert_min_max_u64(&keys::DECOY_SUBHEADER_LENGTH_MIN, &keys::DECOY_SUBHEADER_LENGTH_MAX)?;
        assert_min_max_f64(&keys::DECOY_REPLICATION_PROBABILITY_MIN, &keys::DECOY_REPLICATION_PROBABILITY_MAX)?;

        // Defaults within bounds
        assert_default_in_range(&keys::RTT_MIN, &keys::RTT_DEFAULT, &keys::RTT_MAX)?;
        assert_default_in_range(&keys::TIMEOUT_MIN, &keys::TIMEOUT_DEFAULT, &keys::TIMEOUT_MAX)?;
        assert_default_in_range(&keys::DECOY_HEAVY_DELAY_MIN, &keys::DECOY_HEAVY_DELAY_DEFAULT, &keys::DECOY_HEAVY_DELAY_MAX)?;
        assert_default_in_range(&keys::DECOY_NOISY_DELAY_MIN, &keys::DECOY_NOISY_DELAY_DEFAULT, &keys::DECOY_NOISY_DELAY_MAX)?;
        assert_default_in_range(&keys::DECOY_SPARSE_DELAY_MIN, &keys::DECOY_SPARSE_DELAY_DEFAULT, &keys::DECOY_SPARSE_DELAY_MAX)?;
        assert_default_in_range(&keys::DECOY_SMOOTH_DELAY_MIN, &keys::DECOY_SMOOTH_DELAY_DEFAULT, &keys::DECOY_SMOOTH_DELAY_MAX)?;

        // Next-in must be greater than timeout (README: "next in should be always greater than timeout")
        let next_in_min = self.get(&keys::HEALTH_CHECK_NEXT_IN_MIN);
        let timeout_max = self.get(&keys::TIMEOUT_MAX);
        if next_in_min <= timeout_max {
            return Err(SettingsError::AssertionFailed {
                message: format!(
                    "{} ({}) must be > {} ({})",
                    keys::HEALTH_CHECK_NEXT_IN_MIN.name, next_in_min, keys::TIMEOUT_MAX.name, timeout_max
                ),
            });
        }

        // EWMA alpha/beta values must be in (0, 1)
        assert_unit_exclusive(&keys::RTT_ALPHA)?;
        assert_unit_exclusive(&keys::RTT_BETA)?;
        assert_unit_exclusive(&keys::DECOY_CURRENT_ALPHA)?;
        assert_unit_exclusive(&keys::DECOY_REFERENCE_ALPHA)?;

        // Probability must be in [0, 1]
        assert_unit_inclusive(&keys::FAKE_HEADER_PROBABILITY)?;

        // Positive multipliers
        assert_positive(&keys::FAKE_BODY_SERVICE_PROBABILITY)?;
        assert_positive(&keys::DECOY_MAINTENANCE_MODE_NONE_PROBABILITY)?;
        assert_positive(&keys::DECOY_REPLICATION_MODE_NONE_PROBABILITY)?;
        assert_positive(&keys::TIMEOUT_RTT_FACTOR)?;
        assert_positive(&keys::HANDSHAKE_NEXT_IN_FACTOR)?;
        assert_positive(&keys::DECOY_BYTE_RATE_CAP)?;
        assert_positive(&keys::DECOY_BYTE_RATE_FACTOR)?;
        assert_positive(&keys::DECOY_REFERENCE_BURST_FACTOR)?;

        Ok(())
    }
}

impl<AE: AsyncExecutor> Default for Settings<AE> {
    #[inline]
    fn default() -> Self {
        SettingsBuilder::new().build().expect("default settings must be valid")
    }
}
