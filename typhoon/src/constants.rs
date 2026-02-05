use std::collections::HashMap;
use std::env::var;
use std::ops::Add;

use log::warn;

/// A typed setting key that carries its value type at compile time.
/// This ensures type-safe access to settings - you can only get/set
/// values of the correct type for each key.
///
/// Custom keys can be defined anywhere, not just in this module:
/// ```
/// const MY_CUSTOM_KEY: Key<u64> = Key::new("MY_APP_CUSTOM_SETTING", 42);
/// ```
pub struct Key<T> {
    pub name: &'static str,
    pub default: T,
}

impl<T> Key<T> {
    pub const fn new(name: &'static str, default: T) -> Self {
        Self { name, default }
    }
}

/// Trait for types that can be stored in Settings.
/// Provides conversion to/from the internal SettingValue representation.
pub trait SettingType: Copy {
    fn from_value(v: SettingValue) -> Self;
    fn to_value(self) -> SettingValue;
    fn try_parse(s: &str) -> Option<Self>;
}

impl SettingType for i64 {
    #[inline]
    fn from_value(v: SettingValue) -> Self {
        match v {
            SettingValue::Signed(x) => x,
            _ => unreachable!("expected signed setting"),
        }
    }

    #[inline]
    fn to_value(self) -> SettingValue {
        SettingValue::Signed(self)
    }

    #[inline]
    fn try_parse(s: &str) -> Option<Self> {
        s.parse().ok()
    }
}

impl SettingType for u64 {
    #[inline]
    fn from_value(v: SettingValue) -> Self {
        match v {
            SettingValue::Unsigned(x) => x,
            _ => unreachable!("expected unsigned setting"),
        }
    }

    #[inline]
    fn to_value(self) -> SettingValue {
        SettingValue::Unsigned(self)
    }

    #[inline]
    fn try_parse(s: &str) -> Option<Self> {
        s.parse().ok()
    }
}

impl SettingType for f64 {
    #[inline]
    fn from_value(v: SettingValue) -> Self {
        match v {
            SettingValue::Float(x) => x,
            _ => unreachable!("expected float setting"),
        }
    }

    #[inline]
    fn to_value(self) -> SettingValue {
        SettingValue::Float(self)
    }

    #[inline]
    fn try_parse(s: &str) -> Option<Self> {
        s.parse().ok()
    }
}

pub mod keys {
    use super::Key;

    // RTT settings
    pub const RTT_ALPHA: Key<f64> = Key::new("TYPHOON_RTT_ALPHA", 0.125);
    pub const RTT_BETA: Key<f64> = Key::new("TYPHOON_RTT_BETA", 0.25);
    pub const RTT_DEFAULT: Key<u64> = Key::new("TYPHOON_RTT_DEFAULT", 5000);
    pub const RTT_MIN: Key<u64> = Key::new("TYPHOON_RTT_MIN", 1000);
    pub const RTT_MAX: Key<u64> = Key::new("TYPHOON_RTT_MAX", 8000);

    // Timeout settings
    pub const TIMEOUT_DEFAULT: Key<u64> = Key::new("TYPHOON_TIMEOUT_DEFAULT", 30000);
    pub const TIMEOUT_MIN: Key<u64> = Key::new("TYPHOON_TIMEOUT_MIN", 4000);
    pub const TIMEOUT_MAX: Key<u64> = Key::new("TYPHOON_TIMEOUT_MAX", 32000);
    pub const TIMEOUT_RTT_FACTOR: Key<f64> = Key::new("TYPHOON_TIMEOUT_RTT_FACTOR", 5.0);

    // Health check settings
    pub const HEALTH_CHECK_NEXT_IN_MIN: Key<u64> = Key::new("TYPHOON_HEALTH_CHECK_NEXT_IN_MIN", 64000);
    pub const HEALTH_CHECK_NEXT_IN_MAX: Key<u64> = Key::new("TYPHOON_HEALTH_CHECK_NEXT_IN_MAX", 256000);
    pub const HANDSHAKE_NEXT_IN_FACTOR: Key<f64> = Key::new("TYPHOON_HANDSHAKE_NEXT_IN_FACTOR", 0.02);
    pub const MAX_RETRIES: Key<u64> = Key::new("TYPHOON_MAX_RETRIES", 12);

    // Fake body/header settings
    pub const FAKE_BODY_LENGTH_MIN: Key<u64> = Key::new("TYPHOON_FAKE_BODY_LENGTH_MIN", 0);
    pub const FAKE_BODY_LENGTH_MAX: Key<u64> = Key::new("TYPHOON_FAKE_BODY_LENGTH_MAX", 256);
    pub const FAKE_BODY_SERVICE_PROBABILITY: Key<f64> = Key::new("TYPHOON_FAKE_BODY_SERVICE_PROBABILITY", 5.0);
    pub const FAKE_HEADER_LENGTH_MIN: Key<u64> = Key::new("TYPHOON_FAKE_HEADER_LENGTH_MIN", 4);
    pub const FAKE_HEADER_LENGTH_MAX: Key<u64> = Key::new("TYPHOON_FAKE_HEADER_LENGTH_MAX", 32);
    pub const FAKE_HEADER_PROBABILITY: Key<f64> = Key::new("TYPHOON_FAKE_HEADER_PROBABILITY", 0.35);

    // Decoy general settings
    pub const DECOY_REFERENCE_PACKET_RATE_DEFAULT: Key<f64> = Key::new("TYPHOON_DECOY_REFERENCE_PACKET_RATE_DEFAULT", 200.0);
    pub const DECOY_CURRENT_PACKET_RATE_DEFAULT: Key<f64> = Key::new("TYPHOON_DECOY_CURRENT_PACKET_RATE_DEFAULT", 200.0);
    pub const DECOY_CURRENT_BYTE_RATE_DEFAULT: Key<f64> = Key::new("TYPHOON_DECOY_CURRENT_BYTE_RATE_DEFAULT", 5000.0);
    pub const DECOY_BYTE_RATE_CAP: Key<f64> = Key::new("TYPHOON_DECOY_BYTE_RATE_CAP", 1000000.0);
    pub const DECOY_BYTE_RATE_FACTOR: Key<f64> = Key::new("TYPHOON_DECOY_BYTE_RATE_FACTOR", 3.0);
    pub const DECOY_CURRENT_ALPHA: Key<f64> = Key::new("TYPHOON_DECOY_CURRENT_ALPHA", 0.05);
    pub const DECOY_REFERENCE_ALPHA: Key<f64> = Key::new("TYPHOON_DECOY_REFERENCE_ALPHA", 0.001);
    pub const DECOY_LENGTH_MAX: Key<u64> = Key::new("TYPHOON_DECOY_LENGTH_MAX", 1024);
    pub const DECOY_LENGTH_MIN: Key<u64> = Key::new("TYPHOON_DECOY_LENGTH_MIN", 16);
    pub const DECOY_REFERENCE_BURST_FACTOR: Key<f64> = Key::new("TYPHOON_DECOY_REFERENCE_BURST_FACTOR", 3.0);
    pub const DECOY_BASE_RATE_RND: Key<f64> = Key::new("TYPHOON_DECOY_BASE_RATE_RND", 0.25);

    // Decoy heavy settings
    pub const DECOY_HEAVY_BASE_RATE: Key<f64> = Key::new("TYPHOON_DECOY_HEAVY_BASE_RATE", 0.05);
    pub const DECOY_HEAVY_QUIETNESS_FACTOR: Key<f64> = Key::new("TYPHOON_DECOY_HEAVY_QUIETNESS_FACTOR", 3.0);
    pub const DECOY_HEAVY_DELAY_MIN: Key<u64> = Key::new("TYPHOON_DECOY_HEAVY_DELAY_MIN", 5000);
    pub const DECOY_HEAVY_DELAY_MAX: Key<u64> = Key::new("TYPHOON_DECOY_HEAVY_DELAY_MAX", 120000);
    pub const DECOY_HEAVY_DELAY_DEFAULT: Key<u64> = Key::new("TYPHOON_DECOY_HEAVY_DELAY_DEFAULT", 64000);
    pub const DECOY_HEAVY_BASE_LENGTH: Key<f64> = Key::new("TYPHOON_DECOY_HEAVY_BASE_LENGTH", 0.7);
    pub const DECOY_HEAVY_QUIETNESS_LENGTH: Key<f64> = Key::new("TYPHOON_DECOY_HEAVY_QUIETNESS_LENGTH", 0.3);
    pub const DECOY_HEAVY_DECOY_LENGTH_FACTOR: Key<f64> = Key::new("TYPHOON_DECOY_HEAVY_DECOY_LENGTH_FACTOR", 0.8);

    // Decoy noisy settings
    pub const DECOY_NOISY_BASE_RATE: Key<f64> = Key::new("TYPHOON_DECOY_NOISY_BASE_RATE", 3.0);
    pub const DECOY_NOISY_DELAY_MIN: Key<u64> = Key::new("TYPHOON_DECOY_NOISY_DELAY_MIN", 10);
    pub const DECOY_NOISY_DELAY_MAX: Key<u64> = Key::new("TYPHOON_DECOY_NOISY_DELAY_MAX", 1000);
    pub const DECOY_NOISY_DELAY_DEFAULT: Key<u64> = Key::new("TYPHOON_DECOY_NOISY_DELAY_DEFAULT", 500);
    pub const DECOY_NOISY_DECOY_LENGTH_MIN: Key<u64> = Key::new("TYPHOON_DECOY_NOISY_DECOY_LENGTH_MIN", 128);
    pub const DECOY_NOISY_DECOY_LENGTH_JITTER: Key<f64> = Key::new("TYPHOON_DECOY_NOISY_DECOY_LENGTH_JITTER", 0.3);

    // Decoy sparse settings
    pub const DECOY_SPARSE_BASE_RATE: Key<f64> = Key::new("TYPHOON_DECOY_SPARSE_BASE_RATE", 20.0);
    pub const DECOY_SPARSE_RATE_FACTOR: Key<f64> = Key::new("TYPHOON_DECOY_SPARSE_RATE_FACTOR", 3.0);
    pub const DECOY_SPARSE_JITTER: Key<f64> = Key::new("TYPHOON_DECOY_SPARSE_JITTER", 0.15);
    pub const DECOY_SPARSE_DELAY_FACTOR: Key<f64> = Key::new("TYPHOON_DECOY_SPARSE_DELAY_FACTOR", 3.0);
    pub const DECOY_SPARSE_DELAY_MIN: Key<u64> = Key::new("TYPHOON_DECOY_SPARSE_DELAY_MIN", 20);
    pub const DECOY_SPARSE_DELAY_MAX: Key<u64> = Key::new("TYPHOON_DECOY_SPARSE_DELAY_MAX", 150);
    pub const DECOY_SPARSE_DELAY_DEFAULT: Key<u64> = Key::new("TYPHOON_DECOY_SPARSE_DELAY_DEFAULT", 100);
    pub const DECOY_SPARSE_LENGTH_FACTOR: Key<f64> = Key::new("TYPHOON_DECOY_SPARSE_LENGTH_FACTOR", 120.0);
    pub const DECOY_SPARSE_LENGTH_SIGMA: Key<f64> = Key::new("TYPHOON_DECOY_SPARSE_LENGTH_SIGMA", 20.0);
    pub const DECOY_SPARSE_LENGTH_MIN: Key<u64> = Key::new("TYPHOON_DECOY_SPARSE_LENGTH_MIN", 75);
    pub const DECOY_SPARSE_LENGTH_MAX: Key<u64> = Key::new("TYPHOON_DECOY_SPARSE_LENGTH_MAX", 250);

    // Decoy smooth settings
    pub const DECOY_SMOOTH_BASE_RATE: Key<f64> = Key::new("TYPHOON_DECOY_SMOOTH_BASE_RATE", 0.3);
    pub const DECOY_SMOOTH_QUIETNESS_FACTOR: Key<f64> = Key::new("TYPHOON_DECOY_SMOOTH_QUIETNESS_FACTOR", 2.0);
    pub const DECOY_SMOOTH_RATE_FACTOR: Key<f64> = Key::new("TYPHOON_DECOY_SMOOTH_RATE_FACTOR", 3.0);
    pub const DECOY_SMOOTH_JITTER: Key<f64> = Key::new("TYPHOON_DECOY_SMOOTH_JITTER", 0.2);
    pub const DECOY_SMOOTH_DELAY_FACTOR: Key<f64> = Key::new("TYPHOON_DECOY_SMOOTH_DELAY_FACTOR", 2.0);
    pub const DECOY_SMOOTH_DELAY_MIN: Key<u64> = Key::new("TYPHOON_DECOY_SMOOTH_DELAY_MIN", 300);
    pub const DECOY_SMOOTH_DELAY_MAX: Key<u64> = Key::new("TYPHOON_DECOY_SMOOTH_DELAY_MAX", 10000);
    pub const DECOY_SMOOTH_DELAY_DEFAULT: Key<u64> = Key::new("TYPHOON_DECOY_SMOOTH_DELAY_DEFAULT", 5000);
    pub const DECOY_SMOOTH_LENGTH_MIN: Key<u64> = Key::new("TYPHOON_DECOY_SMOOTH_LENGTH_MIN", 48);
    pub const DECOY_SMOOTH_LENGTH_MAX: Key<u64> = Key::new("TYPHOON_DECOY_SMOOTH_LENGTH_MAX", 512);

    // Decoy maintenance settings
    pub const DECOY_MAINTENANCE_LENGTH_MIN: Key<u64> = Key::new("TYPHOON_DECOY_MAINTENANCE_LENGTH_MIN", 8);
    pub const DECOY_MAINTENANCE_LENGTH_MAX: Key<u64> = Key::new("TYPHOON_DECOY_MAINTENANCE_LENGTH_MAX", 256);
    pub const DECOY_MAINTENANCE_DELAY_MIN: Key<u64> = Key::new("TYPHOON_DECOY_MAINTENANCE_DELAY_MIN", 3000);
    pub const DECOY_MAINTENANCE_DELAY_MAX: Key<u64> = Key::new("TYPHOON_DECOY_MAINTENANCE_DELAY_MAX", 720000);
    pub const DECOY_MAINTENANCE_MODE_NONE_PROBABILITY: Key<f64> = Key::new("TYPHOON_DECOY_MAINTENANCE_MODE_NONE_PROBABILITY", 3.0);

    // Decoy replication settings
    pub const DECOY_REPLICATION_PROBABILITY_MIN: Key<f64> = Key::new("TYPHOON_DECOY_REPLICATION_PROBABILITY_MIN", 0.01);
    pub const DECOY_REPLICATION_PROBABILITY_MAX: Key<f64> = Key::new("TYPHOON_DECOY_REPLICATION_PROBABILITY_MAX", 0.1);
    pub const DECOY_REPLICATION_PROBABILITY_REDUCE: Key<f64> = Key::new("TYPHOON_DECOY_REPLICATION_PROBABILITY_REDUCE", 3.0);
    pub const DECOY_REPLICATION_DELAY_MIN: Key<u64> = Key::new("TYPHOON_DECOY_REPLICATION_DELAY_MIN", 2500);
    pub const DECOY_REPLICATION_DELAY_MAX: Key<u64> = Key::new("TYPHOON_DECOY_REPLICATION_DELAY_MAX", 10000);
    pub const DECOY_REPLICATION_MODE_NONE_PROBABILITY: Key<f64> = Key::new("TYPHOON_DECOY_REPLICATION_MODE_NONE_PROBABILITY", 3.0);

    // Decoy subheader settings
    pub const DECOY_SUBHEADER_LENGTH_MIN: Key<u64> = Key::new("TYPHOON_DECOY_SUBHEADER_LENGTH_MIN", 4);
    pub const DECOY_SUBHEADER_LENGTH_MAX: Key<u64> = Key::new("TYPHOON_DECOY_SUBHEADER_LENGTH_MAX", 16);
}

pub mod consts {
    pub const DEFAULT_TYPHOON_MTU_LENGTH: usize = 1500;
    pub const DEFAULT_TYPHOON_ID_LENGTH: usize = 16;
    pub const TAILOR_LENGTH: usize = 16;
    pub const FG_OFFSET: usize = 0;
    pub const CD_OFFSET: usize = 1;
    pub const TM_OFFSET: usize = 2;
    pub const PN_OFFSET: usize = 6;
    pub const PL_OFFSET: usize = 14;
    pub const ID_OFFSET: usize = 16;
}

#[derive(Copy, Clone, Debug)]
pub enum SettingValue {
    Signed(i64),
    Unsigned(u64),
    Float(f64),
}

impl Add for SettingValue {
    type Output = Self;

    #[inline]
    fn add(self, rhs: Self) -> Self::Output {
        match (self, rhs) {
            (SettingValue::Signed(a), SettingValue::Signed(b)) => SettingValue::Signed(a + b),
            (SettingValue::Unsigned(a), SettingValue::Unsigned(b)) => SettingValue::Unsigned(a + b),
            (SettingValue::Float(a), SettingValue::Float(b)) => SettingValue::Float(a + b),
            (SettingValue::Signed(a), SettingValue::Unsigned(b)) => SettingValue::Float(a as f64 + b as f64),
            (SettingValue::Unsigned(a), SettingValue::Signed(b)) => SettingValue::Float(a as f64 + b as f64),
            (SettingValue::Signed(a), SettingValue::Float(b)) | (SettingValue::Float(b), SettingValue::Signed(a)) => SettingValue::Float(a as f64 + b),
            (SettingValue::Unsigned(a), SettingValue::Float(b)) | (SettingValue::Float(b), SettingValue::Unsigned(a)) => SettingValue::Float(a as f64 + b),
        }
    }
}

type OverrideMap = HashMap<&'static str, SettingValue>;

/// Try to read an environment variable and parse it as type T.
/// Returns None if the variable is not set or cannot be parsed.
fn try_env_override<T: SettingType>(key: &Key<T>) -> Option<T> {
    let env_str = var(key.name).ok()?;
    T::try_parse(&env_str).or_else(|| {
        warn!(
            "Environment variable '{}' set to '{}' cannot be parsed, using default",
            key.name, env_str
        );
        None
    })
}

/// Builder for creating Settings instances with custom overrides.
#[derive(Default)]
pub struct SettingsBuilder {
    overrides: OverrideMap,
    skip_env: bool,
}

impl SettingsBuilder {
    /// Create a new builder that will read environment variables.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a builder that ignores environment variables.
    pub fn without_env() -> Self {
        Self {
            overrides: OverrideMap::new(),
            skip_env: true,
        }
    }

    /// Set a typed value for a key.
    #[inline]
    pub fn set<T: SettingType>(mut self, key: &Key<T>, value: T) -> Self {
        self.overrides.insert(key.name, value.to_value());
        self
    }

    /// Build the Settings instance.
    pub fn build(self) -> Settings {
        Settings {
            overrides: self.overrides,
        }
    }
}

/// Configuration settings with type-safe access.
///
/// Values are resolved in this order:
/// 1. Explicit overrides set via SettingsBuilder
/// 2. Environment variables (if not disabled)
/// 3. Default value from the Key definition
pub struct Settings {
    overrides: OverrideMap,
}

impl Settings {
    /// Get a setting value with compile-time type safety.
    ///
    /// Resolution order: override -> environment -> default
    #[inline]
    pub fn get<T: SettingType + Copy>(&self, key: &Key<T>) -> T {
        // Check overrides first
        if let Some(value) = self.overrides.get(key.name) {
            return T::from_value(*value);
        }

        // Check environment variable
        if let Some(value) = try_env_override(key) {
            return value;
        }

        // Return default
        key.default
    }

    /// Set a setting value with compile-time type safety.
    #[inline]
    pub fn set<T: SettingType>(&mut self, key: &Key<T>, value: T) {
        self.overrides.insert(key.name, value.to_value());
    }
}

impl Default for Settings {
    #[inline]
    fn default() -> Self {
        SettingsBuilder::new().build()
    }
}
