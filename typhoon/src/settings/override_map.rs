//! Override map types for type-safe settings storage.

#[cfg(test)]
#[path = "../../tests/settings/override_map.rs"]
mod tests;

use std::collections::HashMap;
use std::ops::Add;

/// A typed setting key that carries its value type at compile time.
/// This ensures type-safe access to settings - you can only get/set
/// values of the correct type for each key.
pub struct Key<T> {
    pub name: &'static str,
    pub default: T,
}

impl<T> Key<T> {
    pub const fn new(name: &'static str, default: T) -> Self {
        Self {
            name,
            default,
        }
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

/// Internal representation of a setting value.
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

/// Map of setting name to override value.
pub type OverrideMap = HashMap<&'static str, SettingValue>;
