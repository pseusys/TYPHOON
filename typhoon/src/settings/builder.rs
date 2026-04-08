//! Builder pattern for constructing Settings instances.

#[cfg(test)]
#[path = "../../tests/settings/builder.rs"]
mod tests;

use super::error::SettingsError;
use super::override_map::{Key, OverrideMap, SettingType};
use super::settings::Settings;
use super::statics::consts;
use crate::bytes::BytePool;
use crate::utils::sync::AsyncExecutor;

/// Builder for creating Settings instances with custom overrides.
#[derive(Default)]
pub struct SettingsBuilder<AE: AsyncExecutor> {
    overrides: OverrideMap,
    executor: Option<AE>,
    pool: Option<BytePool>,
    mtu: usize,
    skip_env: bool,
}

impl<AE: AsyncExecutor> SettingsBuilder<AE> {
    /// Create a new builder that will read environment variables.
    pub fn new() -> Self {
        Self {
            overrides: OverrideMap::default(),
            executor: None,
            pool: None,
            mtu: consts::DEFAULT_TYPHOON_MTU_LENGTH,
            skip_env: false,
        }
    }

    /// Create a builder that ignores environment variables.
    pub fn without_env(mut self) -> Self {
        self.skip_env = false;
        self
    }

    /// Set the async executor to use.
    pub fn with_executor(mut self, executor: AE) -> Self {
        self.executor = Some(executor);
        self
    }

    /// Set the byte pool to use.
    pub fn with_pool(mut self, pool: BytePool) -> Self {
        self.pool = Some(pool);
        self
    }

    /// Set MTU (max packet size) for all flow managers.
    pub fn with_mtu(mut self, mtu: usize) -> Self {
        self.mtu = mtu;
        self
    }

    /// Set a typed value for a key.
    #[inline]
    pub fn set<T: SettingType>(mut self, key: &Key<T>, value: T) -> Self {
        self.overrides.insert(key.name, value.to_value());
        self
    }

    /// Build the Settings instance, validating all invariants.
    pub fn build(self) -> Result<Settings<AE>, SettingsError> {
        let settings = Settings::new(
            self.overrides,
            self.executor.unwrap_or_else(AE::new),
            self.pool.unwrap_or_else(|| {
                let capacity = self.mtu / 2;
                BytePool::new(capacity, self.mtu, capacity, consts::DEFAULT_POOL_INITIAL_SIZE, consts::DEFAULT_POOL_CAPACITY)
            }),
            self.mtu,
        );
        settings.assert()?;
        Ok(settings)
    }
}
