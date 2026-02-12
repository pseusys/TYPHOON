//! Builder pattern for constructing Settings instances.

use crate::bytes::BytePool;
use crate::utils::sync::AsyncExecutor;

use super::override_map::{Key, OverrideMap, SettingType};
use super::settings::Settings;
use super::statics::consts;

/// Builder for creating Settings instances with custom overrides.
#[derive(Default)]
pub struct SettingsBuilder<AE: AsyncExecutor> {
    overrides: OverrideMap,
    executor: Option<AE>,
    pool: Option<BytePool>,
    skip_env: bool,
}

impl<AE: AsyncExecutor> SettingsBuilder<AE> {
    /// Create a new builder that will read environment variables.
    pub fn new() -> Self {
        Self {
            overrides: OverrideMap::default(),
            executor: None,
            pool: None,
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

    /// Set a typed value for a key.
    #[inline]
    pub fn set<T: SettingType>(mut self, key: &Key<T>, value: T) -> Self {
        self.overrides.insert(key.name, value.to_value());
        self
    }

    /// Build the Settings instance.
    pub fn build(self) -> Settings<AE> {
        Settings::new(
            self.overrides,
            self.executor.unwrap_or_else(AE::new),
            self.pool.unwrap_or_else(|| {
                let capacity = consts::DEFAULT_TYPHOON_MTU_LENGTH / 2;
                BytePool::new(capacity, consts::DEFAULT_TYPHOON_MTU_LENGTH, capacity, consts::DEFAULT_POOL_INITIAL_SIZE, consts::DEFAULT_POOL_CAPACITY)
            }),
        )
    }
}
