use crate::bytes::{ByteBuffer, BytePool};
use crate::defaults::DefaultExecutor;
use crate::settings::{Settings, SettingsBuilder, keys};
use crate::settings::consts::DEFAULT_TYPHOON_MTU_LENGTH;

fn default_settings() -> Settings<DefaultExecutor> {
    SettingsBuilder::new().build().unwrap()
}

// Test: build() with no overrides produces a valid Settings with default MTU.
#[test]
fn test_build_defaults() {
    let s = default_settings();
    assert_eq!(s.mtu(), DEFAULT_TYPHOON_MTU_LENGTH);
}

// Test: with_mtu() overrides the MTU value stored in Settings.
#[test]
fn test_with_mtu() {
    let mtu = 512usize;
    let s = SettingsBuilder::<DefaultExecutor>::new()
        .with_mtu(mtu)
        .build()
        .unwrap();
    assert_eq!(s.mtu(), mtu);
}

// Test: with_pool() stores a custom pool and settings.pool() can allocate from it.
#[test]
fn test_with_pool_is_used() {
    let pool = BytePool::new(16, 256, 16, 4, 32);
    let s = SettingsBuilder::<DefaultExecutor>::new()
        .with_pool(pool)
        .build()
        .unwrap();
    // The pool is accessible and functional.
    let buf = s.pool().allocate(Some(8));
    assert_eq!(buf.len(), 8);
}

// Test: set() followed by get() returns the overridden value.
#[test]
fn test_set_override_reflected_in_get() {
    let s = SettingsBuilder::<DefaultExecutor>::new()
        .set(&keys::MAX_RETRIES, 7u64)
        .build()
        .unwrap();
    assert_eq!(s.get(&keys::MAX_RETRIES), 7u64);
}

// Test: build() returns Err when invariants are violated (TIMEOUT_MIN > TIMEOUT_MAX).
#[test]
fn test_build_fails_on_invalid_settings() {
    let result = SettingsBuilder::<DefaultExecutor>::new()
        .set(&keys::TIMEOUT_MIN, 100u64)
        .set(&keys::TIMEOUT_MAX, 10u64)
        .build();
    assert!(result.is_err(), "build should fail when TIMEOUT_MIN > TIMEOUT_MAX");
}
