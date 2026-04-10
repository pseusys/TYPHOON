use crate::cache::{CacheError, SharedValue};

// ── SharedValue ───────────────────────────────────────────────────────────────

#[test]
fn test_shared_value_new_get() {
    let mut sv = SharedValue::new(42u32);
    assert_eq!(*sv.get(), 42);
}

#[test]
fn test_shared_value_get_mut_mutates_local() {
    let mut sv = SharedValue::new(10u32);
    *sv.get_mut() += 5;
    assert_eq!(*sv.get(), 15);
}

#[test]
fn test_shared_value_set_visible_to_same_instance() {
    let mut sv = SharedValue::new(1u32);
    sv.set(99u32);
    assert_eq!(*sv.get(), 99);
}

#[test]
fn test_shared_value_sibling_sees_set() {
    let mut sv = SharedValue::new(1u32);
    let mut sibling = sv.create_sibling();
    sv.set(77u32);
    // sibling must re-fetch on next get because the pointer changed.
    assert_eq!(*sibling.get(), 77);
}

#[test]
fn test_shared_value_create_sibling_initially_same() {
    let sv = SharedValue::new(55u32);
    let mut sibling = sv.create_sibling();
    assert_eq!(*sibling.get(), 55);
}

#[test]
fn test_shared_value_create_cache_initially_same() {
    let sv = SharedValue::new(33u32);
    let mut cache = sv.create_cache();
    assert_eq!(*cache.get().unwrap(), 33);
}

// ── CachedValue ───────────────────────────────────────────────────────────────

#[test]
fn test_cached_value_refetches_after_set() {
    let mut sv = SharedValue::new(10u32);
    let mut cache = sv.create_cache();
    sv.set(20u32);
    assert_eq!(*cache.get().unwrap(), 20);
}

#[test]
fn test_cached_value_source_dropped_returns_error() {
    let sv = SharedValue::new(1u32);
    let mut cache = sv.create_cache();
    drop(sv);
    assert!(matches!(cache.get(), Err(CacheError::SourceDropped)));
}

#[test]
fn test_cached_value_get_mut() {
    let sv = SharedValue::new(5u32);
    let mut cache = sv.create_cache();
    *cache.get_mut().unwrap() += 3;
    // local mutation is visible within this cache instance.
    assert_eq!(*cache.get().unwrap(), 8);
}

#[test]
fn test_cached_value_create_sibling() {
    let sv = SharedValue::new(42u32);
    let cache = sv.create_cache();
    let mut sibling = cache.create_sibling().unwrap();
    assert_eq!(*sibling.get().unwrap(), 42);
}

#[test]
fn test_cached_value_sibling_source_dropped() {
    let sv = SharedValue::new(1u32);
    let cache = sv.create_cache();
    drop(sv);
    assert!(matches!(cache.create_sibling(), Err(CacheError::SourceDropped)));
}
