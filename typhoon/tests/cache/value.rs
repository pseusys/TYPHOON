use crate::cache::{CacheError, SharedValue};

// ── SharedValue ───────────────────────────────────────────────────────────────

#[tokio::test]
async fn test_shared_value_new_get() {
    let mut sv = SharedValue::new(42u32);
    assert_eq!(*sv.get().await, 42);
}

#[tokio::test]
async fn test_shared_value_get_mut_mutates_local() {
    let mut sv = SharedValue::new(10u32);
    *sv.get_mut().await += 5;
    assert_eq!(*sv.get().await, 15);
}

#[tokio::test]
async fn test_shared_value_set_visible_to_same_instance() {
    let mut sv = SharedValue::new(1u32);
    sv.set(99u32).await;
    assert_eq!(*sv.get().await, 99);
}

#[tokio::test]
async fn test_shared_value_sibling_sees_set() {
    let mut sv = SharedValue::new(1u32);
    let mut sibling = sv.create_sibling().await;
    sv.set(77u32).await;
    // sibling must re-fetch on next get because the version changed.
    assert_eq!(*sibling.get().await, 77);
}

#[tokio::test]
async fn test_shared_value_create_sibling_initially_same() {
    let mut sv = SharedValue::new(55u32);
    let mut sibling = sv.create_sibling().await;
    assert_eq!(*sibling.get().await, 55);
}

#[tokio::test]
async fn test_shared_value_create_cache_initially_same() {
    let mut sv = SharedValue::new(33u32);
    let mut cache = sv.create_cache().await;
    assert_eq!(*cache.get().await.unwrap(), 33);
}

// ── CachedValue ───────────────────────────────────────────────────────────────

#[tokio::test]
async fn test_cached_value_refetches_after_set() {
    let mut sv = SharedValue::new(10u32);
    let mut cache = sv.create_cache().await;
    sv.set(20u32).await;
    assert_eq!(*cache.get().await.unwrap(), 20);
}

#[tokio::test]
async fn test_cached_value_source_dropped_returns_error() {
    let sv = SharedValue::new(1u32);
    let mut cache = sv.create_cache().await;
    drop(sv);
    assert!(matches!(cache.get().await, Err(CacheError::SourceDropped)));
}

#[tokio::test]
async fn test_cached_value_get_mut() {
    let mut sv = SharedValue::new(5u32);
    let mut cache = sv.create_cache().await;
    *cache.get_mut().await.unwrap() += 3;
    // local mutation is visible within this cache instance.
    assert_eq!(*cache.get().await.unwrap(), 8);
}

#[tokio::test]
async fn test_cached_value_create_sibling() {
    let mut sv = SharedValue::new(42u32);
    let cache = sv.create_cache().await;
    let mut sibling = cache.create_sibling().await.unwrap();
    assert_eq!(*sibling.get().await.unwrap(), 42);
}

#[tokio::test]
async fn test_cached_value_sibling_source_dropped() {
    let sv = SharedValue::new(1u32);
    let cache = sv.create_cache().await;
    drop(sv);
    assert!(matches!(cache.create_sibling().await, Err(CacheError::SourceDropped)));
}
