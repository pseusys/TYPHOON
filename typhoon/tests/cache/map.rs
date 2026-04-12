use crate::cache::SharedMap;

// ── SharedMap ─────────────────────────────────────────────────────────────────

// Test: inserted value is immediately visible via get().
#[tokio::test]
async fn test_shared_map_insert_get() {
    let mut map: SharedMap<String, u32> = SharedMap::new();
    map.insert("a".to_string(), 42).await;
    assert_eq!(map.get(&"a".to_string()), Some(&42));
}

// Test: contains_key reflects inserted and removed keys.
#[tokio::test]
async fn test_shared_map_contains_key() {
    let mut map: SharedMap<String, u32> = SharedMap::new();
    assert!(!map.contains_key(&"x".to_string()));
    map.insert("x".to_string(), 1).await;
    assert!(map.contains_key(&"x".to_string()));
    map.remove(&"x".to_string()).await;
    assert!(!map.contains_key(&"x".to_string()));
}

// Test: modify mutates the value in place.
#[tokio::test]
async fn test_shared_map_modify() {
    let mut map: SharedMap<String, u32> = SharedMap::new();
    map.insert("k".to_string(), 10).await;
    map.modify(&"k".to_string(), |v| *v += 5).await;
    assert_eq!(map.get(&"k".to_string()), Some(&15));
}

// ── CachedMapEntry version-bump propagation ───────────────────────────────────

// Test: CachedMapEntry re-fetches the value after the shared map is modified.
#[tokio::test]
async fn test_cached_map_entry_refetches_after_modify() {
    let mut map: SharedMap<String, u32> = SharedMap::new();
    let key = "counter".to_string();
    map.insert(key.clone(), 0).await;

    let template = map.create_cache_for(key.clone());
    let mut entry = template.create_entry();

    // First fetch: sees initial value.
    assert_eq!(*entry.get().await.unwrap(), 0);

    // Modify via SharedMap — bumps the shared version.
    map.modify(&key, |v| *v = 99).await;

    // Next fetch on the SAME entry must re-fetch and see 99.
    assert_eq!(*entry.get().await.unwrap(), 99);
}

// Test: two independent CachedMapEntryTemplates (send vs recv pattern)
// each see the updated value after modify, independently.
#[tokio::test]
async fn test_two_templates_see_same_update() {
    let mut map: SharedMap<String, u32> = SharedMap::new();
    let key = "shared".to_string();
    map.insert(key.clone(), 1).await;

    let t_send = map.create_cache_for(key.clone());
    let t_recv = map.create_cache_for(key.clone());

    let mut e_send = t_send.create_entry();
    let mut e_recv = t_recv.create_entry();

    assert_eq!(*e_send.get().await.unwrap(), 1);
    assert_eq!(*e_recv.get().await.unwrap(), 1);

    // Upgrade: simulate session-key rotation.
    map.modify(&key, |v| *v = 2).await;

    assert_eq!(*e_send.get().await.unwrap(), 2);
    assert_eq!(*e_recv.get().await.unwrap(), 2);
}

// Test: CachedMapEntry returns CacheError::KeyNotFound after remove.
#[tokio::test]
async fn test_cached_map_entry_after_remove() {
    let mut map: SharedMap<String, u32> = SharedMap::new();
    let key = "gone".to_string();
    map.insert(key.clone(), 7).await;

    let template = map.create_cache_for(key.clone());
    let mut entry = template.create_entry();

    assert!(entry.get().await.is_ok());

    map.remove(&key).await;

    assert!(entry.get().await.is_err(), "entry must return error after key removed");
}

// Test: CachedMapEntry returns CacheError::SourceDropped after the SharedMap is dropped.
#[tokio::test]
async fn test_cached_map_entry_source_dropped() {
    let mut entry = {
        let mut map: SharedMap<String, u32> = SharedMap::new();
        let key = "ephemeral".to_string();
        map.insert(key.clone(), 5).await;
        let template = map.create_cache_for(key.clone());
        template.create_entry()
        // map drops here, Arc<SharedState> strong count → 0
    };

    assert!(entry.get().await.is_err(), "entry must return error after source SharedMap is dropped");
}

// ── SharedMap::create_cache (CachedMap) ──────────────────────────────────────

// Test: CachedMap reads the current value for a key.
#[tokio::test]
async fn test_cached_map_get() {
    let mut map: SharedMap<String, u32> = SharedMap::new();
    let key = "foo".to_string();
    map.insert(key.clone(), 123).await;

    let mut cache = map.create_cache();
    assert_eq!(*cache.get(&key).await.unwrap(), 123);
}

// Test: CachedMap re-fetches after modify.
#[tokio::test]
async fn test_cached_map_refetches_after_modify() {
    let mut map: SharedMap<String, u32> = SharedMap::new();
    let key = "bar".to_string();
    map.insert(key.clone(), 10).await;

    let mut cache = map.create_cache();
    assert_eq!(*cache.get(&key).await.unwrap(), 10);

    map.modify(&key, |v| *v = 20).await;
    assert_eq!(*cache.get(&key).await.unwrap(), 20);
}
