#[cfg(all(test, feature = "tokio"))]
#[path = "../../tests/cache/map.rs"]
mod tests;

use std::cell::UnsafeCell;
use std::collections::HashMap;
use std::hash::Hash;
use std::marker::PhantomData;
use std::sync::{Arc, Weak};

use rand::RngCore;

use crate::cache::common::{CacheError, Versioned};
use crate::utils::random::get_rng;
use crate::utils::sync::RwLock;

pub(crate) type SharedState<K, V> = RwLock<HashMap<K, Versioned<V>>>;

struct LocalEntry<V> {
    value: V,
    source_version: u64,
}

/// Change once this is implemented: https://doc.rust-lang.org/beta/unstable-book/language-features/negative-impls.html
pub struct SharedMap<K: Clone + Eq + Hash + Send + ToString, V: Clone + Send> {
    state: Arc<SharedState<K, V>>,
    local: HashMap<K, V>,
    _not_sync: PhantomData<UnsafeCell<()>>,
}

impl<K: Clone + Eq + Hash + Send + ToString, V: Clone + Send> SharedMap<K, V> {
    pub fn new() -> Self {
        SharedMap {
            state: Arc::new(RwLock::new(HashMap::new())),
            local: HashMap::new(),
            _not_sync: PhantomData,
        }
    }

    pub async fn insert(&mut self, key: K, value: V) {
        self.state.write().await.insert(
            key.clone(),
            Versioned {
                value: value.clone(),
                version: get_rng().next_u64(),
            },
        );
        self.local.insert(key, value);
    }

    pub async fn remove(&mut self, key: &K) {
        self.local.remove(key);
        self.state.write().await.remove(key);
    }

    pub fn contains_key(&self, key: &K) -> bool {
        self.local.contains_key(key)
    }

    pub fn get(&self, key: &K) -> Option<&V> {
        self.local.get(key)
    }

    pub fn get_mut(&mut self, key: &K) -> Option<&mut V> {
        self.local.get_mut(key)
    }

    /// Mutate an existing entry in place and propagate the change to all `CachedMap` instances
    /// by bumping the shared-state version. Saves one `V` clone and one `K` clone compared to
    /// the `get().cloned()` + `insert()` pattern.
    pub async fn modify<F: FnOnce(&mut V)>(&mut self, key: &K, f: F) {
        if let Some(local) = self.local.get_mut(key) {
            f(local);
            let versioned = Versioned { value: local.clone(), version: get_rng().next_u64() };
            self.state.write().await.insert(key.clone(), versioned);
        }
    }

    pub fn keys(&self) -> impl Iterator<Item = &K> {
        self.local.keys()
    }

    pub fn create_cache(&self) -> CachedMap<K, V> {
        CachedMap {
            source: Arc::downgrade(&self.state),
            local: HashMap::new(),
            _not_sync: PhantomData,
        }
    }

    /// Create a `Sync` template that watches one specific key.
    /// Call `CachedMapEntryTemplate::create_entry()` on the returned value to get a
    /// working `CachedMapEntry` with a local cache (one per task, no `Mutex` needed).
    pub fn create_cache_for(&self, key: K) -> CachedMapEntryTemplate<K, V> {
        CachedMapEntryTemplate {
            source: Arc::downgrade(&self.state),
            key,
        }
    }
}

impl<K: Clone + Eq + Hash + Send + ToString, V: Clone + Send> Default for SharedMap<K, V> {
    fn default() -> Self {
        Self::new()
    }
}

/// Change once this is implemented: https://doc.rust-lang.org/beta/unstable-book/language-features/negative-impls.html
pub struct CachedMap<K: Clone + Eq + Hash + Send + ToString, V: Clone + Send> {
    source: Weak<SharedState<K, V>>,
    local: HashMap<K, LocalEntry<V>>,
    _not_sync: PhantomData<UnsafeCell<()>>,
}

impl<K: Clone + Eq + Hash + Send + ToString, V: Clone + Send> CachedMap<K, V> {
    async fn fetch(&mut self, key: &K) -> Result<&mut LocalEntry<V>, CacheError> {
        let source = self.source.upgrade().ok_or(CacheError::SourceDropped)?;
        let guard = source.read().await;

        match guard.get(key) {
            Some(entry) => {
                let needs_update = self.local.get(key).map(|local| local.source_version != entry.version).unwrap_or(true);

                if needs_update {
                    self.local.insert(
                        key.clone(),
                        LocalEntry {
                            value: entry.value.clone(),
                            source_version: entry.version,
                        },
                    );
                }
                drop(guard);
                Ok(self.local.get_mut(key).unwrap())
            }
            None => {
                self.local.remove(key);
                Err(CacheError::KeyNotFound(key.to_string()))
            }
        }
    }

    pub async fn get(&mut self, key: &K) -> Result<&V, CacheError> {
        Ok(&self.fetch(key).await?.value)
    }

    pub async fn get_mut(&mut self, key: &K) -> Result<&mut V, CacheError> {
        Ok(&mut self.fetch(key).await?.value)
    }

    pub fn create_sibling(&self) -> Result<CachedMap<K, V>, CacheError> {
        if self.source.strong_count() == 0 {
            return Err(CacheError::SourceDropped);
        }

        Ok(CachedMap {
            source: self.source.clone(),
            local: HashMap::new(),
            _not_sync: PhantomData,
        })
    }
}

/// Sync template for a single-key cache entry.
/// Stores a `Weak` reference to the shared map plus the key.
/// Has no local cache of its own — call `create_entry()` to get a `CachedMapEntry`
/// with a local cache suitable for use within one task (no `Mutex` required at the call site).
pub struct CachedMapEntryTemplate<K: Clone + Eq + Hash + Send + ToString, V: Clone + Send> {
    source: Weak<SharedState<K, V>>,
    key: K,
}

impl<K: Clone + Eq + Hash + Send + ToString, V: Clone + Send> CachedMapEntryTemplate<K, V> {
    /// Create a working `CachedMapEntry` with an empty local cache.
    /// Intended to be created once per task invocation and used locally (not shared).
    pub fn create_entry(&self) -> CachedMapEntry<K, V> {
        CachedMapEntry {
            source: self.source.clone(),
            key: self.key.clone(),
            local: None,
            _not_sync: PhantomData,
        }
    }
}

/// Single-entry cache connected to a `SharedMap`, watching one specific key.
/// Change once this is implemented: https://doc.rust-lang.org/beta/unstable-book/language-features/negative-impls.html
pub struct CachedMapEntry<K: Clone + Eq + Hash + Send + ToString, V: Clone + Send> {
    source: Weak<SharedState<K, V>>,
    key: K,
    local: Option<LocalEntry<V>>,
    _not_sync: PhantomData<UnsafeCell<()>>,
}

impl<K: Clone + Eq + Hash + Send + ToString, V: Clone + Send> CachedMapEntry<K, V> {
    async fn fetch(&mut self) -> Result<&mut LocalEntry<V>, CacheError> {
        let source = self.source.upgrade().ok_or(CacheError::SourceDropped)?;
        let guard = source.read().await;

        match guard.get(&self.key) {
            Some(entry) => {
                let needs_update = self.local.as_ref().map(|local| local.source_version != entry.version).unwrap_or(true);

                if needs_update {
                    self.local = Some(LocalEntry {
                        value: entry.value.clone(),
                        source_version: entry.version,
                    });
                }
                drop(guard);
                Ok(self.local.as_mut().unwrap())
            }
            None => {
                self.local = None;
                Err(CacheError::KeyNotFound(self.key.to_string()))
            }
        }
    }

    pub async fn get(&mut self) -> Result<&V, CacheError> {
        Ok(&self.fetch().await?.value)
    }

    pub async fn get_mut(&mut self) -> Result<&mut V, CacheError> {
        Ok(&mut self.fetch().await?.value)
    }
}
