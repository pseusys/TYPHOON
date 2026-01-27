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
pub(crate) type ValueMapper<V> = Arc<dyn Fn(&V, Option<&V>) -> V + Send>;

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
        self.local.insert(key.clone(), value.clone());
        self.state.write().await.insert(key.clone(), Versioned {
            value: value.clone(),
            version: get_rng().next_u64(),
        });
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

    pub fn keys(&self) -> impl Iterator<Item = &K> {
        self.local.keys()
    }

    pub fn create_cache(&self) -> CachedMap<K, V> {
        CachedMap {
            source: Arc::downgrade(&self.state),
            local: HashMap::new(),
            mapper: None,
            _not_sync: PhantomData,
        }
    }

    pub fn create_cache_with<F: Fn(&V, Option<&V>) -> V + Send + 'static>(&self, mapper: F) -> CachedMap<K, V> {
        CachedMap {
            source: Arc::downgrade(&self.state),
            local: HashMap::new(),
            mapper: Some(Arc::new(mapper)),
            _not_sync: PhantomData,
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
    mapper: Option<ValueMapper<V>>,
    _not_sync: PhantomData<UnsafeCell<()>>,
}

impl<K: Clone + Eq + Hash + Send + ToString, V: Clone + Send> CachedMap<K, V> {
    fn map_value(&self, source: &V, old: Option<&V>) -> V {
        match &self.mapper {
            Some(mapper) => mapper(source, old),
            None => source.clone(),
        }
    }

    async fn fetch(&mut self, key: &K) -> Result<&mut LocalEntry<V>, CacheError> {
        let source = self.source.upgrade().ok_or(CacheError::SourceDropped)?;
        let guard = source.read().await;

        match guard.get(key) {
            Some(entry) => {
                let needs_update = self.local.get(key).map(|local| local.source_version != entry.version).unwrap_or(true);

                if needs_update {
                    let old_value = self.local.get(key).map(|e| &e.value);
                    let new_value = self.map_value(&entry.value, old_value);
                    self.local.insert(
                        key.clone(),
                        LocalEntry {
                            value: new_value,
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
            mapper: self.mapper.clone(),
            _not_sync: PhantomData,
        })
    }

    pub fn create_sibling_with<F: Fn(&V, Option<&V>) -> V + Send + 'static>(&self, mapper: F) -> Result<CachedMap<K, V>, CacheError>{
        if self.source.strong_count() == 0 {
            return Err(CacheError::SourceDropped);
        }

        Ok(CachedMap {
            source: self.source.clone(),
            local: HashMap::new(),
            mapper: Some(Arc::new(mapper)),
            _not_sync: PhantomData,
        })
    }
}
