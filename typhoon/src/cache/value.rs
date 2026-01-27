use std::cell::UnsafeCell;
use std::marker::PhantomData;
use std::sync::{Arc, Weak};

use rand::RngCore;

use crate::cache::common::{CacheError, Versioned};
use crate::utils::random::get_rng;
use crate::utils::sync::RwLock;

pub(crate) type SharedState<T> = RwLock<Versioned<T>>;
pub(crate) type ValueMapper<T> = Arc<dyn Fn(&T, Option<&T>) -> T + Send>;

/// Change once this is implemented: https://doc.rust-lang.org/beta/unstable-book/language-features/negative-impls.html
pub struct SharedValue<T: Clone + Send> {
    state: Arc<SharedState<T>>,
    local: T,
    _not_sync: PhantomData<UnsafeCell<()>>,
}

impl<T: Clone + Send> SharedValue<T> {
    pub fn new(value: T) -> Self {
        let versioned = Versioned {
            value: value.clone(),
            version: get_rng().next_u64(),
        };
        SharedValue {
            state: Arc::new(RwLock::new(versioned)),
            local: value,
            _not_sync: PhantomData,
        }
    }

    pub fn get(&self) -> &T {
        &self.local
    }

    pub fn get_mut(&mut self) -> &mut T {
        &mut self.local
    }

    pub async fn set(&mut self, value: T) {
        self.local = value.clone();
        *self.state.write().await = Versioned {
            value: value.clone(),
            version: get_rng().next_u64(),
        };
    }

    pub async fn create_cache(&self) -> CachedValue<T> {
        self.create_cache_with(|source, _| source.clone()).await
    }

    pub async fn create_cache_with<F: Fn(&T, Option<&T>) -> T + Send + 'static>(&self, mapper: F) -> CachedValue<T> {
        let guard = self.state.read().await;
        let value = mapper(&guard.value, None);
        let version = guard.version;
        drop(guard);

        CachedValue {
            source: Arc::downgrade(&self.state),
            local: value,
            version,
            mapper: Some(Arc::new(mapper)),
            _not_sync: PhantomData,
        }
    }
}

/// Change once this is implemented: https://doc.rust-lang.org/beta/unstable-book/language-features/negative-impls.html
pub struct CachedValue<T: Clone + Send> {
    source: Weak<SharedState<T>>,
    local: T,
    version: u64,
    mapper: Option<ValueMapper<T>>,
    _not_sync: PhantomData<UnsafeCell<()>>,
}

impl<T: Clone + Send> CachedValue<T> {
    fn map_value(&self, source: &T, old: Option<&T>) -> T {
        match &self.mapper {
            Some(mapper) => mapper(source, old),
            None => source.clone(),
        }
    }

    pub async fn get(&mut self) -> Result<&T, CacheError> {
        let source = self.source.upgrade().ok_or(CacheError::SourceDropped)?;
        let guard = source.read().await;

        if guard.version != self.version {
            self.local = self.map_value(&guard.value, Some(&self.local));
            self.version = guard.version;
        }

        Ok(&self.local)
    }

    pub async fn get_mut(&mut self) -> Result<&mut T, CacheError> {
        let source = self.source.upgrade().ok_or(CacheError::SourceDropped)?;
        let guard = source.read().await;

        if guard.version != self.version {
            self.local = self.map_value(&guard.value, Some(&self.local));
            self.version = guard.version;
        }

        Ok(&mut self.local)
    }

    pub async fn create_sibling(&self) -> Result<CachedValue<T>, CacheError> {
        let source = self.source.upgrade().ok_or(CacheError::SourceDropped)?;
        let guard = source.read().await;
        let value = self.map_value(&guard.value, None);
        let version = guard.version;
        drop(guard);

        Ok(CachedValue {
            source: self.source.clone(),
            local: value,
            version,
            mapper: self.mapper.clone(),
            _not_sync: PhantomData,
        })
    }

    pub async fn create_sibling_with<F: Fn(&T, Option<&T>) -> T + Send + 'static>(&self, mapper: F) -> Result<CachedValue<T>, CacheError> {
        let source = self.source.upgrade().ok_or(CacheError::SourceDropped)?;
        let guard = source.read().await;
        let value = mapper(&guard.value, None);
        let version = guard.version;
        drop(guard);

        Ok(CachedValue {
            source: self.source.clone(),
            local: value,
            version,
            mapper: Some(Arc::new(mapper)),
            _not_sync: PhantomData,
        })
    }
}
