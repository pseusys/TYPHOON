use std::cell::UnsafeCell;
use std::marker::PhantomData;
use std::sync::{Arc, Weak};

use rand::RngCore;

use crate::cache::common::{CacheError, Versioned};
use crate::utils::random::get_rng;
use crate::utils::sync::RwLock;

pub(crate) type SharedState<T> = RwLock<Versioned<T>>;

/// Change once this is implemented: https://doc.rust-lang.org/beta/unstable-book/language-features/negative-impls.html
pub struct SharedValue<T: Clone + Send> {
    state: Arc<SharedState<T>>,
    local: T,
    version: u64,
    _not_sync: PhantomData<UnsafeCell<()>>,
}

impl<T: Clone + Send> SharedValue<T> {
    pub fn new(value: T) -> Self {
        let version = get_rng().next_u64();
        let versioned = Versioned {
            value: value.clone(),
            version,
        };
        SharedValue {
            state: Arc::new(RwLock::new(versioned)),
            local: value,
            version,
            _not_sync: PhantomData,
        }
    }

    pub async fn get_mut(&mut self) -> &mut T {
        let guard = self.state.read().await;
        if guard.version != self.version {
            self.local = guard.value.clone();
            self.version = guard.version;
        }
        &mut self.local
    }

    pub async fn get(&mut self) -> &T {
        self.get_mut().await
    }

    pub async fn set(&mut self, value: T) {
        self.local = value.clone();
        *self.state.write().await = Versioned {
            value,
            version: get_rng().next_u64(),
        };
    }

    pub async fn create_sibling(&self) -> SharedValue<T> {
        let guard = self.state.read().await;
        let value = guard.value.clone();
        let version = guard.version;
        drop(guard);

        SharedValue {
            state: self.state.clone(),
            local: value,
            version,
            _not_sync: PhantomData,
        }
    }

    pub async fn create_cache(&self) -> CachedValue<T> {
        let guard = self.state.read().await;
        let value = guard.value.clone();
        let version = guard.version;
        drop(guard);

        CachedValue {
            source: Arc::downgrade(&self.state),
            local: value,
            version,
            _not_sync: PhantomData,
        }
    }
}

/// Change once this is implemented: https://doc.rust-lang.org/beta/unstable-book/language-features/negative-impls.html
pub struct CachedValue<T: Clone + Send> {
    source: Weak<SharedState<T>>,
    local: T,
    version: u64,
    _not_sync: PhantomData<UnsafeCell<()>>,
}

impl<T: Clone + Send> CachedValue<T> {
    pub async fn get_mut(&mut self) -> Result<&mut T, CacheError> {
        let source = self.source.upgrade().ok_or(CacheError::SourceDropped)?;
        let guard = source.read().await;

        if guard.version != self.version {
            self.local = guard.value.clone();
            self.version = guard.version;
        }

        Ok(&mut self.local)
    }

    pub async fn get(&mut self) -> Result<&T, CacheError> {
        self.get_mut().await.map(|v| &*v)
    }

    pub async fn create_sibling(&self) -> Result<CachedValue<T>, CacheError> {
        let source = self.source.upgrade().ok_or(CacheError::SourceDropped)?;
        let guard = source.read().await;
        let value = guard.value.clone();
        let version = guard.version;
        drop(guard);

        Ok(CachedValue {
            source: self.source.clone(),
            local: value,
            version,
            _not_sync: PhantomData,
        })
    }
}
