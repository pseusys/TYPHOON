#[cfg(test)]
#[path = "../../tests/cache/value.rs"]
mod tests;

#[cfg(feature = "client")]
use std::cell::UnsafeCell;
#[cfg(feature = "client")]
use std::marker::PhantomData;
#[cfg(feature = "client")]
use std::sync::{Arc, Weak};

#[cfg(feature = "client")]
use arc_swap::ArcSwap;

#[cfg(feature = "client")]
use crate::cache::common::CacheError;

/// Shared mutable value with lock-free reads.
///
/// All siblings share the same [`ArcSwap`]; a [`SharedValue::set`] atomically publishes to all of
/// them. Staleness is detected by comparing the last-seen shared pointer (`shared`) to the
/// current `ArcSwap` value — independent of any local mutations made via [`SharedValue::get_mut`].
///
/// `shared` always matches the ArcSwap. `local` may diverge (via `get_mut`) until the next
/// shared-state update, at which point it is reset.
///
/// `!Sync` by design: each instance must be driven from exactly one task at a time.
#[cfg(feature = "client")]
pub(crate) struct SharedValue<T: Clone + Send + Sync> {
    state: Arc<ArcSwap<T>>,
    /// Last pointer seen from `state`; used for staleness detection only.
    shared: Arc<T>,
    /// Local working copy; may differ from `shared` after a `get_mut` call.
    local: Arc<T>,
    _not_sync: PhantomData<UnsafeCell<()>>,
}

#[cfg(feature = "client")]
impl<T: Clone + Send + Sync> SharedValue<T> {
    /// Create a new shared value.
    #[inline]
    pub(crate) fn new(value: T) -> Self {
        let arc = Arc::new(value);
        SharedValue {
            state: Arc::new(ArcSwap::from(arc.clone())),
            shared: arc.clone(),
            local: arc,
            _not_sync: PhantomData,
        }
    }

    /// Return a shared reference to the current value, refreshing the local cache if the shared
    /// state has been updated by a sibling.
    #[inline]
    pub(crate) fn get(&mut self) -> &T {
        self.refresh();
        &self.local
    }

    /// Return a mutable reference to the local cache copy, refreshing from shared state first if
    /// a sibling has called `set`. Mutations are local to this instance only and do not propagate.
    #[inline]
    pub(crate) fn get_mut(&mut self) -> &mut T {
        self.refresh();
        Arc::make_mut(&mut self.local)
    }

    /// Atomically publish `value` to all siblings and update this instance's local cache.
    #[inline]
    pub(crate) fn set(&mut self, value: T) {
        let arc = Arc::new(value);
        self.shared = arc.clone();
        self.local = arc.clone();
        self.state.store(arc);
    }

    /// Create another `SharedValue` pointing at the same shared state.
    #[inline]
    pub(crate) fn create_sibling(&self) -> SharedValue<T> {
        let current = self.state.load_full();
        SharedValue {
            state: Arc::clone(&self.state),
            shared: current.clone(),
            local: current,
            _not_sync: PhantomData,
        }
    }

    /// Create a [`CachedValue`] that reads from this shared state but detects drops of the source.
    #[inline]
    pub(crate) fn create_cache(&self) -> CachedValue<T> {
        let current = self.state.load_full();
        CachedValue {
            source: Arc::downgrade(&self.state),
            shared: current.clone(),
            local: current,
            _not_sync: PhantomData,
        }
    }

    /// Re-fetch from shared state if a sibling has published a new value.
    /// Local mutations survive as long as the shared pointer has not changed.
    #[inline]
    fn refresh(&mut self) {
        let current = self.state.load();
        if !Arc::ptr_eq(&self.shared, &current) {
            self.shared = Arc::clone(&current);
            self.local = Arc::clone(&current);
        }
    }
}

/// Read-only cache of a [`SharedValue`] that returns [`CacheError::SourceDropped`] when the
/// originating `SharedValue` has been dropped.
///
/// Staleness detection uses the same `shared` / `local` split as [`SharedValue`].
/// `!Sync` by design.
#[cfg(feature = "client")]
pub(crate) struct CachedValue<T: Clone + Send + Sync> {
    source: Weak<ArcSwap<T>>,
    /// Last pointer seen from the source; used for staleness detection only.
    shared: Arc<T>,
    /// Local working copy; may differ from `shared` after a `get_mut` call.
    local: Arc<T>,
    _not_sync: PhantomData<UnsafeCell<()>>,
}

#[cfg(feature = "client")]
impl<T: Clone + Send + Sync> CachedValue<T> {
    /// Return a mutable reference to the local cache copy, or `Err` if the source was dropped.
    /// Mutations are local to this instance only.
    #[inline]
    pub(crate) fn get_mut(&mut self) -> Result<&mut T, CacheError> {
        self.refresh()?;
        Ok(Arc::make_mut(&mut self.local))
    }

    /// Create a sibling [`CachedValue`] pointing at the same source, or `Err` if dropped.
    #[inline]
    pub(crate) fn create_sibling(&self) -> Result<CachedValue<T>, CacheError> {
        let source = self.source.upgrade().ok_or(CacheError::SourceDropped)?;
        let current = source.load_full();
        Ok(CachedValue {
            source: self.source.clone(),
            shared: current.clone(),
            local: current,
            _not_sync: PhantomData,
        })
    }

    /// Re-fetch from shared state if the source has published a new value.
    #[inline]
    fn refresh(&mut self) -> Result<(), CacheError> {
        let source = self.source.upgrade().ok_or(CacheError::SourceDropped)?;
        let current = source.load();
        if !Arc::ptr_eq(&self.shared, &current) {
            self.shared = Arc::clone(&current);
            self.local = Arc::clone(&current);
        }
        Ok(())
    }
}
