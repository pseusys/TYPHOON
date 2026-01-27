use thiserror::Error;

#[derive(Error, Debug)]
pub enum CacheError {
    #[error("cache source dropped!")]
    SourceDropped,

    #[error("key was not found in cache: {}", .0)]
    KeyNotFound(String),
}

pub(crate) struct Versioned<T> {
    pub(crate) value: T,
    pub(crate) version: u64,
}
