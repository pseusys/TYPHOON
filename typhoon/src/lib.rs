#[cfg(all(feature = "tokio", feature = "async-std"))]
compile_error!("feature 'tokio' and feature 'async-std' cannot be enabled at the same time");

#[cfg(not(any(feature = "tokio", feature = "async-std")))]
compile_error!("one of the features 'tokio' and feature 'async-std' should be selected");

#[cfg(all(feature = "fast", feature = "full"))]
compile_error!("feature 'fast' and feature 'full' cannot be enabled at the same time");

#[cfg(not(any(feature = "fast", feature = "full")))]
compile_error!("one of the features 'fast' and feature 'full' should be selected");

#[cfg(all(feature = "hardware", feature = "software"))]
compile_error!("feature 'hardware' and feature 'software' cannot be enabled at the same time");

#[cfg(not(any(feature = "hardware", feature = "software")))]
compile_error!("one of the features 'hardware' and feature 'software' should be selected");

mod bytes;
mod constants;
mod crypto;
mod random;
mod tailor;
mod utils;
