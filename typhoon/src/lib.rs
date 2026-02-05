#[cfg(all(feature = "fast", feature = "full"))]
compile_error!("feature 'fast' and feature 'full' cannot be enabled at the same time");

#[cfg(not(any(feature = "fast", feature = "full")))]
compile_error!("one of the features 'fast' and 'full' should be selected");

#[cfg(all(feature = "hardware", feature = "software"))]
compile_error!("feature 'hardware' and feature 'software' cannot be enabled at the same time");

#[cfg(not(any(feature = "hardware", feature = "software")))]
compile_error!("one of the features 'hardware' and 'software' should be selected");

#[cfg(not(any(feature = "server", feature = "client")))]
compile_error!("one of the features 'server' and 'client' should be selected");

mod bytes;
mod cache;
mod constants;
mod crypto;
mod flow;
mod session;
mod tailor;
mod utils;
