#[cfg(all(feature = "tokio", feature = "async-std"))]
compile_error!("feature 'tokio' and feature 'async-std' cannot be enabled at the same time");

#[cfg(not(any(feature = "tokio", feature = "async-std")))]
compile_error!("one of the features 'tokio' and 'async-std' should be selected");

#[cfg(not(any(feature = "full_software", feature = "full_hardware", feature = "fast_software", feature = "fast_hardware")))]
compile_error!("one of the features 'full_software', 'full_hardware', 'fast_software' and 'fast_hardware' should be selected");

#[cfg(all(feature = "fast_software", feature = "full_software"))]
compile_error!("feature 'fast_software' and feature 'full_software' cannot be enabled at the same time");

#[cfg(all(feature = "fast_hardware", feature = "full_hardware"))]
compile_error!("feature 'fast_hardware' and feature 'full_hardware' cannot be enabled at the same time");

#[cfg(all(feature = "fast_software", feature = "fast_hardware"))]
compile_error!("feature 'fast_software' and feature 'fast_hardware' cannot be enabled at the same time");

#[cfg(not(any(feature = "server", feature = "client")))]
compile_error!("one of the features 'server' and 'client' should be selected");

pub mod bytes;
pub mod cache;
#[cfg(feature = "debug")]
pub mod debug;
pub mod certificate;
pub mod crypto;
pub mod defaults;
pub mod flow;
mod session;
pub mod settings;
pub mod socket;
mod tailor;
mod utils;
