//! Error types for settings validation.

use thiserror::Error;

/// Error returned by [`crate::settings::SettingsBuilder::build`] when a setting fails validation.
#[derive(Error, Debug)]
pub enum SettingsError {
    /// A setting value failed one of `SettingsBuilder`'s internal consistency checks.
    #[error("settings assertion failed: {message}")]
    AssertionFailed {
        /// Human-readable description of which check failed.
        message: String,
    },
}
