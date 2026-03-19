//! Error types for settings validation.

use thiserror::Error;

#[derive(Error, Debug)]
pub enum SettingsError {
    #[error("settings assertion failed: {message}")]
    AssertionFailed {
        message: String,
    },
}
