//! Type-safe configuration settings for the TYPHOON protocol.

mod builder;
mod error;
mod override_map;
mod settings;
mod statics;

pub use builder::SettingsBuilder;
pub use error::SettingsError;
pub use override_map::{Key, OverrideMap, SettingType, SettingValue};
pub use settings::Settings;
pub use statics::{consts, keys};
