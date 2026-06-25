use std::sync::Arc;

use crate::defaults::DefaultExecutor;
use crate::flow::decoy::features::{DecoyFeatureConfig, SubheaderMode};
use crate::settings::SettingsBuilder;
use crate::settings::keys::*;

fn make_settings() -> Arc<crate::settings::Settings<DefaultExecutor>> {
    Arc::new(SettingsBuilder::new().build().unwrap())
}

// === DecoyFeatureConfig tests ===

// Test: DecoyFeatureConfig::random produces valid configs.
#[test]
fn test_decoy_feature_config_random_valid() {
    let settings = make_settings();
    for _ in 0..50 {
        let config = DecoyFeatureConfig::random(&settings);

        // Replication probability should be within configured bounds.
        let prob_min = settings.get(&DECOY_REPLICATION_PROBABILITY_MIN);
        let prob_max = settings.get(&DECOY_REPLICATION_PROBABILITY_MAX);
        assert!(config.replication_probability >= prob_min && config.replication_probability <= prob_max, "replication_probability {} outside [{}, {}]", config.replication_probability, prob_min, prob_max);

        // Subheader config should be Some iff mode is not None.
        match config.subheader_mode {
            SubheaderMode::None => assert!(config.subheader_config.is_none()),
            _ => assert!(config.subheader_config.is_some()),
        }
    }
}
