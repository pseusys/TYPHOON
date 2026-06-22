use std::sync::Arc;

use super::RttEstimator;
use crate::defaults::DefaultExecutor;
use crate::settings::{Settings, SettingsBuilder, keys};

fn fast_settings() -> Arc<Settings<DefaultExecutor>> {
    Arc::new(SettingsBuilder::new().set(&keys::TIMEOUT_MIN, 5u64).set(&keys::TIMEOUT_DEFAULT, 10u64).set(&keys::TIMEOUT_MAX, 20u64).build().unwrap())
}

// Test: compute_timeout with no measurement uses the configured default.
#[test]
fn test_compute_timeout_default() {
    let settings = fast_settings();
    let rtt = RttEstimator::new();

    let timeout = rtt.compute_timeout(&settings);
    let min = settings.get(&keys::TIMEOUT_MIN);
    let max = settings.get(&keys::TIMEOUT_MAX);
    assert!(timeout >= min && timeout <= max, "timeout {timeout} not in [{min}, {max}]");
}

// Test: compute_timeout with a measurement returns a value based on srtt + rttvar.
#[test]
fn test_compute_timeout_with_rtt() {
    let settings = fast_settings();
    let mut rtt = RttEstimator::new();
    rtt.smooth_rtt = Some(5.0);
    rtt.rtt_variance = Some(2.0);

    let timeout = rtt.compute_timeout(&settings);
    let min = settings.get(&keys::TIMEOUT_MIN);
    let max = settings.get(&keys::TIMEOUT_MAX);
    // (5 + 2) * factor — whatever the factor, must be clamped to [min, max].
    assert!(timeout >= min && timeout <= max, "rtt-derived timeout {timeout} not in [{min}, {max}]");
}

// Test: update initialises smooth_rtt and rtt_variance on the first measurement.
#[test]
fn test_rtt_first_measurement() {
    let settings = fast_settings();
    let mut rtt = RttEstimator::new();

    let receive_time: u128 = 50; // RTT = 50 - 0 - 0 = 50, clamped
    rtt.update(&settings, receive_time, 0, 0);

    assert!(rtt.smooth_rtt.is_some(), "smooth_rtt must be initialised");
    assert!(rtt.rtt_variance.is_some(), "rtt_variance must be initialised");
    // rtt_variance should be approximately smooth_rtt / 2.
    let srtt = rtt.smooth_rtt.unwrap();
    let rttvar = rtt.rtt_variance.unwrap();
    assert!((rttvar - srtt / 2.0).abs() < 1.0, "initial rttvar should be srtt/2, got srtt={srtt}, rttvar={rttvar}");
}

// Test: update converges smooth_rtt toward repeated measurements.
#[test]
fn test_rtt_ewma_converges() {
    let settings = fast_settings();
    let mut rtt = RttEstimator::new();

    // Feed 20 identical samples of RTT_MIN (clamped floor) ms.
    let rtt_min = settings.get(&keys::RTT_MIN) as f64;
    for _ in 0..20 {
        rtt.update(&settings, rtt_min as u128, 0, 0);
    }

    let srtt = rtt.smooth_rtt.unwrap();
    // After many identical samples the EWMA should be near rtt_min.
    assert!((srtt - rtt_min).abs() < rtt_min * 0.1, "EWMA should converge near {rtt_min}ms, got {srtt}ms");
}
