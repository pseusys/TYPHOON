use std::env;

use crate::defaults::DefaultExecutor;
use crate::settings::SettingsBuilder;
use crate::settings::keys::*;

fn builder() -> SettingsBuilder<DefaultExecutor> {
    SettingsBuilder::new()
}

// === Settings assertion tests ===

// Test: default settings pass all assertions.
#[test]
fn test_default_settings_pass_assertions() {
    assert!(builder().build().is_ok());
}

// Test: TIMEOUT_MIN > TIMEOUT_MAX fails assertion.
#[test]
fn test_settings_timeout_min_exceeds_max() {
    let result = builder().set(&TIMEOUT_MIN, 50000).set(&TIMEOUT_MAX, 1000).build();
    assert!(result.is_err());
}

// Test: RTT_MIN > RTT_MAX fails assertion.
#[test]
fn test_settings_rtt_min_exceeds_max() {
    let result = builder().set(&RTT_MIN, 10000).set(&RTT_MAX, 100).build();
    assert!(result.is_err());
}

// Test: RTT_ALPHA > 1.0 fails assertion.
#[test]
fn test_settings_rtt_alpha_exceeds_one() {
    let result = builder().set(&RTT_ALPHA, 1.5).build();
    assert!(result.is_err());
}

// Test: RTT_ALPHA = 0.0 fails assertion (must be exclusive).
#[test]
fn test_settings_rtt_alpha_zero() {
    let result = builder().set(&RTT_ALPHA, 0.0).build();
    assert!(result.is_err());
}

// Test: RTT_BETA negative fails assertion.
#[test]
fn test_settings_rtt_beta_negative() {
    let result = builder().set(&RTT_BETA, -0.1).build();
    assert!(result.is_err());
}

// Test: FAKE_HEADER_PROBABILITY > 1.0 fails assertion.
#[test]
fn test_settings_fake_header_probability_exceeds_one() {
    let result = builder().set(&FAKE_HEADER_PROBABILITY, 1.5).build();
    assert!(result.is_err());
}

// Test: FAKE_HEADER_PROBABILITY = 0.0 passes assertion (inclusive range).
#[test]
fn test_settings_fake_header_probability_zero_ok() {
    let result = builder().set(&FAKE_HEADER_PROBABILITY, 0.0).build();
    assert!(result.is_ok());
}

// Test: HEALTH_CHECK_NEXT_IN_MIN <= TIMEOUT_MAX fails assertion (next_in must be > timeout).
#[test]
fn test_settings_next_in_not_greater_than_timeout() {
    let result = builder().set(&HEALTH_CHECK_NEXT_IN_MIN, 30000).set(&TIMEOUT_MAX, 32000).build();
    assert!(result.is_err());
}

// Test: RTT_DEFAULT outside [RTT_MIN, RTT_MAX] fails assertion.
#[test]
fn test_settings_rtt_default_out_of_range() {
    let result = builder().set(&RTT_DEFAULT, 100000).build();
    assert!(result.is_err());
}

// Test: DECOY_CURRENT_ALPHA > 1.0 fails assertion.
#[test]
fn test_settings_decoy_current_alpha_exceeds_one() {
    let result = builder().set(&DECOY_CURRENT_ALPHA, 2.0).build();
    assert!(result.is_err());
}

// Test: negative FAKE_BODY_SERVICE_PROBABILITY fails assertion.
#[test]
fn test_settings_negative_service_probability() {
    let result = builder().set(&FAKE_BODY_SERVICE_PROBABILITY, -1.0).build();
    assert!(result.is_err());
}

// Test: DECOY_LENGTH_MIN > DECOY_LENGTH_MAX fails assertion.
#[test]
fn test_settings_decoy_length_min_exceeds_max() {
    let result = builder().set(&DECOY_LENGTH_MIN, 2000).set(&DECOY_LENGTH_MAX, 100).build();
    assert!(result.is_err());
}

// Test: valid custom settings pass assertions.
#[test]
fn test_settings_valid_custom_pass() {
    let result = builder().set(&RTT_ALPHA, 0.5).set(&RTT_BETA, 0.5).set(&FAKE_HEADER_PROBABILITY, 0.5).build();
    assert!(result.is_ok());
}

// Test: environment variable override is applied when no explicit override is set.
#[test]
fn test_env_var_override_applied() {
    let env_name = TIMEOUT_RTT_FACTOR.name;
    let original = env::var(env_name).ok();

    // SAFETY: test-only, single-threaded access to this env var.
    unsafe { env::set_var(env_name, "7.5") };
    let settings = builder().build().expect("settings should build with env override");
    let val: f64 = settings.get(&TIMEOUT_RTT_FACTOR);
    assert_eq!(val, 7.5, "env var override should take effect");

    // Cleanup.
    unsafe {
        match original {
            Some(v) => env::set_var(env_name, v),
            None => env::remove_var(env_name),
        }
    }
}

// Test: explicit override takes precedence over environment variable.
#[test]
fn test_explicit_override_beats_env_var() {
    let env_name = TIMEOUT_RTT_FACTOR.name;
    let original = env::var(env_name).ok();

    // SAFETY: test-only, single-threaded access to this env var.
    unsafe { env::set_var(env_name, "7.5") };
    let settings = builder().set(&TIMEOUT_RTT_FACTOR, 3.0).build().expect("settings should build");
    let val: f64 = settings.get(&TIMEOUT_RTT_FACTOR);
    assert_eq!(val, 3.0, "explicit override should take precedence over env var");

    // Cleanup.
    unsafe {
        match original {
            Some(v) => env::set_var(env_name, v),
            None => env::remove_var(env_name),
        }
    }
}
