use std::sync::Arc;

use crate::bytes::{ByteBuffer, StaticByteBuffer};
use crate::defaults::DefaultExecutor;
use crate::flow::decoy::common::{DecoyState, exponential_variance, random_gauss, random_uniform};
use crate::settings::SettingsBuilder;
use crate::settings::consts::{DEFAULT_TYPHOON_ID_LENGTH, TAILOR_LENGTH};
use crate::settings::keys::*;
use crate::utils::time::unix_timestamp_ms;

fn make_settings() -> Arc<crate::settings::Settings<DefaultExecutor>> {
    Arc::new(SettingsBuilder::new().build().unwrap())
}

// === DecoyState::new tests ===

// Test: new state has expected default values from settings.
#[test]
fn test_decoy_state_new_defaults() {
    let settings = make_settings();
    let state = DecoyState::<StaticByteBuffer, DefaultExecutor>::new(settings.clone(), StaticByteBuffer::empty(DEFAULT_TYPHOON_ID_LENGTH));

    let expected_ref_rate = settings.get(&DECOY_REFERENCE_PACKET_RATE_DEFAULT);
    let expected_pkt_rate = settings.get(&DECOY_CURRENT_PACKET_RATE_DEFAULT);
    let expected_byte_rate = settings.get(&DECOY_CURRENT_BYTE_RATE_DEFAULT);
    let length_max = settings.get(&DECOY_LENGTH_MAX) as usize;
    let length_min = settings.get(&DECOY_LENGTH_MIN) as usize;

    assert_eq!(state.reference_rate, expected_ref_rate);
    assert_eq!(state.packet_rate, expected_pkt_rate);
    assert_eq!(state.byte_rate, expected_byte_rate);
    assert_eq!(state.packet_length_cap, length_max.max(length_min));
    assert_eq!(state.pending_length, length_min);
}

// Test: initial byte_budget is half of cap * factor.
#[test]
fn test_decoy_state_new_initial_budget() {
    let settings = make_settings();
    let state = DecoyState::<StaticByteBuffer, DefaultExecutor>::new(settings.clone(), StaticByteBuffer::empty(DEFAULT_TYPHOON_ID_LENGTH));

    let byte_rate_cap = settings.get(&DECOY_BYTE_RATE_CAP);
    let byte_rate_factor = settings.get(&DECOY_BYTE_RATE_FACTOR);
    let expected_budget = byte_rate_cap * byte_rate_factor / 2.0;

    assert_eq!(state.byte_budget, expected_budget);
}

// === DecoyState::quietness_index tests ===

// Test: when packet_rate equals reference_rate, quietness is 0 (busy).
#[test]
fn test_quietness_index_busy() {
    let settings = make_settings();
    let mut state = DecoyState::<StaticByteBuffer, DefaultExecutor>::new(settings.clone(), StaticByteBuffer::empty(DEFAULT_TYPHOON_ID_LENGTH));
    state.reference_rate = 100.0;
    state.packet_rate = 100.0;
    assert_eq!(state.quietness_index(), 0.0);
}

// Test: when packet_rate is much smaller than reference_rate, quietness approaches 1.
#[test]
fn test_quietness_index_quiet() {
    let settings = make_settings();
    let mut state = DecoyState::<StaticByteBuffer, DefaultExecutor>::new(settings.clone(), StaticByteBuffer::empty(DEFAULT_TYPHOON_ID_LENGTH));
    state.reference_rate = 1000.0;
    state.packet_rate = 1.0;
    let qi = state.quietness_index();
    assert!(qi > 0.99, "quietness should be near 1.0, got {qi}");
}

// Test: when packet_rate exceeds reference_rate, quietness clamps to 0.
#[test]
fn test_quietness_index_clamped_to_zero() {
    let settings = make_settings();
    let mut state = DecoyState::<StaticByteBuffer, DefaultExecutor>::new(settings.clone(), StaticByteBuffer::empty(DEFAULT_TYPHOON_ID_LENGTH));
    state.reference_rate = 50.0;
    state.packet_rate = 200.0;
    assert_eq!(state.quietness_index(), 0.0, "should clamp negative values to 0");
}

// === DecoyState::schedule_next tests ===

// Test: schedule_next sets next_decoy_time in the future and pending_length.
#[test]
fn test_schedule_next() {
    let settings = make_settings();
    let mut state = DecoyState::<StaticByteBuffer, DefaultExecutor>::new(settings.clone(), StaticByteBuffer::empty(DEFAULT_TYPHOON_ID_LENGTH));

    let before = unix_timestamp_ms();
    state.schedule_next(500, 256);
    let after = unix_timestamp_ms();

    assert!(state.next_decoy_time >= before + 500, "next_decoy_time should be at least 500ms in the future");
    assert!(state.next_decoy_time <= after + 500, "next_decoy_time should not be too far in the future");
    assert_eq!(state.pending_length, 256);
}

// === DecoyState::create_decoy_packet tests ===

// Test: create_decoy_packet returns a packet of body + tailor + identity length.
#[test]
fn test_create_decoy_packet_size() {
    let settings = make_settings();
    let mut state = DecoyState::<StaticByteBuffer, DefaultExecutor>::new(settings.clone(), StaticByteBuffer::empty(DEFAULT_TYPHOON_ID_LENGTH));

    let body_length = 64;
    let packet = state.create_decoy_packet(body_length);

    assert_eq!(packet.len(), body_length + TAILOR_LENGTH + DEFAULT_TYPHOON_ID_LENGTH, "packet should be body + tailor + identity length");
}

// Test: create_decoy_packet with zero body returns tailor + identity length.
#[test]
fn test_create_decoy_packet_zero_body() {
    let settings = make_settings();
    let mut state = DecoyState::<StaticByteBuffer, DefaultExecutor>::new(settings.clone(), StaticByteBuffer::empty(DEFAULT_TYPHOON_ID_LENGTH));

    let packet = state.create_decoy_packet(0);
    assert_eq!(packet.len(), TAILOR_LENGTH + DEFAULT_TYPHOON_ID_LENGTH);
}

// === Random utility function tests ===

// Test: random_uniform produces values within [min, max].
#[test]
fn test_random_uniform_range() {
    for _ in 0..100 {
        let val = random_uniform(10.0, 20.0);
        assert!(val >= 10.0 && val <= 20.0, "value {val} outside [10, 20]");
    }
}

// Test: random_uniform with equal min and max returns that value.
#[test]
fn test_random_uniform_equal_bounds() {
    let val = random_uniform(5.0, 5.0);
    assert_eq!(val, 5.0);
}

// Test: random_gauss with sigma=0 returns exactly the mean.
#[test]
fn test_random_gauss_zero_sigma() {
    for _ in 0..20 {
        assert_eq!(random_gauss(42.0, 0.0), 42.0);
    }
}

// Test: random_gauss with negative sigma returns exactly the mean.
#[test]
fn test_random_gauss_negative_sigma() {
    assert_eq!(random_gauss(7.5, -1.0), 7.5);
}

// Test: exponential_variance with rate=0 returns f64::MAX.
#[test]
fn test_exponential_variance_zero_rate() {
    assert_eq!(exponential_variance(0.0), f64::MAX);
}

// Test: exponential_variance with negative rate returns f64::MAX.
#[test]
fn test_exponential_variance_negative_rate() {
    assert_eq!(exponential_variance(-5.0), f64::MAX);
}

// Test: exponential_variance with positive rate returns positive value.
#[test]
fn test_exponential_variance_positive_rate() {
    for _ in 0..50 {
        let val = exponential_variance(1.0);
        assert!(val > 0.0, "exponential_variance should return positive value, got {val}");
    }
}
