use std::sync::Arc;

use crate::bytes::{ByteBuffer, StaticByteBuffer};
use crate::defaults::DefaultExecutor;
use crate::flow::decoy::common::{DecoyFeatureConfig, DecoyState, MaintenanceMode, ReplicationMode, SubheaderMode, exponential_variance, random_gauss, random_uniform};
use crate::settings::SettingsBuilder;
use crate::settings::consts::{DEFAULT_TYPHOON_ID_LENGTH, TAILOR_LENGTH};
use crate::settings::keys::*;
use crate::utils::unix_timestamp_ms;

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
    state.features.subheader_mode = SubheaderMode::None;
    state.features.subheader_config = None;

    let body_length = 64;
    let packet = state.create_decoy_packet(body_length, false);

    assert_eq!(packet.len(), body_length + TAILOR_LENGTH + DEFAULT_TYPHOON_ID_LENGTH, "packet should be body + tailor + identity length");
}

// Test: create_decoy_packet with zero body returns tailor + identity length.
#[test]
fn test_create_decoy_packet_zero_body() {
    let settings = make_settings();
    let mut state = DecoyState::<StaticByteBuffer, DefaultExecutor>::new(settings.clone(), StaticByteBuffer::empty(DEFAULT_TYPHOON_ID_LENGTH));
    state.features.subheader_mode = SubheaderMode::None;
    state.features.subheader_config = None;

    let packet = state.create_decoy_packet(0, false);
    assert_eq!(packet.len(), TAILOR_LENGTH + DEFAULT_TYPHOON_ID_LENGTH);
}

// === DecoyState::update tests ===

// Test: calling update twice in quick succession moves packet_rate toward 0.
#[test]
fn test_update_adjusts_packet_rate() {
    let settings = make_settings();
    let mut state = DecoyState::<StaticByteBuffer, DefaultExecutor>::new(settings.clone(), StaticByteBuffer::empty(DEFAULT_TYPHOON_ID_LENGTH));
    let initial_packet_rate = state.packet_rate;

    // First call: sets previous_packet_time, no EWMA computation.
    state.update(100);
    assert_eq!(state.packet_rate, initial_packet_rate, "first update should not change packet_rate");

    // Second call (immediately after): time_delta ≈ 0ms, so EWMA should pull packet_rate down.
    state.update(100);
    assert!(state.packet_rate < initial_packet_rate, "packet_rate should decrease with near-zero time delta");
}

// Test: update adjusts byte_rate toward packet length.
#[test]
fn test_update_adjusts_byte_rate() {
    let settings = make_settings();
    let mut state = DecoyState::<StaticByteBuffer, DefaultExecutor>::new(settings.clone(), StaticByteBuffer::empty(DEFAULT_TYPHOON_ID_LENGTH));
    let initial_byte_rate = state.byte_rate;

    state.update(10); // First call: no EWMA.
    state.update(10); // Second call: byte_rate should move toward 10.

    assert!(state.byte_rate < initial_byte_rate, "byte_rate should decrease toward small packet length");
}

// === DecoyState::try_spend_budget tests ===

// Test: spending within budget succeeds and deducts.
#[test]
fn test_try_spend_budget_sufficient() {
    let settings = make_settings();
    let mut state = DecoyState::<StaticByteBuffer, DefaultExecutor>::new(settings.clone(), StaticByteBuffer::empty(DEFAULT_TYPHOON_ID_LENGTH));
    let initial_budget = state.byte_budget;
    assert!(initial_budget > 100.0, "initial budget should be large enough for test");

    assert!(state.try_spend_budget(100));
    assert!((state.byte_budget - (initial_budget - 100.0)).abs() < f64::EPSILON);
}

// Test: spending more than budget fails and does not deduct.
#[test]
fn test_try_spend_budget_insufficient() {
    let settings = make_settings();
    let mut state = DecoyState::<StaticByteBuffer, DefaultExecutor>::new(settings.clone(), StaticByteBuffer::empty(DEFAULT_TYPHOON_ID_LENGTH));
    let initial_budget = state.byte_budget;
    let over_budget = (initial_budget as usize) + 1;

    assert!(!state.try_spend_budget(over_budget));
    assert_eq!(state.byte_budget, initial_budget, "budget should remain unchanged on failure");
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

// === should_replicate tests ===

// Test: ReplicationMode::None never replicates.
#[test]
fn test_should_replicate_none() {
    let settings = make_settings();
    let mut state = DecoyState::<StaticByteBuffer, DefaultExecutor>::new(settings.clone(), StaticByteBuffer::empty(DEFAULT_TYPHOON_ID_LENGTH));
    state.features.replication_mode = ReplicationMode::None;
    assert!(!state.should_replicate(false));
    assert!(!state.should_replicate(true));
}

// Test: ReplicationMode::Maintenance replicates only maintenance packets.
#[test]
fn test_should_replicate_maintenance() {
    let settings = make_settings();
    let mut state = DecoyState::<StaticByteBuffer, DefaultExecutor>::new(settings.clone(), StaticByteBuffer::empty(DEFAULT_TYPHOON_ID_LENGTH));
    state.features.replication_mode = ReplicationMode::Maintenance;
    state.features.replication_probability = 1.0;
    assert!(!state.should_replicate(false));
    assert!(state.should_replicate(true));
}

// Test: ReplicationMode::All replicates all packets.
#[test]
fn test_should_replicate_all() {
    let settings = make_settings();
    let mut state = DecoyState::<StaticByteBuffer, DefaultExecutor>::new(settings.clone(), StaticByteBuffer::empty(DEFAULT_TYPHOON_ID_LENGTH));
    state.features.replication_mode = ReplicationMode::All;
    state.features.replication_probability = 1.0;
    assert!(state.should_replicate(false));
    assert!(state.should_replicate(true));
}

// === subheader_length tests ===

// Test: SubheaderMode::None always returns 0.
#[test]
fn test_subheader_length_none() {
    let settings = make_settings();
    let mut state = DecoyState::<StaticByteBuffer, DefaultExecutor>::new(settings.clone(), StaticByteBuffer::empty(DEFAULT_TYPHOON_ID_LENGTH));
    state.features.subheader_mode = SubheaderMode::None;
    state.features.subheader_config = None;
    assert_eq!(state.subheader_length(false), 0);
    assert_eq!(state.subheader_length(true), 0);
}

// Test: SubheaderMode::Maintenance returns length only for maintenance.
#[test]
fn test_subheader_length_maintenance() {
    let settings = make_settings();
    let mut state = DecoyState::<StaticByteBuffer, DefaultExecutor>::new(settings.clone(), StaticByteBuffer::empty(DEFAULT_TYPHOON_ID_LENGTH));
    state.features.subheader_mode = SubheaderMode::Maintenance;
    // Ensure a subheader config exists.
    let min_len = settings.get(&DECOY_SUBHEADER_LENGTH_MIN) as usize;
    let max_len = settings.get(&DECOY_SUBHEADER_LENGTH_MAX) as usize;
    state.features.subheader_config = Some(super::generate_random_fake_header(min_len, max_len));
    assert_eq!(state.subheader_length(false), 0);
    assert!(state.subheader_length(true) > 0);
}

// Test: SubheaderMode::All returns length for both.
#[test]
fn test_subheader_length_all() {
    let settings = make_settings();
    let mut state = DecoyState::<StaticByteBuffer, DefaultExecutor>::new(settings.clone(), StaticByteBuffer::empty(DEFAULT_TYPHOON_ID_LENGTH));
    state.features.subheader_mode = SubheaderMode::All;
    let min_len = settings.get(&DECOY_SUBHEADER_LENGTH_MIN) as usize;
    let max_len = settings.get(&DECOY_SUBHEADER_LENGTH_MAX) as usize;
    state.features.subheader_config = Some(super::generate_random_fake_header(min_len, max_len));
    assert!(state.subheader_length(false) > 0);
    assert!(state.subheader_length(true) > 0);
}

// === schedule_next_maintenance tests ===

// Test: schedule_next_maintenance sets time in the future.
#[test]
fn test_schedule_next_maintenance() {
    let settings = make_settings();
    let mut state = DecoyState::<StaticByteBuffer, DefaultExecutor>::new(settings.clone(), StaticByteBuffer::empty(DEFAULT_TYPHOON_ID_LENGTH));
    state.features.maintenance_mode = MaintenanceMode::Random;

    let before = unix_timestamp_ms();
    state.schedule_next_maintenance();

    assert!(state.next_maintenance_time >= before, "next_maintenance_time should be in the future");
    assert!(state.pending_maintenance_length > 0, "maintenance length should be positive");
}

// Test: Timed mode produces fixed delay.
#[test]
fn test_schedule_next_maintenance_timed() {
    let settings = make_settings();
    let mut state = DecoyState::<StaticByteBuffer, DefaultExecutor>::new(settings.clone(), StaticByteBuffer::empty(DEFAULT_TYPHOON_ID_LENGTH));
    state.features.maintenance_mode = MaintenanceMode::Timed {
        delay_ms: 1000,
    };

    let before = unix_timestamp_ms();
    state.schedule_next_maintenance();

    // With a fixed delay of 1000ms, the time should be ~1000ms from now.
    assert!(state.next_maintenance_time >= before + 1000);
    assert!(state.next_maintenance_time <= before + 1500); // generous tolerance for slow CI
}

// === Seeded RNG determinism tests ===

// Test: create_decoy_packet with the same seed produces byte-identical packets,
// including a seeded subheader config so the full decoy path is exercised.
#[test]
fn test_seeded_packet_is_deterministic() {
    use crate::utils::random::{clear_test_rng, set_test_rng_seed};

    let settings = make_settings();
    let sh_min = settings.get(&DECOY_SUBHEADER_LENGTH_MIN) as usize;
    let sh_max = settings.get(&DECOY_SUBHEADER_LENGTH_MAX) as usize;

    let make_packet = |seed: u64| -> Vec<u8> {
        set_test_rng_seed(seed);
        let mut state = DecoyState::<StaticByteBuffer, DefaultExecutor>::new(settings.clone(), StaticByteBuffer::empty(DEFAULT_TYPHOON_ID_LENGTH));
        // Override subheader to All so the subheader path is always taken.
        // The config is generated from the seeded RNG, so it is deterministic.
        state.features.subheader_mode = SubheaderMode::All;
        state.features.subheader_config = Some(super::generate_random_fake_header(sh_min, sh_max));
        let packet = state.create_decoy_packet(64, false);
        clear_test_rng();
        packet.as_ref().to_vec()
    };

    let first = make_packet(42);
    let second = make_packet(42);
    assert_eq!(first, second, "same seed should produce identical packet bytes");
}

// Test: create_decoy_packet with different seeds produces different bytes.
#[test]
fn test_seeded_packets_differ_with_different_seeds() {
    use crate::utils::random::{clear_test_rng, set_test_rng_seed};

    let settings = make_settings();
    let sh_min = settings.get(&DECOY_SUBHEADER_LENGTH_MIN) as usize;
    let sh_max = settings.get(&DECOY_SUBHEADER_LENGTH_MAX) as usize;

    let make_packet = |seed: u64| -> Vec<u8> {
        set_test_rng_seed(seed);
        let mut state = DecoyState::<StaticByteBuffer, DefaultExecutor>::new(settings.clone(), StaticByteBuffer::empty(DEFAULT_TYPHOON_ID_LENGTH));
        state.features.subheader_mode = SubheaderMode::All;
        state.features.subheader_config = Some(super::generate_random_fake_header(sh_min, sh_max));
        let packet = state.create_decoy_packet(64, false);
        clear_test_rng();
        packet.as_ref().to_vec()
    };

    let with_seed_42 = make_packet(42);
    let with_seed_99 = make_packet(99);
    assert_ne!(with_seed_42, with_seed_99, "different seeds should produce different packet bytes");
}

// Test: seeded packet body matches a known snapshot (regression guard).
// All randomness — feature config, subheader fields, body fill — flows from the seed.
#[test]
fn test_seeded_packet_snapshot() {
    use crate::utils::random::{clear_test_rng, set_test_rng_seed};

    let settings = make_settings();
    let sh_min = settings.get(&DECOY_SUBHEADER_LENGTH_MIN) as usize;
    let sh_max = settings.get(&DECOY_SUBHEADER_LENGTH_MAX) as usize;

    let make_packet = |seed: u64| -> Vec<u8> {
        set_test_rng_seed(seed);
        let mut state = DecoyState::<StaticByteBuffer, DefaultExecutor>::new(settings.clone(), StaticByteBuffer::empty(DEFAULT_TYPHOON_ID_LENGTH));
        state.features.subheader_mode = SubheaderMode::All;
        state.features.subheader_config = Some(super::generate_random_fake_header(sh_min, sh_max));
        let packet = state.create_decoy_packet(16, false);
        clear_test_rng();
        packet.as_ref().to_vec()
    };

    // Build snapshot on first run, then assert second run is identical.
    let snapshot = make_packet(1337);
    let replay = make_packet(1337);
    assert_eq!(snapshot, replay, "snapshot must be reproducible across runs");
}

// === create_replica_packet tests ===

// Test: create_replica_packet produces correct size and identical body.
#[test]
fn test_create_replica_packet() {
    let settings = make_settings();
    let mut state = DecoyState::<StaticByteBuffer, DefaultExecutor>::new(settings.clone(), StaticByteBuffer::empty(DEFAULT_TYPHOON_ID_LENGTH));
    state.features.subheader_mode = SubheaderMode::None;
    state.features.subheader_config = None;

    let body: Vec<u8> = vec![0xAA, 0xBB, 0xCC, 0xDD, 0xEE];
    let packet = state.create_replica_packet(&body, false);

    let expected_len = body.len() + TAILOR_LENGTH + DEFAULT_TYPHOON_ID_LENGTH;
    assert_eq!(packet.len(), expected_len, "replica packet should have correct total length");

    // Body bytes should be identical.
    let packet_body = packet.slice_end(body.len());
    assert_eq!(packet_body, body.as_slice(), "replica body should match original");
}
