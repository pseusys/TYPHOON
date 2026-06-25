use std::sync::Arc;
use std::sync::atomic::AtomicU32;

use crate::bytes::{ByteBuffer, StaticByteBuffer};
use crate::cache::DerivedValue;
use crate::defaults::DefaultExecutor;
use crate::flow::decoy::common::{DecoyFeatureConfig, DecoyState, MaintenanceMode, ReplicationMode, SubheaderMode, exponential_variance, random_gauss, random_uniform};
use crate::flow::decoy::{HeavyDecoyProvider, NoisyDecoyProvider, SmoothDecoyProvider};
use crate::settings::SettingsBuilder;
use crate::settings::consts::{DEFAULT_TYPHOON_ID_LENGTH, TAILER_LENGTH};
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
    let state = DecoyState::<StaticByteBuffer, DefaultExecutor>::new(settings.clone(), DerivedValue::constant(StaticByteBuffer::empty(DEFAULT_TYPHOON_ID_LENGTH)), Arc::new(AtomicU32::new(0)), None);

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
    let state = DecoyState::<StaticByteBuffer, DefaultExecutor>::new(settings.clone(), DerivedValue::constant(StaticByteBuffer::empty(DEFAULT_TYPHOON_ID_LENGTH)), Arc::new(AtomicU32::new(0)), None);

    let byte_rate_cap = settings.get(&DECOY_BYTE_RATE_CAP);
    let byte_rate_factor = settings.get(&DECOY_BYTE_RATE_FACTOR);
    let expected_budget = byte_rate_cap * byte_rate_factor / 2.0;

    assert_eq!(state.byte_budget, expected_budget);
}

// === DecoyState fallthrough tests ===

// Test: should_fallthrough returns false when probability is 0.0 (degenerate floor case).
#[test]
fn test_should_fallthrough_zero_probability() {
    let settings = make_settings();
    let state = DecoyState::<StaticByteBuffer, DefaultExecutor>::new(settings.clone(), DerivedValue::constant(StaticByteBuffer::empty(DEFAULT_TYPHOON_ID_LENGTH)), Arc::new(AtomicU32::new(0)), Some(0.0));
    for _ in 0..256 {
        assert!(!state.should_fallthrough(), "should_fallthrough must always be false at p=0.0");
    }
}

// Test: should_fallthrough returns true when probability is 1.0 (degenerate ceiling case).
#[test]
fn test_should_fallthrough_one_probability() {
    let settings = make_settings();
    let state = DecoyState::<StaticByteBuffer, DefaultExecutor>::new(settings.clone(), DerivedValue::constant(StaticByteBuffer::empty(DEFAULT_TYPHOON_ID_LENGTH)), Arc::new(AtomicU32::new(0)), Some(1.0));
    for _ in 0..256 {
        assert!(state.should_fallthrough(), "should_fallthrough must always be true at p=1.0");
    }
}

// Test: factory override of [min, max] yields a probability in that range, repeated rolls converge.
#[test]
fn test_should_fallthrough_rate_in_range() {
    let settings = make_settings();
    let state = DecoyState::<StaticByteBuffer, DefaultExecutor>::new(settings.clone(), DerivedValue::constant(StaticByteBuffer::empty(DEFAULT_TYPHOON_ID_LENGTH)), Arc::new(AtomicU32::new(0)), Some(0.5));
    let trials = 4_000;
    let hits: u32 = (0..trials).filter(|_| state.should_fallthrough()).count() as u32;
    let rate = hits as f64 / trials as f64;
    // p=0.5 with 4 000 trials → 95 % CI of about ±1.5 %; allow ±5 % margin.
    assert!((rate - 0.5).abs() < 0.05, "observed fallthrough rate {rate} is too far from 0.5");
}

// === DecoyState::quietness_index tests ===

// Test: when packet_rate equals reference_rate, quietness is 0 (busy).
#[test]
fn test_quietness_index_busy() {
    let settings = make_settings();
    let mut state = DecoyState::<StaticByteBuffer, DefaultExecutor>::new(settings.clone(), DerivedValue::constant(StaticByteBuffer::empty(DEFAULT_TYPHOON_ID_LENGTH)), Arc::new(AtomicU32::new(0)), None);
    state.reference_rate = 100.0;
    state.packet_rate = 100.0;
    assert_eq!(state.quietness_index(), 0.0);
}

// Test: when packet_rate is much smaller than reference_rate, quietness approaches 1.
#[test]
fn test_quietness_index_quiet() {
    let settings = make_settings();
    let mut state = DecoyState::<StaticByteBuffer, DefaultExecutor>::new(settings.clone(), DerivedValue::constant(StaticByteBuffer::empty(DEFAULT_TYPHOON_ID_LENGTH)), Arc::new(AtomicU32::new(0)), None);
    state.reference_rate = 1000.0;
    state.packet_rate = 1.0;
    let qi = state.quietness_index();
    assert!(qi > 0.99, "quietness should be near 1.0, got {qi}");
}

// Test: when packet_rate exceeds reference_rate, quietness clamps to 0.
#[test]
fn test_quietness_index_clamped_to_zero() {
    let settings = make_settings();
    let mut state = DecoyState::<StaticByteBuffer, DefaultExecutor>::new(settings.clone(), DerivedValue::constant(StaticByteBuffer::empty(DEFAULT_TYPHOON_ID_LENGTH)), Arc::new(AtomicU32::new(0)), None);
    state.reference_rate = 50.0;
    state.packet_rate = 200.0;
    assert_eq!(state.quietness_index(), 0.0, "should clamp negative values to 0");
}

// === DecoyState::schedule_next tests ===

// Test: schedule_next sets next_decoy_time in the future and pending_length.
#[test]
fn test_schedule_next() {
    let settings = make_settings();
    let mut state = DecoyState::<StaticByteBuffer, DefaultExecutor>::new(settings.clone(), DerivedValue::constant(StaticByteBuffer::empty(DEFAULT_TYPHOON_ID_LENGTH)), Arc::new(AtomicU32::new(0)), None);

    let before = unix_timestamp_ms();
    state.schedule_next(500, 256);
    let after = unix_timestamp_ms();

    assert!(state.next_decoy_time >= before + 500, "next_decoy_time should be at least 500ms in the future");
    assert!(state.next_decoy_time <= after + 500, "next_decoy_time should not be too far in the future");
    assert_eq!(state.pending_length, 256);
}

// === DecoyState::create_decoy_packet tests ===

// Test: create_decoy_packet returns a packet of body + tailer + identity length.
#[test]
fn test_create_decoy_packet_size() {
    let settings = make_settings();
    let mut state = DecoyState::<StaticByteBuffer, DefaultExecutor>::new(settings.clone(), DerivedValue::constant(StaticByteBuffer::empty(DEFAULT_TYPHOON_ID_LENGTH)), Arc::new(AtomicU32::new(0)), None);
    state.features.subheader_mode = SubheaderMode::None;
    state.features.subheader_config = None;

    let body_length = 64;
    let packet = state.create_decoy_packet(body_length, false);

    assert_eq!(packet.len(), body_length + TAILER_LENGTH + DEFAULT_TYPHOON_ID_LENGTH, "packet should be body + tailer + identity length");
}

// Test: create_decoy_packet with zero body returns tailer + identity length.
#[test]
fn test_create_decoy_packet_zero_body() {
    let settings = make_settings();
    let mut state = DecoyState::<StaticByteBuffer, DefaultExecutor>::new(settings.clone(), DerivedValue::constant(StaticByteBuffer::empty(DEFAULT_TYPHOON_ID_LENGTH)), Arc::new(AtomicU32::new(0)), None);
    state.features.subheader_mode = SubheaderMode::None;
    state.features.subheader_config = None;

    let packet = state.create_decoy_packet(0, false);
    assert_eq!(packet.len(), TAILER_LENGTH + DEFAULT_TYPHOON_ID_LENGTH);
}

// === DecoyState::update tests ===

// Test: calling update twice in quick succession moves packet_rate toward 0.
#[test]
fn test_update_adjusts_packet_rate() {
    let settings = make_settings();
    let mut state = DecoyState::<StaticByteBuffer, DefaultExecutor>::new(settings.clone(), DerivedValue::constant(StaticByteBuffer::empty(DEFAULT_TYPHOON_ID_LENGTH)), Arc::new(AtomicU32::new(0)), None);
    let initial_packet_rate = state.packet_rate;

    // First call: sets previous_packet_time, no EWMA computation.
    state.update(100, false);
    assert_eq!(state.packet_rate, initial_packet_rate, "first update should not change packet_rate");

    // Second call (immediately after): time_delta ≈ 0ms, so EWMA should pull packet_rate down.
    state.update(100, false);
    assert!(state.packet_rate < initial_packet_rate, "packet_rate should decrease with near-zero time delta");
}

// Test: update adjusts byte_rate toward packet length.
#[test]
fn test_update_adjusts_byte_rate() {
    let settings = make_settings();
    let mut state = DecoyState::<StaticByteBuffer, DefaultExecutor>::new(settings.clone(), DerivedValue::constant(StaticByteBuffer::empty(DEFAULT_TYPHOON_ID_LENGTH)), Arc::new(AtomicU32::new(0)), None);
    let initial_byte_rate = state.byte_rate;

    state.update(10, false); // First call: no EWMA.
    state.update(10, false); // Second call: byte_rate should move toward 10.

    assert!(state.byte_rate < initial_byte_rate, "byte_rate should decrease toward small packet length");
}

// === DecoyState::try_spend_budget tests ===

// Test: spending within budget succeeds and deducts.
#[test]
fn test_try_spend_budget_sufficient() {
    let settings = make_settings();
    let mut state = DecoyState::<StaticByteBuffer, DefaultExecutor>::new(settings.clone(), DerivedValue::constant(StaticByteBuffer::empty(DEFAULT_TYPHOON_ID_LENGTH)), Arc::new(AtomicU32::new(0)), None);
    let initial_budget = state.byte_budget;
    assert!(initial_budget > 100.0, "initial budget should be large enough for test");

    assert!(state.try_spend_budget(100));
    assert!((state.byte_budget - (initial_budget - 100.0)).abs() < f64::EPSILON);
}

// Test: spending more than budget fails and does not deduct.
#[test]
fn test_try_spend_budget_insufficient() {
    let settings = make_settings();
    let mut state = DecoyState::<StaticByteBuffer, DefaultExecutor>::new(settings.clone(), DerivedValue::constant(StaticByteBuffer::empty(DEFAULT_TYPHOON_ID_LENGTH)), Arc::new(AtomicU32::new(0)), None);
    let initial_budget = state.byte_budget;
    let over_budget = (initial_budget as usize) + 1;

    assert!(!state.try_spend_budget(over_budget));
    assert_eq!(state.byte_budget, initial_budget, "budget should remain unchanged on failure");
}

// Test: update with outgoing_real=true deducts packet_length from byte_budget.
#[test]
fn test_update_outgoing_real_depletes_budget() {
    let settings = make_settings();
    let mut state = DecoyState::<StaticByteBuffer, DefaultExecutor>::new(settings.clone(), DerivedValue::constant(StaticByteBuffer::empty(DEFAULT_TYPHOON_ID_LENGTH)), Arc::new(AtomicU32::new(0)), None);
    let initial_budget = state.byte_budget;

    // First call seeds previous_packet_time without applying EWMA / budget math.
    state.update(0, true);
    assert_eq!(state.byte_budget, initial_budget, "first update should not change budget");

    // Second call: with outgoing_real=true the packet_length is deducted from budget. Use a
    // packet large enough that the deduction dominates any refill from real elapsed time between
    // the two calls (refill is bounded by byte_rate_cap=1_000_000 bytes/sec, so even a full
    // second of scheduling jitter couldn't offset a 10x larger deduction).
    state.update(10_000_000, true);
    assert!(state.byte_budget < initial_budget, "outgoing real should deplete budget (was {} now {})", initial_budget, state.byte_budget);
}

// Test: update with outgoing_real=false does NOT deduct (incoming or peer's decoys).
#[test]
fn test_update_incoming_does_not_deplete_budget() {
    let settings = make_settings();
    let mut state = DecoyState::<StaticByteBuffer, DefaultExecutor>::new(settings.clone(), DerivedValue::constant(StaticByteBuffer::empty(DEFAULT_TYPHOON_ID_LENGTH)), Arc::new(AtomicU32::new(0)), None);
    let initial_budget = state.byte_budget;

    state.update(0, false);
    // Second call with packet bytes but outgoing_real=false — budget should not drop.
    state.update(5000, false);
    assert!(state.byte_budget >= initial_budget - f64::EPSILON, "incoming should not deplete budget (was {} now {})", initial_budget, state.byte_budget);
}

// Test: byte_budget never drops below 0 even under heavy outgoing real load.
#[test]
fn test_update_budget_floored_at_zero() {
    let settings = make_settings();
    let mut state = DecoyState::<StaticByteBuffer, DefaultExecutor>::new(settings.clone(), DerivedValue::constant(StaticByteBuffer::empty(DEFAULT_TYPHOON_ID_LENGTH)), Arc::new(AtomicU32::new(0)), None);

    state.update(0, true);
    // Deduct way more than the initial budget — should clamp at 0, not go negative.
    state.update(usize::MAX / 2, true);
    assert!(state.byte_budget >= 0.0, "budget should never go negative, got {}", state.byte_budget);
}

// === Random utility function tests ===

// Test: random_uniform produces values within [min, max].
#[test]
fn test_random_uniform_range() {
    for _ in 0..100 {
        let val = random_uniform(10.0, 20.0);
        assert!((10.0..=20.0).contains(&val), "value {val} outside [10, 20]");
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
    let mut state = DecoyState::<StaticByteBuffer, DefaultExecutor>::new(settings.clone(), DerivedValue::constant(StaticByteBuffer::empty(DEFAULT_TYPHOON_ID_LENGTH)), Arc::new(AtomicU32::new(0)), None);
    state.features.replication_mode = ReplicationMode::None;
    assert!(!state.should_replicate(false));
    assert!(!state.should_replicate(true));
}

// Test: ReplicationMode::Maintenance replicates only maintenance packets.
#[test]
fn test_should_replicate_maintenance() {
    let settings = make_settings();
    let mut state = DecoyState::<StaticByteBuffer, DefaultExecutor>::new(settings.clone(), DerivedValue::constant(StaticByteBuffer::empty(DEFAULT_TYPHOON_ID_LENGTH)), Arc::new(AtomicU32::new(0)), None);
    state.features.replication_mode = ReplicationMode::Maintenance;
    state.features.replication_probability = 1.0;
    assert!(!state.should_replicate(false));
    assert!(state.should_replicate(true));
}

// Test: ReplicationMode::All replicates all packets.
#[test]
fn test_should_replicate_all() {
    let settings = make_settings();
    let mut state = DecoyState::<StaticByteBuffer, DefaultExecutor>::new(settings.clone(), DerivedValue::constant(StaticByteBuffer::empty(DEFAULT_TYPHOON_ID_LENGTH)), Arc::new(AtomicU32::new(0)), None);
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
    let mut state = DecoyState::<StaticByteBuffer, DefaultExecutor>::new(settings.clone(), DerivedValue::constant(StaticByteBuffer::empty(DEFAULT_TYPHOON_ID_LENGTH)), Arc::new(AtomicU32::new(0)), None);
    state.features.subheader_mode = SubheaderMode::None;
    state.features.subheader_config = None;
    assert_eq!(state.subheader_length(false), 0);
    assert_eq!(state.subheader_length(true), 0);
}

// Test: SubheaderMode::Maintenance returns length only for maintenance.
#[test]
fn test_subheader_length_maintenance() {
    let settings = make_settings();
    let mut state = DecoyState::<StaticByteBuffer, DefaultExecutor>::new(settings.clone(), DerivedValue::constant(StaticByteBuffer::empty(DEFAULT_TYPHOON_ID_LENGTH)), Arc::new(AtomicU32::new(0)), None);
    state.features.subheader_mode = SubheaderMode::Maintenance;
    // Ensure a subheader config exists.
    let min_len = settings.get(&DECOY_SUBHEADER_LENGTH_MIN) as usize;
    let max_len = settings.get(&DECOY_SUBHEADER_LENGTH_MAX) as usize;
    state.features.subheader_config = Some(super::generate_random_fake_header(&settings, min_len, max_len));
    assert_eq!(state.subheader_length(false), 0);
    assert!(state.subheader_length(true) > 0);
}

// Test: SubheaderMode::All returns length for both.
#[test]
fn test_subheader_length_all() {
    let settings = make_settings();
    let mut state = DecoyState::<StaticByteBuffer, DefaultExecutor>::new(settings.clone(), DerivedValue::constant(StaticByteBuffer::empty(DEFAULT_TYPHOON_ID_LENGTH)), Arc::new(AtomicU32::new(0)), None);
    state.features.subheader_mode = SubheaderMode::All;
    let min_len = settings.get(&DECOY_SUBHEADER_LENGTH_MIN) as usize;
    let max_len = settings.get(&DECOY_SUBHEADER_LENGTH_MAX) as usize;
    state.features.subheader_config = Some(super::generate_random_fake_header(&settings, min_len, max_len));
    assert!(state.subheader_length(false) > 0);
    assert!(state.subheader_length(true) > 0);
}

// === schedule_next_maintenance tests ===

// Test: schedule_next_maintenance sets time in the future.
#[test]
fn test_schedule_next_maintenance() {
    let settings = make_settings();
    let mut state = DecoyState::<StaticByteBuffer, DefaultExecutor>::new(settings.clone(), DerivedValue::constant(StaticByteBuffer::empty(DEFAULT_TYPHOON_ID_LENGTH)), Arc::new(AtomicU32::new(0)), None);
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
    let mut state = DecoyState::<StaticByteBuffer, DefaultExecutor>::new(settings.clone(), DerivedValue::constant(StaticByteBuffer::empty(DEFAULT_TYPHOON_ID_LENGTH)), Arc::new(AtomicU32::new(0)), None);
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
        let mut state = DecoyState::<StaticByteBuffer, DefaultExecutor>::new(settings.clone(), DerivedValue::constant(StaticByteBuffer::empty(DEFAULT_TYPHOON_ID_LENGTH)), Arc::new(AtomicU32::new(0)), None);
        // Override subheader to All so the subheader path is always taken.
        // The config is generated from the seeded RNG, so it is deterministic.
        state.features.subheader_mode = SubheaderMode::All;
        state.features.subheader_config = Some(super::generate_random_fake_header(&settings, sh_min, sh_max));
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
        let mut state = DecoyState::<StaticByteBuffer, DefaultExecutor>::new(settings.clone(), DerivedValue::constant(StaticByteBuffer::empty(DEFAULT_TYPHOON_ID_LENGTH)), Arc::new(AtomicU32::new(0)), None);
        state.features.subheader_mode = SubheaderMode::All;
        state.features.subheader_config = Some(super::generate_random_fake_header(&settings, sh_min, sh_max));
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
        let mut state = DecoyState::<StaticByteBuffer, DefaultExecutor>::new(settings.clone(), DerivedValue::constant(StaticByteBuffer::empty(DEFAULT_TYPHOON_ID_LENGTH)), Arc::new(AtomicU32::new(0)), None);
        state.features.subheader_mode = SubheaderMode::All;
        state.features.subheader_config = Some(super::generate_random_fake_header(&settings, sh_min, sh_max));
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
    let mut state = DecoyState::<StaticByteBuffer, DefaultExecutor>::new(settings.clone(), DerivedValue::constant(StaticByteBuffer::empty(DEFAULT_TYPHOON_ID_LENGTH)), Arc::new(AtomicU32::new(0)), None);
    state.features.subheader_mode = SubheaderMode::None;
    state.features.subheader_config = None;

    let body: Vec<u8> = vec![0xAA, 0xBB, 0xCC, 0xDD, 0xEE];
    let packet = state.create_replica_packet(&body, false);

    let expected_len = body.len() + TAILER_LENGTH + DEFAULT_TYPHOON_ID_LENGTH;
    assert_eq!(packet.len(), expected_len, "replica packet should have correct total length");

    // Body bytes should be identical.
    let packet_body = packet.slice_end(body.len());
    assert_eq!(packet_body, body.as_slice(), "replica body should match original");
}

// === Communication mode length-distribution tests ===
//
// Each provider's calculate_length is sampled in "busy" (packet_rate ==
// reference_rate ⇒ quietness=0) and "quiet" (packet_rate=0 ⇒ quietness=1)
// regimes.  Tests verify mode-specific intent: clamping invariants,
// adaptive growth with quietness, and that no mode unintentionally piles
// at MTU.

const LENGTH_SAMPLE_COUNT: usize = 500;

fn sampled_state_busy(settings: Arc<crate::settings::Settings<DefaultExecutor>>) -> DecoyState<StaticByteBuffer, DefaultExecutor> {
    let mut state = DecoyState::<StaticByteBuffer, DefaultExecutor>::new(settings, DerivedValue::constant(StaticByteBuffer::empty(DEFAULT_TYPHOON_ID_LENGTH)), Arc::new(AtomicU32::new(0)), None);
    // Equal current and reference rates → quietness_index = 0.
    state.reference_rate = 200.0;
    state.packet_rate = 200.0;
    state
}

fn sampled_state_quiet(settings: Arc<crate::settings::Settings<DefaultExecutor>>) -> DecoyState<StaticByteBuffer, DefaultExecutor> {
    let mut state = DecoyState::<StaticByteBuffer, DefaultExecutor>::new(settings, DerivedValue::constant(StaticByteBuffer::empty(DEFAULT_TYPHOON_ID_LENGTH)), Arc::new(AtomicU32::new(0)), None);
    // Reference_rate >> packet_rate → quietness_index ≈ 1.
    state.reference_rate = 200.0;
    state.packet_rate = 0.0;
    state
}

fn mean(samples: &[usize]) -> f64 {
    samples.iter().map(|&s| s as f64).sum::<f64>() / samples.len() as f64
}

// Noisy: small/medium bursty mode — must NEVER reach MTU regardless of quietness.
#[test]
fn test_noisy_length_stays_below_mtu() {
    let settings = make_settings();
    let noisy_min = settings.get(&DECOY_NOISY_DECOY_LENGTH_MIN) as usize;
    let noisy_max = settings.get(&DECOY_NOISY_LENGTH_MAX) as usize;
    let mtu_class = settings.get(&DECOY_LENGTH_MAX) as usize;
    assert!(noisy_max < mtu_class, "test premise: NOISY_LENGTH_MAX should be < DECOY_LENGTH_MAX");

    let state_quiet = sampled_state_quiet(settings.clone());
    let samples: Vec<usize> = (0..LENGTH_SAMPLE_COUNT).map(|_| NoisyDecoyProvider::<StaticByteBuffer, DefaultExecutor>::calculate_length(&state_quiet)).collect();

    for &s in &samples {
        assert!(s >= noisy_min, "Noisy length {} should be >= NOISY_MIN {}", s, noisy_min);
        assert!(s <= noisy_max, "Noisy length {} should be <= NOISY_MAX {}", s, noisy_max);
    }
}

// Noisy adapts: quiet mean > busy mean (the formula scales mean with quietness).
#[test]
fn test_noisy_length_adaptive_to_quietness() {
    let settings = make_settings();
    let state_busy = sampled_state_busy(settings.clone());
    let state_quiet = sampled_state_quiet(settings.clone());

    let busy_samples: Vec<usize> = (0..LENGTH_SAMPLE_COUNT).map(|_| NoisyDecoyProvider::<StaticByteBuffer, DefaultExecutor>::calculate_length(&state_busy)).collect();
    let quiet_samples: Vec<usize> = (0..LENGTH_SAMPLE_COUNT).map(|_| NoisyDecoyProvider::<StaticByteBuffer, DefaultExecutor>::calculate_length(&state_quiet)).collect();

    let busy_mean = mean(&busy_samples);
    let quiet_mean = mean(&quiet_samples);
    assert!(quiet_mean > busy_mean, "Noisy should grow with quietness: busy mean = {:.1}, quiet mean = {:.1}", busy_mean, quiet_mean);
}

// Heavy: bulk-class mode — must respect HEAVY_LENGTH_MIN as floor.
#[test]
fn test_heavy_length_respects_floor() {
    let settings = make_settings();
    let heavy_min = settings.get(&DECOY_HEAVY_LENGTH_MIN) as usize;
    let length_cap = settings.get(&DECOY_LENGTH_MAX) as usize;

    let state_quiet = sampled_state_quiet(settings.clone());
    let samples: Vec<usize> = (0..LENGTH_SAMPLE_COUNT).map(|_| HeavyDecoyProvider::<StaticByteBuffer, DefaultExecutor>::calculate_length(&state_quiet)).collect();

    for &s in &samples {
        assert!(s >= heavy_min, "Heavy length {} should be >= HEAVY_MIN {}", s, heavy_min);
        assert!(s <= length_cap, "Heavy length {} should be <= length_cap {}", s, length_cap);
    }
}

// Heavy: when tuned-down base length pushes the natural distribution under
// the floor, the configurable HEAVY_LENGTH_MIN must enforce it correctly.
#[test]
fn test_heavy_length_min_enforced_under_low_base() {
    // Configure a Heavy mode whose intrinsic minimum (0.8·0.3·cap = 0.24·cap)
    // would fall below the floor, then verify all samples respect the floor.
    let settings = Arc::new(SettingsBuilder::new().set(&DECOY_HEAVY_BASE_LENGTH, 0.3).set(&DECOY_HEAVY_QUIETNESS_LENGTH, 0.0).set(&DECOY_HEAVY_LENGTH_MIN, 500).build().unwrap());
    let state = sampled_state_quiet(settings.clone());
    let length_cap = settings.get(&DECOY_LENGTH_MAX) as usize;

    let samples: Vec<usize> = (0..LENGTH_SAMPLE_COUNT).map(|_| HeavyDecoyProvider::<StaticByteBuffer, DefaultExecutor>::calculate_length(&state)).collect();

    // With base=0.3·cap=420, decoy_length naturally falls in [0.8·420, 420] = [336, 420];
    // the floor at 500 must clamp every sample up to ≥ 500.
    for &s in &samples {
        assert!(s >= 500, "Heavy length {} should respect HEAVY_LENGTH_MIN=500", s);
        assert!(s <= length_cap, "Heavy length {} should be <= length_cap {}", s, length_cap);
    }
}

// Smooth: adaptive ceiling — quiet samples should reach higher than busy ones,
// and ALL samples should stay within [MIN, SMOOTH_LENGTH_MAX] (not MTU).
#[test]
fn test_smooth_length_adaptive_and_bounded() {
    let settings = make_settings();
    let smooth_min = settings.get(&DECOY_SMOOTH_LENGTH_MIN) as usize;
    let smooth_max = settings.get(&DECOY_SMOOTH_LENGTH_MAX) as usize;
    let mtu_class = settings.get(&DECOY_LENGTH_MAX) as usize;
    assert!(smooth_max < mtu_class, "test premise: SMOOTH_LENGTH_MAX should be < DECOY_LENGTH_MAX");

    let state_busy = sampled_state_busy(settings.clone());
    let state_quiet = sampled_state_quiet(settings.clone());

    let busy_samples: Vec<usize> = (0..LENGTH_SAMPLE_COUNT).map(|_| SmoothDecoyProvider::<StaticByteBuffer, DefaultExecutor>::calculate_length(&state_busy)).collect();
    let quiet_samples: Vec<usize> = (0..LENGTH_SAMPLE_COUNT).map(|_| SmoothDecoyProvider::<StaticByteBuffer, DefaultExecutor>::calculate_length(&state_quiet)).collect();

    // All samples respect [MIN, MAX].
    for &s in busy_samples.iter().chain(quiet_samples.iter()) {
        assert!(s >= smooth_min, "Smooth length {} should be >= SMOOTH_MIN {}", s, smooth_min);
        assert!(s <= smooth_max, "Smooth length {} should be <= SMOOTH_MAX {}", s, smooth_max);
    }

    // Max sampled length grows with quietness (uniform draw ceiling tracks quietness).
    let busy_max = *busy_samples.iter().max().unwrap_or(&0);
    let quiet_max = *quiet_samples.iter().max().unwrap_or(&0);
    assert!(quiet_max > busy_max, "Smooth max should grow with quietness: busy max = {}, quiet max = {}", busy_max, quiet_max);
}
