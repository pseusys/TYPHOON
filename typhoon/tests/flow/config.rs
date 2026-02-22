use lazy_static::lazy_static;

use crate::bytes::{ByteBuffer, BytePool};
use crate::flow::config::{FakeBodyMode, FakeHeaderConfig, FieldType, FieldTypeHolder, FlowConfig};
use crate::utils::time::unix_timestamp_ms;

lazy_static! {
    static ref TEST_POOL: BytePool = BytePool::new(32, 256, 32, 4, 16);
}

// === FakeBodyMode tests ===

// Test: Empty mode always returns 0 regardless of parameters.
#[test]
fn test_fake_body_empty_returns_zero() {
    let mode = FakeBodyMode::Empty;
    assert_eq!(mode.get_length(1500, 100, false), 0);
    assert_eq!(mode.get_length(1500, 100, true), 0);
    assert_eq!(mode.get_length(0, 0, false), 0);
}

// Test: Constant mode returns packet_length minus taken, clamped to max_packet_size.
#[test]
fn test_fake_body_constant_basic() {
    let mode = FakeBodyMode::Constant { packet_length: 500 };
    // min(1500, 500) - 100 = 400
    assert_eq!(mode.get_length(1500, 100, false), 400);
    assert_eq!(mode.get_length(1500, 100, true), 400);
}

// Test: Constant mode when taken equals packet_length returns 0.
#[test]
fn test_fake_body_constant_exact_fit() {
    let mode = FakeBodyMode::Constant { packet_length: 100 };
    assert_eq!(mode.get_length(1500, 100, false), 0);
}

// Test: Constant mode returns 0 when taken exceeds packet_length.
#[test]
fn test_fake_body_constant_returns_zero_when_taken_exceeds() {
    let mode = FakeBodyMode::Constant { packet_length: 50 };
    assert_eq!(mode.get_length(1500, 100, false), 0);
}

// Test: Random mode with service=true returns 0 for non-service packets.
#[test]
fn test_fake_body_random_service_only_skips_non_service() {
    let mode = FakeBodyMode::Random {
        min_length: 10,
        max_length: 200,
        service: true,
    };
    assert_eq!(mode.get_length(1500, 100, false), 0, "service-only mode should skip non-service packets");
}

// Test: Random mode with service=false pads within [min, min(max, body_space)) range.
#[test]
fn test_fake_body_random_non_service_pads() {
    let mode = FakeBodyMode::Random {
        min_length: 10,
        max_length: 200,
        service: false,
    };
    for _ in 0..20 {
        let len = mode.get_length(1500, 100, false);
        assert!(len >= 10 && len < 200, "length {len} should be in [10, 200)");
    }
}

// Test: Random mode with service=true pads service packets.
#[test]
fn test_fake_body_random_service_only_pads_service() {
    let mode = FakeBodyMode::Random {
        min_length: 10,
        max_length: 200,
        service: true,
    };
    for _ in 0..20 {
        let len = mode.get_length(1500, 100, true);
        assert!(len >= 10 && len < 200, "length {len} should be in [10, 200)");
    }
}

// Test: Random mode returns effective_max when body_space is too small for the range.
#[test]
fn test_fake_body_random_tight_space() {
    let mode = FakeBodyMode::Random {
        min_length: 50,
        max_length: 200,
        service: false,
    };
    // body_space = 60 - 50 = 10. effective_max = min(200, 10) = 10 <= min_length=50, returns 10.
    let len = mode.get_length(60, 50, false);
    assert_eq!(len, 10, "should return effective_max when space is tight");
}

// === FieldType tests ===

// Test: Constant field always returns the same value.
#[test]
fn test_field_type_constant() {
    let mut field: FieldType<u32> = FieldType::Constant { value: 42 };
    for _ in 0..10 {
        assert_eq!(field.apply(), 42);
    }
}

// Test: Incremental field increments by 1 each call.
#[test]
fn test_field_type_incremental() {
    let mut field: FieldType<u16> = FieldType::Incremental { value: 0 };
    assert_eq!(field.apply(), 1);
    assert_eq!(field.apply(), 2);
    assert_eq!(field.apply(), 3);
}

// Test: Incremental field starts from given initial value.
#[test]
fn test_field_type_incremental_from_offset() {
    let mut field: FieldType<u8> = FieldType::Incremental { value: 250 };
    assert_eq!(field.apply(), 251);
    assert_eq!(field.apply(), 252);
}

// Test: Random field produces values without panicking.
#[test]
fn test_field_type_random_runs() {
    let mut field: FieldType<u64> = FieldType::Random;
    for _ in 0..20 {
        let _ = field.apply();
    }
}

// Test: Volatile field with change_probability > 1.0 never changes (condition: rng > prob is never true).
#[test]
fn test_field_type_volatile_never_changes() {
    let mut field: FieldType<u32> = FieldType::Volatile {
        value: 99,
        change_probability: 2.0,
    };
    for _ in 0..50 {
        assert_eq!(field.apply(), 99);
    }
}

// Test: Switching field returns current value when switch time hasn't passed.
#[test]
fn test_field_type_switching_before_timeout() {
    let far_future = unix_timestamp_ms() + 1_000_000;
    let mut field: FieldType<u32> = FieldType::Switching {
        value: 7,
        next_switch: far_future,
        switch_timeout: 60_000,
    };
    assert_eq!(field.apply(), 7, "should return current value before timeout");
}

// Test: Switching field switches value after timeout.
#[test]
fn test_field_type_switching_after_timeout() {
    let mut field: FieldType<u32> = FieldType::Switching {
        value: 7,
        next_switch: 0, // Already in the past
        switch_timeout: 60_000,
    };
    // After timeout, value is regenerated - just verify it doesn't panic.
    let _ = field.apply();
}

// === FakeHeaderConfig tests ===

// Test: len() correctly sums field sizes.
#[test]
fn test_fake_header_config_len() {
    let config = FakeHeaderConfig {
        pattern: vec![
            FieldTypeHolder::U8(FieldType::Constant { value: 0 }),
            FieldTypeHolder::U16(FieldType::Constant { value: 0 }),
            FieldTypeHolder::U32(FieldType::Constant { value: 0 }),
            FieldTypeHolder::U64(FieldType::Constant { value: 0 }),
        ],
    };
    assert_eq!(config.len(), 1 + 2 + 4 + 8, "total header length should be 15 bytes");
}

// Test: len() with empty pattern returns 0.
#[test]
fn test_fake_header_config_len_empty() {
    let config = FakeHeaderConfig { pattern: vec![] };
    assert_eq!(config.len(), 0);
}

// Test: fill() writes constant values into buffer correctly.
#[test]
fn test_fake_header_config_fill_constants() {
    let mut config = FakeHeaderConfig {
        pattern: vec![
            FieldTypeHolder::U8(FieldType::Constant { value: 0xAB }),
            FieldTypeHolder::U16(FieldType::Constant { value: 0x1234 }),
            FieldTypeHolder::U32(FieldType::Constant { value: 0xDEADBEEF }),
        ],
    };

    let total_len = config.len(); // 1 + 2 + 4 = 7
    let buffer = TEST_POOL.allocate(Some(total_len));

    config.fill(buffer.clone());

    let data = buffer.slice();
    assert_eq!(data[0], 0xAB, "u8 field should be written at offset 0");
    assert_eq!(&data[1..3], &0x1234u16.to_be_bytes(), "u16 field should be big-endian at offset 1");
    assert_eq!(&data[3..7], &0xDEADBEEFu32.to_be_bytes(), "u32 field should be big-endian at offset 3");
}

// Test: fill() with incremental field writes incrementing values across calls.
#[test]
fn test_fake_header_config_fill_incremental() {
    let mut config = FakeHeaderConfig {
        pattern: vec![FieldTypeHolder::U8(FieldType::Incremental { value: 0 })],
    };

    let buffer = TEST_POOL.allocate(Some(1));

    config.fill(buffer.clone());
    assert_eq!(buffer.slice()[0], 1);

    config.fill(buffer.clone());
    assert_eq!(buffer.slice()[0], 2);
}

// === FlowConfig assertion tests ===

// Test: valid FlowConfig with Empty body passes assertion.
#[test]
fn test_flow_config_assert_empty_body_ok() {
    let config = FlowConfig::new(FakeBodyMode::Empty, FakeHeaderConfig::new(vec![]));
    assert!(config.assert(1500).is_ok());
}

// Test: valid FlowConfig with Constant body passes assertion.
#[test]
fn test_flow_config_assert_constant_body_ok() {
    let config = FlowConfig::new(
        FakeBodyMode::Constant { packet_length: 1000 },
        FakeHeaderConfig::new(vec![]),
    );
    assert!(config.assert(1500).is_ok());
}

// Test: Constant body packet_length exceeding max_packet_size fails assertion.
#[test]
fn test_flow_config_assert_constant_body_exceeds_max() {
    let config = FlowConfig::new(
        FakeBodyMode::Constant { packet_length: 2000 },
        FakeHeaderConfig::new(vec![]),
    );
    assert!(config.assert(1500).is_err());
}

// Test: valid Random body passes assertion.
#[test]
fn test_flow_config_assert_random_body_ok() {
    let config = FlowConfig::new(
        FakeBodyMode::Random { min_length: 10, max_length: 200, service: false },
        FakeHeaderConfig::new(vec![]),
    );
    assert!(config.assert(1500).is_ok());
}

// Test: Random body min_length > max_length fails assertion.
#[test]
fn test_flow_config_assert_random_body_min_exceeds_max() {
    let config = FlowConfig::new(
        FakeBodyMode::Random { min_length: 300, max_length: 100, service: false },
        FakeHeaderConfig::new(vec![]),
    );
    assert!(config.assert(1500).is_err());
}

// Test: fake header length exceeding max_packet_size fails assertion.
#[test]
fn test_flow_config_assert_header_exceeds_max() {
    let large_pattern: Vec<FieldTypeHolder> = (0..200)
        .map(|_| FieldTypeHolder::U64(FieldType::Constant { value: 0 }))
        .collect();
    let config = FlowConfig::new(
        FakeBodyMode::Empty,
        FakeHeaderConfig::new(large_pattern),
    );
    // 200 * 8 = 1600 > 1500
    assert!(config.assert(1500).is_err());
}

// Test: Constant body packet_length exactly at max_packet_size passes assertion.
#[test]
fn test_flow_config_assert_constant_body_at_max() {
    let config = FlowConfig::new(
        FakeBodyMode::Constant { packet_length: 1500 },
        FakeHeaderConfig::new(vec![]),
    );
    assert!(config.assert(1500).is_ok());
}

// Test: Random body with min_length == max_length passes assertion.
#[test]
fn test_flow_config_assert_random_body_equal_bounds() {
    let config = FlowConfig::new(
        FakeBodyMode::Random { min_length: 100, max_length: 100, service: false },
        FakeHeaderConfig::new(vec![]),
    );
    assert!(config.assert(1500).is_ok());
}
