use lazy_static::lazy_static;

use crate::bytes::{ByteBuffer, BytePool, DynamicByteBuffer};
use crate::settings::consts::{DEFAULT_TYPHOON_ID_LENGTH, TAILOR_LENGTH};
use crate::tailor::flags::{PacketFlags, ReturnCode};
use crate::tailor::structure::Tailor;

lazy_static! {
    static ref TEST_POOL: BytePool = BytePool::new(32, 256, 32, 4, 16);
}

/// Allocate a buffer from pool and fill with identity pattern.
fn pool_identity(pool: &BytePool, pattern: u8) -> DynamicByteBuffer {
    pool.allocate_precise_from_slice_with_capacity(&[pattern; DEFAULT_TYPHOON_ID_LENGTH], 0, 0)
}

/// Allocate an empty buffer from pool.
fn pool_empty(pool: &BytePool, size: usize) -> DynamicByteBuffer {
    pool.allocate_precise(size, 0, 0)
}

impl Tailor {
    fn new_test(pool: &BytePool, identity_length: usize) -> Self {
        Self {
            flags: PacketFlags::empty(),
            code: 0,
            time: 0,
            packet_number: 0,
            payload_length: 0,
            identity: pool_empty(pool, identity_length),
        }
    }
}

#[test]
fn test_tailor_roundtrip() {
    let identity = TEST_POOL.allocate_precise_from_slice_with_capacity(&[0xAB; DEFAULT_TYPHOON_ID_LENGTH], 0, 0);
    let tailor = Tailor {
        flags: PacketFlags::DATA,
        code: 42,
        time: 64000,
        packet_number: 0x12345678_ABCD0001,
        payload_length: 1024,
        identity,
    };

    let buffer = pool_empty(&TEST_POOL, TAILOR_LENGTH + DEFAULT_TYPHOON_ID_LENGTH);
    let tailor_buffer = tailor.to_buffer(buffer);
    assert_eq!(tailor_buffer.len(), TAILOR_LENGTH + DEFAULT_TYPHOON_ID_LENGTH);

    let decoded = Tailor::from_buffer(&tailor_buffer, DEFAULT_TYPHOON_ID_LENGTH);
    assert_eq!(decoded.flags, tailor.flags);
    assert_eq!(decoded.code, tailor.code);
    assert_eq!(decoded.time, tailor.time);
    assert_eq!(decoded.packet_number, tailor.packet_number);
    assert_eq!(decoded.payload_length, tailor.payload_length);
    assert_eq!(decoded.identity, tailor.identity);
}

#[test]
fn test_packet_number_components() {
    let mut tailor = Tailor::new_test(&TEST_POOL, DEFAULT_TYPHOON_ID_LENGTH);
    tailor.set_packet_number(0x12345678, 0xABCD0001);

    assert_eq!(tailor.timestamp(), 0x12345678);
    assert_eq!(tailor.incremental(), 0xABCD0001);
}

#[test]
fn test_data_tailor() {
    let identity = pool_identity(&TEST_POOL, 1);
    let tailor = Tailor::data(identity, 512, 12345);

    assert!(tailor.flags.has_payload());
    assert_eq!(tailor.payload_length, 512);
}

#[test]
fn test_health_check_tailor() {
    let identity = pool_identity(&TEST_POOL, 2);
    let tailor = Tailor::health_check(identity, 64000, 12345);

    assert!(!tailor.flags.has_payload());
    assert_eq!(tailor.time, 64000);
}

#[test]
fn test_shadowride_tailor() {
    let identity = pool_identity(&TEST_POOL, 3);
    let tailor = Tailor::shadowride(identity, 256, 128000, 12345);

    assert!(tailor.flags.is_shadowride());
    assert!(tailor.flags.has_payload());
    assert_eq!(tailor.payload_length, 256);
    assert_eq!(tailor.time, 128000);
}

#[test]
fn test_decoy_tailor() {
    let identity = pool_identity(&TEST_POOL, 4);
    let tailor = Tailor::decoy(identity, 12345);

    assert!(tailor.flags.is_discardable());
    assert!(!tailor.flags.has_payload());
}

#[test]
fn test_termination_tailor() {
    let identity = pool_identity(&TEST_POOL, 5);
    let tailor = Tailor::termination(identity, ReturnCode::Success, 12345);

    assert!(tailor.flags.is_termination());
    assert_eq!(tailor.return_code(), ReturnCode::Success);
}
