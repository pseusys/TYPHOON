use lazy_static::lazy_static;

use crate::bytes::{ByteBuffer, BytePool, DynamicByteBuffer, StaticByteBuffer};
use crate::settings::consts::{DEFAULT_TYPHOON_ID_LENGTH, TAILOR_LENGTH};
use crate::tailor::flags::{PacketFlags, ReturnCode};
use crate::tailor::structure::Tailor;

lazy_static! {
    static ref TEST_POOL: BytePool = BytePool::new(32, 256, 32, 4, 16);
}

/// Allocate an empty buffer from pool.
fn pool_empty(pool: &BytePool, size: usize) -> DynamicByteBuffer {
    pool.allocate_precise(size, 0, 0)
}

impl Tailor<StaticByteBuffer> {
    fn new_test() -> Self {
        Self {
            flags: PacketFlags::empty(),
            code: 0,
            time: 0,
            packet_number: 0,
            payload_length: 0,
            identity: StaticByteBuffer::empty(DEFAULT_TYPHOON_ID_LENGTH),
        }
    }
}

#[test]
fn test_tailor_roundtrip() {
    let identity = StaticByteBuffer::from_slice(&[0xAB; DEFAULT_TYPHOON_ID_LENGTH]);
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

    let decoded = Tailor::<StaticByteBuffer>::from_buffer(&tailor_buffer, DEFAULT_TYPHOON_ID_LENGTH);
    assert_eq!(decoded.flags, tailor.flags);
    assert_eq!(decoded.code, tailor.code);
    assert_eq!(decoded.time, tailor.time);
    assert_eq!(decoded.packet_number, tailor.packet_number);
    assert_eq!(decoded.payload_length, tailor.payload_length);
    assert_eq!(decoded.identity, tailor.identity);
}

#[test]
fn test_packet_number_components() {
    let mut tailor = Tailor::<StaticByteBuffer>::new_test();
    tailor.set_packet_number(0x12345678, 0xABCD0001);

    assert_eq!(tailor.timestamp(), 0x12345678);
    assert_eq!(tailor.incremental(), 0xABCD0001);
}

#[test]
fn test_data_tailor() {
    let identity = StaticByteBuffer::from_slice(&[1; DEFAULT_TYPHOON_ID_LENGTH]);
    let tailor = Tailor::<StaticByteBuffer>::data(identity, 512, 12345);

    assert!(tailor.flags.has_payload());
    assert_eq!(tailor.payload_length, 512);
}

#[test]
fn test_health_check_tailor() {
    let identity = StaticByteBuffer::from_slice(&[2; DEFAULT_TYPHOON_ID_LENGTH]);
    let tailor = Tailor::<StaticByteBuffer>::health_check(identity, 64000, 12345);

    assert!(!tailor.flags.has_payload());
    assert_eq!(tailor.time, 64000);
}

#[test]
fn test_shadowride_tailor() {
    let identity = StaticByteBuffer::from_slice(&[3; DEFAULT_TYPHOON_ID_LENGTH]);
    let tailor = Tailor::<StaticByteBuffer>::shadowride(identity, 256, 128000, 12345);

    assert!(tailor.flags.is_shadowride());
    assert!(tailor.flags.has_payload());
    assert_eq!(tailor.payload_length, 256);
    assert_eq!(tailor.time, 128000);
}

#[test]
fn test_decoy_tailor() {
    let identity = StaticByteBuffer::from_slice(&[4; DEFAULT_TYPHOON_ID_LENGTH]);
    let tailor = Tailor::<StaticByteBuffer>::decoy(identity, 12345);

    assert!(tailor.flags.is_discardable());
    assert!(!tailor.flags.has_payload());
}

#[test]
fn test_termination_tailor() {
    let identity = StaticByteBuffer::from_slice(&[5; DEFAULT_TYPHOON_ID_LENGTH]);
    let tailor = Tailor::<StaticByteBuffer>::termination(identity, ReturnCode::Success, 12345);

    assert!(tailor.flags.is_termination());
    assert_eq!(tailor.return_code(), ReturnCode::Success);
}
