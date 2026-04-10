use std::sync::LazyLock;

use crate::bytes::{ByteBuffer, BytePool, DynamicByteBuffer, StaticByteBuffer};
use crate::settings::consts::{DEFAULT_TYPHOON_ID_LENGTH, TAILOR_LENGTH};
use crate::tailor::flags::{PacketFlags, ReturnCode};
use crate::tailor::structure::Tailor;

static TEST_POOL: LazyLock<BytePool> = LazyLock::new(|| BytePool::new(32, 256, 32, 4, 16));

/// Allocate an empty buffer from pool.
fn pool_empty(pool: &BytePool, size: usize) -> DynamicByteBuffer {
    pool.allocate_precise(size, 0, 0)
}

#[test]
fn test_tailor_roundtrip() {
    let identity = StaticByteBuffer::from_slice(&[0xAB; DEFAULT_TYPHOON_ID_LENGTH]);
    let buffer = pool_empty(&TEST_POOL, TAILOR_LENGTH + DEFAULT_TYPHOON_ID_LENGTH);
    let tailor = Tailor::<StaticByteBuffer>::data(buffer, &identity, 1024, 0x12345678_ABCD0001);
    tailor.set_code(42);
    tailor.set_flags(PacketFlags::DATA);
    tailor.set_time(64000);

    let tailor_buffer = tailor.buffer().clone();
    assert_eq!(tailor_buffer.len(), TAILOR_LENGTH + DEFAULT_TYPHOON_ID_LENGTH);

    let decoded = Tailor::<StaticByteBuffer>::new(tailor_buffer);
    assert_eq!(decoded.flags(), tailor.flags());
    assert_eq!(decoded.code(), tailor.code());
    assert_eq!(decoded.time(), tailor.time());
    assert_eq!(decoded.packet_number(), tailor.packet_number());
    assert_eq!(decoded.payload_length(), tailor.payload_length());
    assert_eq!(decoded.identity(), tailor.identity());
}

#[test]
fn test_packet_number_components() {
    let identity = StaticByteBuffer::empty(DEFAULT_TYPHOON_ID_LENGTH);
    let buffer = pool_empty(&TEST_POOL, TAILOR_LENGTH + DEFAULT_TYPHOON_ID_LENGTH);
    let tailor = Tailor::<StaticByteBuffer>::data(buffer, &identity, 0, 0);
    tailor.set_packet_number(0x12345678, 0xABCD0001);

    assert_eq!(tailor.timestamp(), 0x12345678);
    assert_eq!(tailor.incremental(), 0xABCD0001);
}

#[test]
fn test_data_tailor() {
    let identity = StaticByteBuffer::from_slice(&[1; DEFAULT_TYPHOON_ID_LENGTH]);
    let buffer = pool_empty(&TEST_POOL, TAILOR_LENGTH + DEFAULT_TYPHOON_ID_LENGTH);
    let tailor = Tailor::<StaticByteBuffer>::data(buffer, &identity, 512, 12345);

    assert!(tailor.flags().has_payload());
    assert_eq!(tailor.payload_length(), 512);
}

#[test]
fn test_health_check_tailor() {
    let identity = StaticByteBuffer::from_slice(&[2; DEFAULT_TYPHOON_ID_LENGTH]);
    let buffer = pool_empty(&TEST_POOL, TAILOR_LENGTH + DEFAULT_TYPHOON_ID_LENGTH);
    let tailor = Tailor::<StaticByteBuffer>::health_check(buffer, &identity, 64000, 12345);

    assert!(!tailor.flags().has_payload());
    assert_eq!(tailor.time(), 64000);
}

#[test]
fn test_shadowride_tailor() {
    let identity = StaticByteBuffer::from_slice(&[3; DEFAULT_TYPHOON_ID_LENGTH]);
    let buffer = pool_empty(&TEST_POOL, TAILOR_LENGTH + DEFAULT_TYPHOON_ID_LENGTH);
    let tailor = Tailor::<StaticByteBuffer>::shadowride(buffer, &identity, 256, 128000, 12345);

    assert!(tailor.flags().is_shadowride());
    assert!(tailor.flags().has_payload());
    assert_eq!(tailor.payload_length(), 256);
    assert_eq!(tailor.time(), 128000);
}

#[test]
fn test_handshake_tailor() {
    let identity = StaticByteBuffer::from_slice(&[6; DEFAULT_TYPHOON_ID_LENGTH]);
    let buffer = pool_empty(&TEST_POOL, TAILOR_LENGTH + DEFAULT_TYPHOON_ID_LENGTH);
    let tailor = Tailor::<StaticByteBuffer>::handshake(buffer, &identity, 42, 5000, 12345, 100);

    assert_eq!(tailor.flags(), PacketFlags::HANDSHAKE);
    assert!(!tailor.flags().is_discardable());
    assert!(!tailor.flags().has_payload());
    assert_eq!(tailor.code(), 42);
    assert_eq!(tailor.time(), 5000);
}

#[test]
fn test_decoy_tailor() {
    let identity = StaticByteBuffer::from_slice(&[4; DEFAULT_TYPHOON_ID_LENGTH]);
    let buffer = pool_empty(&TEST_POOL, TAILOR_LENGTH + DEFAULT_TYPHOON_ID_LENGTH);
    let tailor = Tailor::<StaticByteBuffer>::decoy(buffer, &identity, 12345);

    assert!(tailor.flags().is_discardable());
    assert!(!tailor.flags().has_payload());
}

#[test]
fn test_termination_tailor() {
    let identity = StaticByteBuffer::from_slice(&[5; DEFAULT_TYPHOON_ID_LENGTH]);
    let buffer = pool_empty(&TEST_POOL, TAILOR_LENGTH + DEFAULT_TYPHOON_ID_LENGTH);
    let tailor = Tailor::<StaticByteBuffer>::termination(buffer, &identity, ReturnCode::Success, 12345);

    assert!(tailor.flags().is_termination());
    assert_eq!(tailor.return_code(), ReturnCode::Success);
}

#[test]
fn test_debug_probe_tailor_roundtrip() {
    let identity = StaticByteBuffer::from_slice(&[7; DEFAULT_TYPHOON_ID_LENGTH]);
    let buffer = pool_empty(&TEST_POOL, TAILOR_LENGTH + DEFAULT_TYPHOON_ID_LENGTH);
    let tailor = Tailor::<StaticByteBuffer>::debug_probe(buffer, &identity, 42, 0xDEADBEEF, 99, 1, 1024);

    assert_eq!(tailor.flags(), PacketFlags::DATA);
    assert_eq!(tailor.debug_ref_num(), 42);
    assert_eq!(tailor.debug_send_time(), 0xDEADBEEF);
    assert_eq!(tailor.debug_sequence(), 99);
    assert_eq!(tailor.debug_phase(), 1);
    assert_eq!(tailor.payload_length(), 1024);
}

#[test]
fn test_debug_probe_accessors_all_phases() {
    let identity = StaticByteBuffer::empty(DEFAULT_TYPHOON_ID_LENGTH);

    // Phase 0: reachability
    let buf = pool_empty(&TEST_POOL, TAILOR_LENGTH + DEFAULT_TYPHOON_ID_LENGTH);
    let t = Tailor::<StaticByteBuffer>::debug_probe(buf, &identity, 0, 1000, 0, 0, 0);
    assert_eq!(t.debug_phase(), 0);
    assert_eq!(t.debug_sequence(), 0);

    // Phase 1: return time
    let buf = pool_empty(&TEST_POOL, TAILOR_LENGTH + DEFAULT_TYPHOON_ID_LENGTH);
    let t = Tailor::<StaticByteBuffer>::debug_probe(buf, &identity, 1, 2000, 1, 1, 0);
    assert_eq!(t.debug_phase(), 1);
    assert_eq!(t.debug_sequence(), 1);

    // Phase 2: throughput
    let buf = pool_empty(&TEST_POOL, TAILOR_LENGTH + DEFAULT_TYPHOON_ID_LENGTH);
    let t = Tailor::<StaticByteBuffer>::debug_probe(buf, &identity, 255, 3000, 9, 2, 65016);
    assert_eq!(t.debug_ref_num(), 255);
    assert_eq!(t.debug_send_time(), 3000);
    assert_eq!(t.debug_sequence(), 9);
    assert_eq!(t.debug_phase(), 2);
    assert_eq!(t.payload_length(), 65016);
}

#[test]
fn test_debug_probe_pn_encoding() {
    // Verify upper/lower 32-bit split of the packet number field.
    let identity = StaticByteBuffer::empty(DEFAULT_TYPHOON_ID_LENGTH);
    let buf = pool_empty(&TEST_POOL, TAILOR_LENGTH + DEFAULT_TYPHOON_ID_LENGTH);
    let sequence: u32 = 0x0000_CAFE;
    let phase: u32 = 0x0000_0002;
    let t = Tailor::<StaticByteBuffer>::debug_probe(buf, &identity, 0, 0, sequence, phase, 0);
    let raw_pn = t.packet_number();
    assert_eq!((raw_pn >> 32) as u32, sequence);
    assert_eq!(raw_pn as u32, phase);
}
