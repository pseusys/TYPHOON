use std::sync::LazyLock;

use crate::bytes::{ByteBuffer, BytePool, DynamicByteBuffer, StaticByteBuffer};
use crate::settings::consts::{DEFAULT_TYPHOON_ID_LENGTH, TAILER_LENGTH};
use crate::tailer::flags::{PacketFlags, ReturnCode};
use crate::tailer::structure::Tailer;

static TEST_POOL: LazyLock<BytePool> = LazyLock::new(|| BytePool::new(32, 256, 32, 4, 16));

/// Allocate an empty buffer from pool.
fn pool_empty(pool: &BytePool, size: usize) -> DynamicByteBuffer {
    pool.allocate_precise(size, 0, 0)
}

#[test]
fn test_tailer_roundtrip() {
    let identity = StaticByteBuffer::from_slice(&[0xAB; DEFAULT_TYPHOON_ID_LENGTH]);
    let buffer = pool_empty(&TEST_POOL, TAILER_LENGTH + DEFAULT_TYPHOON_ID_LENGTH);
    let tailer = Tailer::<StaticByteBuffer>::data(buffer, &identity, 1024, 0x1234_5678_ABCD_0001);
    tailer.set_code(42);
    tailer.set_flags(PacketFlags::DATA);
    tailer.set_time(64000);

    let tailer_buffer = tailer.buffer().clone();
    assert_eq!(tailer_buffer.len(), TAILER_LENGTH + DEFAULT_TYPHOON_ID_LENGTH);

    let decoded = Tailer::<StaticByteBuffer>::new(tailer_buffer);
    assert_eq!(decoded.flags(), tailer.flags());
    assert_eq!(decoded.code(), tailer.code());
    assert_eq!(decoded.time(), tailer.time());
    assert_eq!(decoded.packet_number(), tailer.packet_number());
    assert_eq!(decoded.payload_length(), tailer.payload_length());
    assert_eq!(decoded.identity(), tailer.identity());
}

#[test]
fn test_packet_number_components() {
    let identity = StaticByteBuffer::empty(DEFAULT_TYPHOON_ID_LENGTH);
    let buffer = pool_empty(&TEST_POOL, TAILER_LENGTH + DEFAULT_TYPHOON_ID_LENGTH);
    let tailer = Tailer::<StaticByteBuffer>::data(buffer, &identity, 0, 0);
    tailer.set_packet_number(0x1234_5678, 0xABCD_0001);

    assert_eq!(tailer.timestamp(), 0x1234_5678);
    assert_eq!(tailer.incremental(), 0xABCD_0001);
}

#[test]
fn test_data_tailer() {
    let identity = StaticByteBuffer::from_slice(&[1; DEFAULT_TYPHOON_ID_LENGTH]);
    let buffer = pool_empty(&TEST_POOL, TAILER_LENGTH + DEFAULT_TYPHOON_ID_LENGTH);
    let tailer = Tailer::<StaticByteBuffer>::data(buffer, &identity, 512, 12345);

    assert!(tailer.flags().has_payload());
    assert_eq!(tailer.payload_length(), 512);
}

#[test]
fn test_health_check_tailer() {
    let identity = StaticByteBuffer::from_slice(&[2; DEFAULT_TYPHOON_ID_LENGTH]);
    let buffer = pool_empty(&TEST_POOL, TAILER_LENGTH + DEFAULT_TYPHOON_ID_LENGTH);
    let tailer = Tailer::<StaticByteBuffer>::health_check(buffer, &identity, 64000, 12345);

    assert!(!tailer.flags().has_payload());
    assert_eq!(tailer.time(), 64000);
}

#[test]
fn test_handshake_tailer() {
    let identity = StaticByteBuffer::from_slice(&[6; DEFAULT_TYPHOON_ID_LENGTH]);
    let buffer = pool_empty(&TEST_POOL, TAILER_LENGTH + DEFAULT_TYPHOON_ID_LENGTH);
    let tailer = Tailer::<StaticByteBuffer>::handshake(buffer, &identity, 42, 5000, 12345, 100);

    assert_eq!(tailer.flags(), PacketFlags::HANDSHAKE);
    assert!(!tailer.flags().is_discardable());
    assert!(!tailer.flags().has_payload());
    assert_eq!(tailer.code(), 42);
    assert_eq!(tailer.time(), 5000);
}

#[test]
fn test_decoy_tailer() {
    let identity = StaticByteBuffer::from_slice(&[4; DEFAULT_TYPHOON_ID_LENGTH]);
    let buffer = pool_empty(&TEST_POOL, TAILER_LENGTH + DEFAULT_TYPHOON_ID_LENGTH);
    let tailer = Tailer::<StaticByteBuffer>::decoy(buffer, &identity, 12345);

    assert!(tailer.flags().is_discardable());
    assert!(!tailer.flags().has_payload());
}

#[test]
fn test_termination_tailer() {
    let identity = StaticByteBuffer::from_slice(&[5; DEFAULT_TYPHOON_ID_LENGTH]);
    let buffer = pool_empty(&TEST_POOL, TAILER_LENGTH + DEFAULT_TYPHOON_ID_LENGTH);
    let tailer = Tailer::<StaticByteBuffer>::termination(buffer, &identity, ReturnCode::Success, 12345);

    assert!(tailer.flags().is_termination());
    assert_eq!(tailer.return_code(), ReturnCode::Success);
}

#[test]
fn test_debug_probe_tailer_roundtrip() {
    let identity = StaticByteBuffer::from_slice(&[7; DEFAULT_TYPHOON_ID_LENGTH]);
    let buffer = pool_empty(&TEST_POOL, TAILER_LENGTH + DEFAULT_TYPHOON_ID_LENGTH);
    let tailer = Tailer::<StaticByteBuffer>::debug_probe(buffer, &identity, 42, 0xDEAD_BEEF, 99, 1, 1024);

    assert_eq!(tailer.flags(), PacketFlags::DATA);
    assert_eq!(tailer.debug_ref_num(), 42);
    assert_eq!(tailer.debug_send_time(), 0xDEAD_BEEF);
    assert_eq!(tailer.debug_sequence(), 99);
    assert_eq!(tailer.debug_phase(), 1);
    assert_eq!(tailer.payload_length(), 1024);
}

#[test]
fn test_debug_probe_accessors_all_phases() {
    let identity = StaticByteBuffer::empty(DEFAULT_TYPHOON_ID_LENGTH);

    // Phase 0: reachability
    let buf = pool_empty(&TEST_POOL, TAILER_LENGTH + DEFAULT_TYPHOON_ID_LENGTH);
    let t = Tailer::<StaticByteBuffer>::debug_probe(buf, &identity, 0, 1000, 0, 0, 0);
    assert_eq!(t.debug_phase(), 0);
    assert_eq!(t.debug_sequence(), 0);

    // Phase 1: return time
    let buf = pool_empty(&TEST_POOL, TAILER_LENGTH + DEFAULT_TYPHOON_ID_LENGTH);
    let t = Tailer::<StaticByteBuffer>::debug_probe(buf, &identity, 1, 2000, 1, 1, 0);
    assert_eq!(t.debug_phase(), 1);
    assert_eq!(t.debug_sequence(), 1);

    // Phase 2: throughput
    let buf = pool_empty(&TEST_POOL, TAILER_LENGTH + DEFAULT_TYPHOON_ID_LENGTH);
    let t = Tailer::<StaticByteBuffer>::debug_probe(buf, &identity, 255, 3000, 9, 2, 65016);
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
    let buf = pool_empty(&TEST_POOL, TAILER_LENGTH + DEFAULT_TYPHOON_ID_LENGTH);
    let sequence: u32 = 0x0000_CAFE;
    let phase: u32 = 0x0000_0002;
    let t = Tailer::<StaticByteBuffer>::debug_probe(buf, &identity, 0, 0, sequence, phase, 0);
    let raw_pn = t.packet_number();
    assert_eq!((raw_pn >> 32) as u32, sequence);
    assert_eq!(raw_pn as u32, phase);
}
