use std::sync::LazyLock;

use crate::bytes::{ByteBuffer, BytePool, DynamicByteBuffer, StaticByteBuffer};
use crate::settings::consts::{DEFAULT_TYPHOON_ID_LENGTH, TRAILER_LENGTH};
use crate::trailer::flags::{PacketFlags, ReturnCode};
use crate::trailer::structure::Trailer;

static TEST_POOL: LazyLock<BytePool> = LazyLock::new(|| BytePool::new(32, 256, 32, 4, 16));

/// Allocate an empty buffer from pool.
fn pool_empty(pool: &BytePool, size: usize) -> DynamicByteBuffer {
    pool.allocate_precise(size, 0, 0)
}

#[test]
fn test_trailer_roundtrip() {
    let identity = StaticByteBuffer::from_slice(&[0xAB; DEFAULT_TYPHOON_ID_LENGTH]);
    let buffer = pool_empty(&TEST_POOL, TRAILER_LENGTH + DEFAULT_TYPHOON_ID_LENGTH);
    let trailer = Trailer::<StaticByteBuffer>::data(buffer, &identity, 1024, 0x1234_5678_ABCD_0001);
    trailer.set_code(42);
    trailer.set_flags(PacketFlags::DATA);
    trailer.set_time(64000);

    let trailer_buffer = trailer.buffer().clone();
    assert_eq!(trailer_buffer.len(), TRAILER_LENGTH + DEFAULT_TYPHOON_ID_LENGTH);

    let decoded = Trailer::<StaticByteBuffer>::new(trailer_buffer);
    assert_eq!(decoded.flags(), trailer.flags());
    assert_eq!(decoded.code(), trailer.code());
    assert_eq!(decoded.time(), trailer.time());
    assert_eq!(decoded.packet_number(), trailer.packet_number());
    assert_eq!(decoded.payload_length(), trailer.payload_length());
    assert_eq!(decoded.identity(), trailer.identity());
}

#[test]
fn test_packet_number_components() {
    let identity = StaticByteBuffer::empty(DEFAULT_TYPHOON_ID_LENGTH);
    let buffer = pool_empty(&TEST_POOL, TRAILER_LENGTH + DEFAULT_TYPHOON_ID_LENGTH);
    let trailer = Trailer::<StaticByteBuffer>::data(buffer, &identity, 0, 0);
    trailer.set_packet_number(0x1234_5678, 0xABCD_0001);

    assert_eq!(trailer.timestamp(), 0x1234_5678);
    assert_eq!(trailer.incremental(), 0xABCD_0001);
}

#[test]
fn test_data_trailer() {
    let identity = StaticByteBuffer::from_slice(&[1; DEFAULT_TYPHOON_ID_LENGTH]);
    let buffer = pool_empty(&TEST_POOL, TRAILER_LENGTH + DEFAULT_TYPHOON_ID_LENGTH);
    let trailer = Trailer::<StaticByteBuffer>::data(buffer, &identity, 512, 12345);

    assert!(trailer.flags().has_payload());
    assert_eq!(trailer.payload_length(), 512);
}

#[test]
fn test_health_check_trailer() {
    let identity = StaticByteBuffer::from_slice(&[2; DEFAULT_TYPHOON_ID_LENGTH]);
    let buffer = pool_empty(&TEST_POOL, TRAILER_LENGTH + DEFAULT_TYPHOON_ID_LENGTH);
    let trailer = Trailer::<StaticByteBuffer>::health_check(buffer, &identity, 64000, 12345);

    assert!(!trailer.flags().has_payload());
    assert_eq!(trailer.time(), 64000);
}

#[test]
fn test_handshake_trailer() {
    let identity = StaticByteBuffer::from_slice(&[6; DEFAULT_TYPHOON_ID_LENGTH]);
    let buffer = pool_empty(&TEST_POOL, TRAILER_LENGTH + DEFAULT_TYPHOON_ID_LENGTH);
    let trailer = Trailer::<StaticByteBuffer>::handshake(buffer, &identity, 42, 5000, 12345, 100);

    assert_eq!(trailer.flags(), PacketFlags::HANDSHAKE);
    assert!(!trailer.flags().is_discardable());
    assert!(!trailer.flags().has_payload());
    assert_eq!(trailer.code(), 42);
    assert_eq!(trailer.time(), 5000);
}

#[test]
fn test_decoy_trailer() {
    let identity = StaticByteBuffer::from_slice(&[4; DEFAULT_TYPHOON_ID_LENGTH]);
    let buffer = pool_empty(&TEST_POOL, TRAILER_LENGTH + DEFAULT_TYPHOON_ID_LENGTH);
    let trailer = Trailer::<StaticByteBuffer>::decoy(buffer, &identity, 12345);

    assert!(trailer.flags().is_discardable());
    assert!(!trailer.flags().has_payload());
}

#[test]
fn test_termination_trailer() {
    let identity = StaticByteBuffer::from_slice(&[5; DEFAULT_TYPHOON_ID_LENGTH]);
    let buffer = pool_empty(&TEST_POOL, TRAILER_LENGTH + DEFAULT_TYPHOON_ID_LENGTH);
    let trailer = Trailer::<StaticByteBuffer>::termination(buffer, &identity, ReturnCode::Success, 12345);

    assert!(trailer.flags().is_termination());
    assert_eq!(trailer.return_code(), ReturnCode::Success);
}

#[test]
fn test_debug_probe_trailer_roundtrip() {
    let identity = StaticByteBuffer::from_slice(&[7; DEFAULT_TYPHOON_ID_LENGTH]);
    let buffer = pool_empty(&TEST_POOL, TRAILER_LENGTH + DEFAULT_TYPHOON_ID_LENGTH);
    let trailer = Trailer::<StaticByteBuffer>::debug_probe(buffer, &identity, 42, 0xDEAD_BEEF, 99, 1, 1024);

    assert_eq!(trailer.flags(), PacketFlags::DATA);
    assert_eq!(trailer.debug_ref_num(), 42);
    assert_eq!(trailer.debug_send_time(), 0xDEAD_BEEF);
    assert_eq!(trailer.debug_sequence(), 99);
    assert_eq!(trailer.debug_phase(), 1);
    assert_eq!(trailer.payload_length(), 1024);
}

#[test]
fn test_debug_probe_accessors_all_phases() {
    let identity = StaticByteBuffer::empty(DEFAULT_TYPHOON_ID_LENGTH);

    // Phase 0: reachability
    let buf = pool_empty(&TEST_POOL, TRAILER_LENGTH + DEFAULT_TYPHOON_ID_LENGTH);
    let t = Trailer::<StaticByteBuffer>::debug_probe(buf, &identity, 0, 1000, 0, 0, 0);
    assert_eq!(t.debug_phase(), 0);
    assert_eq!(t.debug_sequence(), 0);

    // Phase 1: return time
    let buf = pool_empty(&TEST_POOL, TRAILER_LENGTH + DEFAULT_TYPHOON_ID_LENGTH);
    let t = Trailer::<StaticByteBuffer>::debug_probe(buf, &identity, 1, 2000, 1, 1, 0);
    assert_eq!(t.debug_phase(), 1);
    assert_eq!(t.debug_sequence(), 1);

    // Phase 2: throughput
    let buf = pool_empty(&TEST_POOL, TRAILER_LENGTH + DEFAULT_TYPHOON_ID_LENGTH);
    let t = Trailer::<StaticByteBuffer>::debug_probe(buf, &identity, 255, 3000, 9, 2, 65016);
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
    let buf = pool_empty(&TEST_POOL, TRAILER_LENGTH + DEFAULT_TYPHOON_ID_LENGTH);
    let sequence: u32 = 0x0000_CAFE;
    let phase: u32 = 0x0000_0002;
    let t = Trailer::<StaticByteBuffer>::debug_probe(buf, &identity, 0, 0, sequence, phase, 0);
    let raw_pn = t.packet_number();
    assert_eq!((raw_pn >> 32) as u32, sequence);
    assert_eq!(raw_pn as u32, phase);
}
