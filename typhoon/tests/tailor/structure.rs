use crate::bytes::ByteBuffer;
use crate::constants::consts::{DEFAULT_TYPHOON_ID_LENGTH, TAILOR_LENGTH};
use crate::tailor::flags::{PacketFlags, ReturnCode};
use crate::tailor::structure::Tailor;

impl<const TYPHOON_ID_LENGTH: usize> Tailor<{ TYPHOON_ID_LENGTH }> {
    fn new() -> Self {
        Self {
            flags: PacketFlags::empty(),
            code: 0,
            time: 0,
            packet_number: 0,
            payload_length: 0,
            identity: [0u8; TYPHOON_ID_LENGTH],
        }
    }
}

#[test]
fn test_tailor_roundtrip() {
    let identity = [0xAB; DEFAULT_TYPHOON_ID_LENGTH];
    let tailor = Tailor {
        flags: PacketFlags::DATA,
        code: 42,
        time: 64000,
        packet_number: 0x12345678_ABCD0001,
        payload_length: 1024,
        identity,
    };

    let buffer = ByteBuffer::empty(TAILOR_LENGTH + DEFAULT_TYPHOON_ID_LENGTH);
    let tailor_buffer = tailor.to_buffer(buffer);
    assert_eq!(tailor_buffer.len(), TAILOR_LENGTH);

    let decoded = Tailor::<DEFAULT_TYPHOON_ID_LENGTH>::from_buffer(&tailor_buffer);
    assert_eq!(decoded.flags, tailor.flags);
    assert_eq!(decoded.code, tailor.code);
    assert_eq!(decoded.time, tailor.time);
    assert_eq!(decoded.packet_number, tailor.packet_number);
    assert_eq!(decoded.payload_length, tailor.payload_length);
    assert_eq!(decoded.identity, tailor.identity);
}

#[test]
fn test_packet_number_components() {
    let mut tailor = Tailor::<DEFAULT_TYPHOON_ID_LENGTH>::new();
    tailor.set_packet_number(0x12345678, 0xABCD0001);

    assert_eq!(tailor.timestamp(), 0x12345678);
    assert_eq!(tailor.incremental(), 0xABCD0001);
}

#[test]
fn test_data_tailor() {
    let identity = [1; DEFAULT_TYPHOON_ID_LENGTH];
    let tailor = Tailor::data(identity, 512, 12345);

    assert!(tailor.flags.has_payload());
    assert_eq!(tailor.payload_length, 512);
}

#[test]
fn test_health_check_tailor() {
    let identity = [2; DEFAULT_TYPHOON_ID_LENGTH];
    let tailor = Tailor::health_check(identity, 64000, 12345);

    assert!(!tailor.flags.has_payload());
    assert_eq!(tailor.time, 64000);
}

#[test]
fn test_shadowride_tailor() {
    let identity = [3; DEFAULT_TYPHOON_ID_LENGTH];
    let tailor = Tailor::shadowride(identity, 256, 128000, 12345);

    assert!(tailor.flags.is_shadowride());
    assert!(tailor.flags.has_payload());
    assert_eq!(tailor.payload_length, 256);
    assert_eq!(tailor.time, 128000);
}

#[test]
fn test_decoy_tailor() {
    let identity = [4; DEFAULT_TYPHOON_ID_LENGTH];
    let tailor = Tailor::decoy(identity, 12345);

    assert!(tailor.flags.is_discardable());
    assert!(!tailor.flags.has_payload());
}

#[test]
fn test_termination_tailor() {
    let identity = [5; DEFAULT_TYPHOON_ID_LENGTH];
    let tailor = Tailor::termination(identity, ReturnCode::Success, 12345);

    assert!(tailor.flags.is_termination());
    assert_eq!(tailor.return_code(), ReturnCode::Success);
}
