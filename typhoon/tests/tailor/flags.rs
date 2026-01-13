use crate::tailor::flags::{PacketFlags, ReturnCode};

#[test]
fn test_packet_flags_values() {
    assert_eq!(PacketFlags::HANDSHAKE.bits(), 128);
    assert_eq!(PacketFlags::HEALTH_CHECK.bits(), 64);
    assert_eq!(PacketFlags::DATA.bits(), 32);
    assert_eq!(PacketFlags::DECOY.bits(), 16);
    assert_eq!(PacketFlags::TERMINATION.bits(), 8);
}

#[test]
fn test_shadowride_detection() {
    let shadowride = PacketFlags::DATA | PacketFlags::HEALTH_CHECK;
    assert!(shadowride.is_shadowride());
    assert!(!PacketFlags::DATA.is_shadowride());
    assert!(!PacketFlags::HEALTH_CHECK.is_shadowride());
}

#[test]
fn test_has_payload() {
    assert!(PacketFlags::DATA.has_payload());
    assert!((PacketFlags::DATA | PacketFlags::HEALTH_CHECK).has_payload());
    assert!(!PacketFlags::HEALTH_CHECK.has_payload());
    assert!(!PacketFlags::HANDSHAKE.has_payload());
}

#[test]
fn test_requires_response() {
    assert!(PacketFlags::HANDSHAKE.requires_response());
    assert!(PacketFlags::HEALTH_CHECK.requires_response());
    assert!(!PacketFlags::DATA.requires_response());
    assert!(!PacketFlags::DECOY.requires_response());
}

#[test]
fn test_return_code_roundtrip() {
    assert_eq!(u8::from(ReturnCode::Success), 0);
    assert_eq!(ReturnCode::from(0), ReturnCode::Success);
    assert_eq!(ReturnCode::from(101), ReturnCode::UnknownError);
    assert_eq!(ReturnCode::from(255), ReturnCode::UnknownError);
}
