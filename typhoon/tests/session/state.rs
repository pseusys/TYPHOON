use crate::bytes::ByteBuffer;
use crate::constants::tailor::TYPHOON_ID_LENGTH;
use crate::crypto::symmetric::Symmetric;
use crate::session::state::SessionState;

fn make_test_cipher() -> Symmetric {
    let key = ByteBuffer::from(&[0x42u8; 32]);
    Symmetric::new(&key).unwrap()
}

#[test]
fn test_new_session() {
    let id = [0xAB; TYPHOON_ID_LENGTH];
    let cipher = make_test_cipher();
    let state = SessionState::new(id, cipher);

    assert_eq!(state.session_id(), &id);
    assert!(state.is_active());
}

#[test]
fn test_packet_number_generation() {
    let id = [0xAB; TYPHOON_ID_LENGTH];
    let cipher = make_test_cipher();
    let state = SessionState::new(id, cipher);

    let pn1 = state.next_packet_number();
    let pn2 = state.next_packet_number();
    let pn3 = state.next_packet_number();

    // Incremental should increase
    assert_eq!(SessionState::extract_incremental(pn1), 0);
    assert_eq!(SessionState::extract_incremental(pn2), 1);
    assert_eq!(SessionState::extract_incremental(pn3), 2);

    // Timestamps should be the same (within same second)
    assert_eq!(
        SessionState::extract_timestamp(pn1),
        SessionState::extract_timestamp(pn2)
    );
}

#[test]
fn test_validate_packet_number() {
    let id = [0xAB; TYPHOON_ID_LENGTH];
    let cipher = make_test_cipher();
    let state = SessionState::new(id, cipher);

    // First packet is always valid
    assert!(state.validate_packet_number(1));

    // Increasing packets are valid
    assert!(state.validate_packet_number(2));
    assert!(state.validate_packet_number(3));
    assert!(state.validate_packet_number(100));

    // Small reordering is allowed
    assert!(state.validate_packet_number(50));

    // Old packets are rejected
    assert!(!state.validate_packet_number(0));
}

#[test]
fn test_deactivate_activate() {
    let id = [0xAB; TYPHOON_ID_LENGTH];
    let cipher = make_test_cipher();
    let state = SessionState::new(id, cipher);

    assert!(state.is_active());
    state.deactivate();
    assert!(!state.is_active());
    state.activate();
    assert!(state.is_active());
}

#[test]
fn test_compose_extract_packet_number() {
    let timestamp = 0x12345678u32;
    let incremental = 0xABCD0001u32;

    let pn = SessionState::compose_packet_number(timestamp, incremental);
    assert_eq!(SessionState::extract_timestamp(pn), timestamp);
    assert_eq!(SessionState::extract_incremental(pn), incremental);
}

#[test]
fn test_clone() {
    let id = [0xAB; TYPHOON_ID_LENGTH];
    let cipher = make_test_cipher();
    let state = SessionState::new(id, cipher);

    state.next_packet_number();
    state.next_packet_number();

    let cloned = state.clone();
    assert_eq!(cloned.session_id(), state.session_id());
    assert_eq!(cloned.current_incremental(), state.current_incremental());
}
