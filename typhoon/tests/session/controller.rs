use crate::bytes::ByteBuffer;
use crate::constants::tailor::TYPHOON_ID_LENGTH;
use crate::crypto::symmetric::{NONCE_LEN, SYMMETRIC_FIRST_AUTH_LEN, Symmetric};
use crate::session::controller::BaseSessionManager;

fn make_test_cipher() -> Symmetric {
    let key = ByteBuffer::from(&[0x42u8; 32]);
    Symmetric::new(&key).unwrap()
}

#[test]
fn test_new_base_session() {
    let id = [0xAB; TYPHOON_ID_LENGTH];
    let cipher = make_test_cipher();
    let manager = BaseSessionManager::new(id, cipher);

    assert_eq!(manager.session_id(), &id);
    assert!(manager.is_active());
}

#[test]
fn test_encrypt_decrypt_roundtrip() {
    let id = [0xAB; TYPHOON_ID_LENGTH];
    let cipher = make_test_cipher();
    let manager = BaseSessionManager::new(id, cipher);

    // Create plaintext with capacity for nonce (before) and auth tag (after)
    let plaintext = ByteBuffer::from_slice_with_capacity(
        b"Hello, TYPHOON!".as_slice(),
        NONCE_LEN,
        SYMMETRIC_FIRST_AUTH_LEN,
    );
    let original = plaintext.copy();
    let ciphertext = manager.encrypt_payload(plaintext).unwrap();

    assert_ne!(ciphertext.slice(), original.slice());

    let decrypted = manager.decrypt_payload(ciphertext).unwrap();
    assert_eq!(decrypted.slice(), original.slice());
}

#[test]
fn test_terminate() {
    let id = [0xAB; TYPHOON_ID_LENGTH];
    let cipher = make_test_cipher();
    let manager = BaseSessionManager::new(id, cipher);

    assert!(manager.is_active());
    manager.terminate();
    assert!(!manager.is_active());
}

#[test]
fn test_packet_number_generation() {
    let id = [0xAB; TYPHOON_ID_LENGTH];
    let cipher = make_test_cipher();
    let manager = BaseSessionManager::new(id, cipher);

    let pn1 = manager.next_packet_number();
    let pn2 = manager.next_packet_number();

    assert_ne!(pn1, pn2);
    assert!(manager.validate_packet_number(pn1));
    assert!(manager.validate_packet_number(pn2));
}
