use crate::bytes::ByteBuffer;
use crate::crypto::symmetric::{ANONYMOUS_NONCE_LEN, NONCE_LEN, SYMMETRIC_FIRST_AUTH_LEN, SYMMETRIC_KEY_LENGTH, Symmetric, decrypt_anonymously, encrypt_anonymously};

#[cfg(feature = "fast")]
use crate::crypto::symmetric::SYMMETRIC_SECOND_AUTH_LEN;

#[inline]
fn make_key() -> ByteBuffer {
    ByteBuffer::from(&[0x42u8; SYMMETRIC_KEY_LENGTH])
}

#[cfg(feature = "fast")]
#[inline]
fn make_different_key() -> ByteBuffer {
    ByteBuffer::from(&[0x24u8; SYMMETRIC_KEY_LENGTH])
}

// Test: anonymous encrypt then decrypt produces original plaintext.
#[test]
fn test_anonymous_encrypt_decrypt_cycle() {
    let key = make_key();

    let plaintext_data = b"Anonymous encryption test";
    let mut plaintext = ByteBuffer::from_slice_with_capacity(plaintext_data, 0, ANONYMOUS_NONCE_LEN);

    let mut ciphertext = encrypt_anonymously(&key, &mut plaintext);
    let decrypted = decrypt_anonymously(&key, &mut ciphertext);

    assert_eq!(decrypted.slice(), plaintext_data, "decrypted text should match original");
}

// Test: authenticated encrypt then decrypt produces original plaintext.
#[test]
fn test_symmetric_encrypt_decrypt_cycle() {
    let key = make_key();
    let mut cipher = Symmetric::new(&key);

    let plaintext_data = b"Authenticated encryption test";
    let plaintext = ByteBuffer::from_slice_with_capacity(plaintext_data, 0, NONCE_LEN + SYMMETRIC_FIRST_AUTH_LEN);

    let ciphertext = cipher.encrypt_auth(plaintext, None).expect("encryption failed");
    let decrypted = cipher.decrypt_auth(ciphertext, None).expect("decryption failed");

    assert_eq!(decrypted.slice(), plaintext_data, "decrypted should match original");
}

// Test: dual authentication (AEAD + BLAKE3 hash) encrypt/decrypt cycle.
#[cfg(feature = "fast")]
#[test]
fn test_symmetric_encrypt_decrypt_twice_cycle() {
    let key = make_key();
    let second_key = make_different_key();
    let mut cipher = Symmetric::new(&key);

    let plaintext_data = b"Double authenticated message";
    let plaintext = ByteBuffer::from_slice_with_capacity(plaintext_data, NONCE_LEN, SYMMETRIC_FIRST_AUTH_LEN + SYMMETRIC_SECOND_AUTH_LEN);

    let ciphertext = cipher.encrypt_auth_twice(plaintext, None, &second_key).expect("encryption failed");
    let (decrypted, ciphertext_with_nonce, second_auth) = cipher.decrypt_auth_twice(ciphertext, None).expect("decryption failed");

    assert_eq!(decrypted.slice(), plaintext_data, "decrypted should match original");
    let verify_result = cipher.verify_second_auth(&ciphertext_with_nonce, None, &second_key, &second_auth);
    assert!(verify_result.is_ok(), "second authentication should verify correctly");
}
