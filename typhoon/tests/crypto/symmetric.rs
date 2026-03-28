use lazy_static::lazy_static;

use crate::bytes::{ByteBuffer, BytePool, StaticByteBuffer};
#[cfg(any(feature = "fast_software", feature = "fast_hardware"))]
use crate::crypto::symmetric::SYMMETRIC_ADDITIONAL_AUTH_LEN;
use crate::crypto::symmetric::{ANONYMOUS_NONCE_LEN, NONCE_LEN, SYMMETRIC_BUILT_IN_AUTH_LEN, SYMMETRIC_KEY_LENGTH, Symmetric, decrypt_anonymously, encrypt_anonymously};

lazy_static! {
    static ref TEST_POOL: BytePool = BytePool::new(32, 256, 32, 4, 16);
}

#[inline]
fn make_key() -> StaticByteBuffer {
    StaticByteBuffer::from(&[0x42u8; SYMMETRIC_KEY_LENGTH])
}

#[cfg(any(feature = "fast_software", feature = "fast_hardware"))]
#[inline]
fn make_different_key() -> StaticByteBuffer {
    StaticByteBuffer::from(&[0x24u8; SYMMETRIC_KEY_LENGTH])
}

#[inline]
fn make_wrong_key() -> StaticByteBuffer {
    StaticByteBuffer::from(&[0x99u8; SYMMETRIC_KEY_LENGTH])
}

// Test: anonymous encrypt then decrypt produces original plaintext.
#[test]
fn test_anonymous_encrypt_decrypt_cycle() {
    let key = make_key();

    let plaintext_data = b"Anonymous encryption test";
    let mut plaintext = TEST_POOL.allocate_precise_from_slice_with_capacity(plaintext_data, 0, ANONYMOUS_NONCE_LEN);

    let mut ciphertext = encrypt_anonymously(&key, &mut plaintext);
    let decrypted = decrypt_anonymously(&key, &mut ciphertext);

    assert_eq!(decrypted.slice(), plaintext_data.as_slice(), "decrypted text should match original");
}

// Test: authenticated encrypt then decrypt produces original plaintext.
#[test]
fn test_symmetric_encrypt_decrypt_cycle() {
    let key = make_key();
    let mut cipher = Symmetric::new(&key);

    let plaintext_data = b"Authenticated encryption test";
    let plaintext = TEST_POOL.allocate_precise_from_slice_with_capacity(plaintext_data, 0, NONCE_LEN + SYMMETRIC_BUILT_IN_AUTH_LEN);

    let ciphertext = cipher.encrypt_auth(plaintext, None::<&StaticByteBuffer>).expect("encryption failed");
    let decrypted = cipher.decrypt_auth(ciphertext, None::<&StaticByteBuffer>).expect("decryption failed");

    assert_eq!(decrypted.slice(), plaintext_data.as_slice(), "decrypted should match original");
}

// Test: authentication (anonymous cipher + BLAKE3 hash) encrypt/decrypt cycle.
#[cfg(any(feature = "fast_software", feature = "fast_hardware"))]
#[test]
fn test_symmetric_encrypt_decrypt_auth_cycle() {
    let key = make_key();
    let second_key = make_different_key();
    let mut cipher = Symmetric::new_split(key, second_key);

    let plaintext_data = b"Authenticated obfuscation message";
    let plaintext = TEST_POOL.allocate_precise_from_slice_with_capacity(plaintext_data, 0, ANONYMOUS_NONCE_LEN + SYMMETRIC_ADDITIONAL_AUTH_LEN);

    let ciphertext = cipher.encrypt_auth(plaintext, None::<&StaticByteBuffer>).expect("encryption failed");

    let (decrypted, transcript) = cipher.decrypt_no_verify(ciphertext.copy());
    assert_eq!(decrypted.slice(), plaintext_data.as_slice(), "decrypted should match original");
    let verify_result = cipher.verify_decrypted(transcript, None::<&StaticByteBuffer>);
    assert!(verify_result.is_ok(), "authentication should verify correctly");

    let decrypted = cipher.decrypt_auth(ciphertext, None::<&StaticByteBuffer>).expect("decryption failed");
    assert_eq!(decrypted.slice(), plaintext_data.as_slice(), "decrypted should match original");
}

// Test: anonymous decrypt with wrong key produces garbage (not the original plaintext).
#[test]
fn test_anonymous_decrypt_wrong_key_produces_garbage() {
    let key = make_key();
    let wrong_key = make_wrong_key();

    let plaintext_data = b"Anonymous wrong key test";
    let mut plaintext = TEST_POOL.allocate_precise_from_slice_with_capacity(plaintext_data, 0, ANONYMOUS_NONCE_LEN);

    let mut ciphertext = encrypt_anonymously(&key, &mut plaintext);
    let decrypted = decrypt_anonymously(&wrong_key, &mut ciphertext);

    assert_ne!(decrypted.slice(), plaintext_data.as_slice(), "wrong key should not produce original plaintext");
}

// Test: authenticated decrypt with wrong key fails.
#[test]
fn test_symmetric_decrypt_wrong_key_fails() {
    let key = make_key();
    let wrong_key = make_wrong_key();
    let mut encrypt_cipher = Symmetric::new(&key);
    let mut decrypt_cipher = Symmetric::new(&wrong_key);

    let plaintext_data = b"Wrong key auth test";
    let plaintext = TEST_POOL.allocate_precise_from_slice_with_capacity(plaintext_data, 0, NONCE_LEN + SYMMETRIC_BUILT_IN_AUTH_LEN);

    let ciphertext = encrypt_cipher.encrypt_auth(plaintext, None::<&StaticByteBuffer>).expect("encryption failed");
    let result = decrypt_cipher.decrypt_auth(ciphertext, None::<&StaticByteBuffer>);

    assert!(result.is_err(), "decryption with wrong key should fail authentication");
}
