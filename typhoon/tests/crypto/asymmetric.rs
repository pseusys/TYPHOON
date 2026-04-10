use crate::bytes::BytePool;
#[cfg(all(feature = "client", feature = "server"))]
use crate::bytes::{ByteBuffer, ByteBufferMut, StaticByteBuffer};
#[cfg(any(feature = "full_software", feature = "full_hardware"))]
use crate::crypto::symmetric::ANONYMOUS_NONCE_LEN;
#[cfg(all(feature = "client", feature = "server"))]
use crate::crypto::symmetric::{NONCE_LEN, SYMMETRIC_BUILT_IN_AUTH_LEN, Symmetric};
use crate::certificate::ServerKeyPair;

use lazy_static::lazy_static;

#[cfg(any(feature = "full_software", feature = "full_hardware"))]
const X25519_KEY_LENGTH: usize = 32;

#[cfg(any(feature = "full_software", feature = "full_hardware"))]
const NONCE_LENGTH: usize = 32;

#[cfg(any(feature = "full_software", feature = "full_hardware"))]
const ENCRYPT_OBFUSCATE_HEADER: usize = NONCE_LENGTH + X25519_KEY_LENGTH + 2 * ANONYMOUS_NONCE_LEN;

lazy_static! {
    static ref TEST_POOL: BytePool = BytePool::new(32, 256, 32, 4, 16);
}

// Test: handshake produces matching shared secrets and session keys, with initial data exchange.
#[cfg(all(feature = "client", feature = "server"))]
#[test]
fn test_handshake_cycle() {
    let (certificate, server_secret) = ServerKeyPair::for_tests_pair();

    let client_initial_data = b"Secret client initial data";
    let server_initial_data = b"Secret server initial data";

    // Client creates handshake with initial data encrypted inside.
    let (client_data, client_handshake, _client_initial_key) = certificate.encapsulate_handshake_client(&TEST_POOL, client_initial_data);

    // Server decapsulates and receives decrypted client initial data.
    let (server_data, server_initial_key, decrypted_client_initial_data) = server_secret.decapsulate_handshake_server(client_handshake, &TEST_POOL);

    assert_eq!(client_data.shared_secret, server_data.shared_secret, "client and server should derive the same shared secret");
    assert_eq!(client_initial_data.as_slice(), decrypted_client_initial_data.slice(), "server should receive the same client initial data");

    // Server creates response with server initial data encrypted with initial key.
    let (server_handshake, server_session_key) = server_secret.encapsulate_handshake_server(server_data, &TEST_POOL, server_initial_data, &server_initial_key);

    // Client decapsulates and receives session key + decrypted server initial data.
    let (client_session_key, decrypted_server_initial_data) = certificate.decapsulate_handshake_client(client_data, server_handshake, &TEST_POOL).expect("client handshake decapsulation failed");

    assert_eq!(server_initial_data.as_slice(), decrypted_server_initial_data.slice(), "client should receive the same server initial data");

    // Verify session keys match by encrypting/decrypting a test message.
    let session_data_data = b"Secret session data message";
    let session_data = TEST_POOL.allocate_precise_from_slice_with_capacity(session_data_data, 0, NONCE_LEN + SYMMETRIC_BUILT_IN_AUTH_LEN);

    let mut server_session_cipher = Symmetric::new(&server_session_key);
    let session_data_encrypted = server_session_cipher.encrypt_auth(session_data, None::<&StaticByteBuffer>).expect("session data encryption failed");

    let mut client_session_cipher = Symmetric::new(&client_session_key);
    let session_data_decrypted = client_session_cipher.decrypt_auth(session_data_encrypted, None::<&StaticByteBuffer>).expect("session data decryption failed");

    assert_eq!(session_data_data.as_slice(), session_data_decrypted.slice(), "client and server should get the same session data");
}

// Test: tampered handshake ciphertext produces wrong shared secret and fails initial data decryption.
#[cfg(all(feature = "client", feature = "server"))]
#[test]
fn test_handshake_tampered_ciphertext_fails() {
    let (certificate, server_secret) = ServerKeyPair::for_tests_pair();

    let client_initial_data = b"Tampered handshake test";

    let (client_data, client_handshake, _client_initial_key) = certificate.encapsulate_handshake_client(&TEST_POOL, client_initial_data);

    // Tamper with the handshake crypto header (not the encrypted initial data).
    let tampered_byte_idx = client_handshake.len() / 4;
    let original = *client_handshake.get(tampered_byte_idx);
    client_handshake.set(tampered_byte_idx, original ^ 0xFF);

    let (server_data, _server_initial_key, decrypted_client_initial_data) = server_secret.decapsulate_handshake_server(client_handshake, &TEST_POOL);

    // Server should derive a different shared secret from tampered data.
    assert_ne!(client_data.shared_secret, server_data.shared_secret, "tampered handshake should produce different shared secrets");

    // Initial data decryption should fail (returns empty via unwrap_or_default).
    assert!(decrypted_client_initial_data.is_empty(), "decrypting initial data with wrong key should fail");
}

// Test: full mode encrypt/obfuscate then decrypt/deobfuscate cycle succeeds.
#[cfg(all(any(feature = "full_software", feature = "full_hardware"), feature = "client", feature = "server"))]
#[test]
fn test_obfuscate_cycle() {
    let (certificate, server_secret) = ServerKeyPair::for_tests_pair();

    let plaintext_data = b"Secret initial data message";
    let plaintext_static = StaticByteBuffer::from(plaintext_data.as_slice());
    let plaintext = TEST_POOL.allocate_precise_from_slice_with_capacity(plaintext_data, 0, ENCRYPT_OBFUSCATE_HEADER + SYMMETRIC_BUILT_IN_AUTH_LEN);

    let ciphertext = certificate.encrypt_obfuscate(plaintext, &TEST_POOL).expect("encryption failed");
    let decrypted = server_secret.decrypt_deobfuscate(ciphertext).expect("decryption failed");

    assert_eq!(decrypted.slice(), plaintext_static.slice(), "decrypted message should match original");
}
