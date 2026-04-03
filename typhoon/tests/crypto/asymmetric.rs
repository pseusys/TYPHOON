use std::sync::Mutex;
#[cfg(all(feature = "client", feature = "server"))]
use std::sync::Arc;

use classic_mceliece_rust::{CRYPTO_PUBLICKEYBYTES, CRYPTO_SECRETKEYBYTES, keypair_boxed};
#[cfg(all(feature = "client", feature = "server"))]
use classic_mceliece_rust::SecretKey;
#[cfg(all(feature = "client", feature = "server"))]
use classic_mceliece_rust::PublicKey as McEliecePublicKey;
use ed25519_dalek::{SecretKey as X25519SecretKey, SigningKey, VerifyingKey};
#[cfg(all(feature = "client", any(feature = "full_software", feature = "full_hardware")))]
use x25519_dalek::PublicKey as X25519PublicKey;
use lazy_static::lazy_static;
use x25519_dalek::StaticSecret;

use crate::bytes::BytePool;
#[cfg(all(feature = "client", feature = "server"))]
use crate::bytes::{ByteBuffer, ByteBufferMut, StaticByteBuffer};
#[cfg(all(all(feature = "client", feature = "server"), any(feature = "fast_software", feature = "fast_hardware")))]
use crate::bytes::FixedByteBuffer;
#[cfg(all(feature = "client", feature = "server"))]
use crate::certificate::ClientCertificate;
#[cfg(all(feature = "client", feature = "server"))]
use crate::certificate::ServerSecret;
#[cfg(any(feature = "full_software", feature = "full_hardware"))]
use crate::crypto::symmetric::ANONYMOUS_NONCE_LEN;
#[cfg(all(all(feature = "client", feature = "server"), any(feature = "fast_software", feature = "fast_hardware")))]
use crate::crypto::symmetric::SYMMETRIC_KEY_LENGTH;
#[cfg(all(feature = "client", feature = "server"))]
use crate::crypto::symmetric::{NONCE_LEN, SYMMETRIC_BUILT_IN_AUTH_LEN, Symmetric};
use crate::utils::random::get_rng;

#[cfg(any(feature = "full_software", feature = "full_hardware"))]
const X25519_KEY_LENGTH: usize = 32;

#[cfg(any(feature = "full_software", feature = "full_hardware"))]
const NONCE_LENGTH: usize = 32;

#[cfg(any(feature = "full_software", feature = "full_hardware"))]
const ENCRYPT_OBFUSCATE_HEADER: usize = NONCE_LENGTH + X25519_KEY_LENGTH + 2 * ANONYMOUS_NONCE_LEN;

// Cached keypairs for test performance (McEliece generation is slow).
lazy_static! {
    static ref MCELIECE_KEYPAIR_BYTES: (Box<[u8; CRYPTO_PUBLICKEYBYTES]>, Box<[u8; CRYPTO_SECRETKEYBYTES]>) = {
        let (pk, sk) = keypair_boxed(&mut get_rng());
        (Box::new(*pk.as_array()), Box::new(*sk.as_array()))
    };
    static ref ED25519_KEYPAIR: (SigningKey, VerifyingKey) = {
        let secret_bytes: X25519SecretKey = [0u8; 32];
        let signing_key = SigningKey::from_bytes(&secret_bytes);
        let verifying_key = signing_key.verifying_key();
        (signing_key, verifying_key)
    };
    static ref X25519_SECRET_BYTES: Mutex<[u8; 32]> = {
        let secret = StaticSecret::random_from_rng(get_rng());
        Mutex::new(secret.to_bytes())
    };
    static ref TEST_POOL: BytePool = BytePool::new(32, 256, 32, 4, 16);
}

#[cfg(all(all(feature = "client", feature = "server"), any(feature = "fast_software", feature = "fast_hardware")))]
#[inline]
fn get_obfuscation_key() -> FixedByteBuffer<SYMMETRIC_KEY_LENGTH> {
    FixedByteBuffer::from([0x55u8; SYMMETRIC_KEY_LENGTH])
}

#[cfg(all(feature = "client", feature = "server"))]
#[inline]
fn get_mceliece_secret() -> SecretKey<'static> {
    SecretKey::from(Box::new(*MCELIECE_KEYPAIR_BYTES.1))
}

#[cfg(all(feature = "client", feature = "server"))]
#[inline]
fn get_ed25519_keypair() -> (SigningKey, VerifyingKey) {
    (ED25519_KEYPAIR.0.clone(), ED25519_KEYPAIR.1)
}

#[cfg(all(all(feature = "client", feature = "server"), any(feature = "full_software", feature = "full_hardware")))]
#[inline]
fn get_x25519_keypair() -> (StaticSecret, X25519PublicKey) {
    let bytes = *X25519_SECRET_BYTES.lock().unwrap();
    let secret = StaticSecret::from(bytes);
    let public = X25519PublicKey::from(&secret);
    (secret, public)
}

// TODO: move to cert creation:

#[cfg(all(all(feature = "client", feature = "server"), any(feature = "fast_software", feature = "fast_hardware")))]
#[inline]
fn create_test_certificate() -> ClientCertificate {
    let (_, vpk) = get_ed25519_keypair();
    ClientCertificate {
        epk: Arc::new(McEliecePublicKey::from(Box::new(*MCELIECE_KEYPAIR_BYTES.0))),
        vpk,
        obfs: get_obfuscation_key(),
        addresses: vec![],
    }
}

#[cfg(all(feature = "client", feature = "server", any(feature = "fast_software", feature = "fast_hardware")))]
#[inline]
fn create_test_server_secret() -> ServerSecret<'static> {
    let esk = get_mceliece_secret();
    let (vsk, _) = get_ed25519_keypair();
    ServerSecret {
        esk,
        vsk,
        obfs: get_obfuscation_key(),
    }
}

#[cfg(all(feature = "client", any(feature = "full_software", feature = "full_hardware")))]
#[inline]
fn create_test_certificate() -> ClientCertificate {
    let (_, vpk) = get_ed25519_keypair();
    let (_, opk) = get_x25519_keypair();
    ClientCertificate {
        epk: Arc::new(McEliecePublicKey::from(Box::new(*MCELIECE_KEYPAIR_BYTES.0))),
        vpk,
        opk,
        addresses: vec![],
    }
}

#[cfg(all(feature = "client", feature = "server", any(feature = "full_software", feature = "full_hardware")))]
#[inline]
fn create_test_server_secret() -> ServerSecret<'static> {
    let esk = get_mceliece_secret();
    let (vsk, _) = get_ed25519_keypair();
    let (osk, opk) = get_x25519_keypair();
    ServerSecret {
        esk,
        vsk,
        opk,
        osk,
    }
}

// TODO: end.

// Test: handshake produces matching shared secrets and session keys, with initial data exchange.
#[cfg(all(feature = "client", feature = "server"))]
#[test]
fn test_handshake_cycle() {
    let certificate = create_test_certificate();
    let server_secret = create_test_server_secret();

    let client_initial_data = b"Secret client initial data";
    let server_initial_data = b"Secret server initial data";

    // Client creates handshake with initial data encrypted inside.
    let (client_data, client_handshake, _client_initial_key) = certificate.encapsulate_handshake_client(&TEST_POOL, client_initial_data);

    // Server decapsulates and receives decrypted client initial data.
    let (server_data, server_initial_key, decrypted_client_initial_data) = server_secret.decapsulate_handshake_server(client_handshake);

    assert_eq!(client_data.shared_secret, server_data.shared_secret, "client and server should derive the same shared secret");
    assert_eq!(client_initial_data.as_slice(), decrypted_client_initial_data.slice(), "server should receive the same client initial data");

    // Server creates response with server initial data encrypted with initial key.
    let (server_handshake, server_session_key) = server_secret.encapsulate_handshake_server(server_data, &TEST_POOL, server_initial_data, &server_initial_key);

    // Client decapsulates and receives session key + decrypted server initial data.
    let (client_session_key, decrypted_server_initial_data) = certificate.decapsulate_handshake_client(client_data, server_handshake).expect("client handshake decapsulation failed");

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
    let certificate = create_test_certificate();
    let server_secret = create_test_server_secret();

    let client_initial_data = b"Tampered handshake test";

    let (client_data, client_handshake, _client_initial_key) = certificate.encapsulate_handshake_client(&TEST_POOL, client_initial_data);

    // Tamper with the handshake crypto header (not the encrypted initial data).
    let tampered_byte_idx = client_handshake.len() / 4;
    let original = *client_handshake.get(tampered_byte_idx);
    client_handshake.set(tampered_byte_idx, original ^ 0xFF);

    let (server_data, _server_initial_key, decrypted_client_initial_data) = server_secret.decapsulate_handshake_server(client_handshake);

    // Server should derive a different shared secret from tampered data.
    assert_ne!(client_data.shared_secret, server_data.shared_secret, "tampered handshake should produce different shared secrets");

    // Initial data decryption should fail (returns empty via unwrap_or_default).
    assert!(decrypted_client_initial_data.is_empty(), "decrypting initial data with wrong key should fail");
}

// Test: full mode encrypt/obfuscate then decrypt/deobfuscate cycle succeeds.
#[cfg(all(any(feature = "full_software", feature = "full_hardware"), feature = "client", feature = "server"))]
#[test]
fn test_obfuscate_cycle() {
    let certificate = create_test_certificate();
    let server_secret = create_test_server_secret();

    let plaintext_data = b"Secret initial data message";
    let plaintext_static = StaticByteBuffer::from(plaintext_data.as_slice());
    let plaintext = TEST_POOL.allocate_precise_from_slice_with_capacity(plaintext_data, 0, ENCRYPT_OBFUSCATE_HEADER + SYMMETRIC_BUILT_IN_AUTH_LEN);

    let ciphertext = certificate.encrypt_obfuscate(plaintext, &TEST_POOL).expect("encryption failed");
    let decrypted = server_secret.decrypt_deobfuscate(ciphertext).expect("decryption failed");

    assert_eq!(decrypted.slice(), plaintext_static.slice(), "decrypted message should match original");
}
