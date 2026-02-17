use std::sync::{Arc, Mutex};

use classic_mceliece_rust::{CRYPTO_PUBLICKEYBYTES, CRYPTO_SECRETKEYBYTES, PublicKey as McEliecePublicKey, SecretKey, keypair_boxed};
use ed25519_dalek::{SecretKey as X25519SecretKey, SigningKey, VerifyingKey};
use lazy_static::lazy_static;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

use crate::bytes::{ByteBuffer, BytePool, StaticByteBuffer};
#[cfg(feature = "client")]
use crate::crypto::certificate::Certificate;
#[cfg(feature = "server")]
use crate::crypto::certificate::ServerSecret;
#[cfg(any(feature = "full_software", feature = "full_hardware"))]
use crate::crypto::symmetric::ANONYMOUS_NONCE_LEN;
#[cfg(any(feature = "fast_software", feature = "fast_hardware"))]
use crate::crypto::symmetric::SYMMETRIC_KEY_LENGTH;
use crate::crypto::symmetric::{NONCE_LEN, SYMMETRIC_BUILT_IN_AUTH_LEN, Symmetric};
use crate::utils::random::get_rng;

const X25519_KEY_LENGTH: usize = 32;
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

#[cfg(any(feature = "fast_software", feature = "fast_hardware"))]
#[inline]
fn get_obfuscation_key() -> StaticByteBuffer {
    StaticByteBuffer::from(&[0x55u8; SYMMETRIC_KEY_LENGTH])
}

#[inline]
fn get_mceliece_secret() -> SecretKey<'static> {
    SecretKey::from(Box::new(*MCELIECE_KEYPAIR_BYTES.1))
}

#[inline]
fn get_ed25519_keypair() -> (SigningKey, VerifyingKey) {
    (ED25519_KEYPAIR.0.clone(), ED25519_KEYPAIR.1)
}

#[inline]
fn get_x25519_keypair() -> (StaticSecret, X25519PublicKey) {
    let bytes = *X25519_SECRET_BYTES.lock().unwrap();
    let secret = StaticSecret::from(bytes);
    let public = X25519PublicKey::from(&secret);
    (secret, public)
}

// TODO: move to cert creation:

#[cfg(all(feature = "client", any(feature = "fast_software", feature = "fast_hardware")))]
#[inline]
fn create_test_certificate() -> Certificate {
    let (_, vpk) = get_ed25519_keypair();
    Certificate {
        epk: Arc::new(McEliecePublicKey::from(Box::new(*MCELIECE_KEYPAIR_BYTES.0))),
        vpk,
        obfs: get_obfuscation_key(),
    }
}

#[cfg(all(feature = "server", any(feature = "fast_software", feature = "fast_hardware")))]
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
fn create_test_certificate() -> Certificate {
    let (_, vpk) = get_ed25519_keypair();
    let (_, opk) = get_x25519_keypair();
    Certificate {
        epk: Arc::new(McEliecePublicKey::from(Box::new(*MCELIECE_KEYPAIR_BYTES.0))),
        vpk,
        opk,
    }
}

#[cfg(all(feature = "server", any(feature = "full_software", feature = "full_hardware")))]
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

// Test: handshake produces matching shared secrets and session keys.
#[cfg(all(feature = "client", feature = "server"))]
#[test]
fn test_handshake_cycle() {
    let certificate = create_test_certificate();
    let server_secret = create_test_server_secret();

    let initial_data_data = b"Secret initial data message";
    let initial_data = TEST_POOL.allocate_precise_from_slice_with_capacity(initial_data_data, 0, NONCE_LEN + SYMMETRIC_BUILT_IN_AUTH_LEN);

    let (client_data, client_handshake, mut client_initial_cipher) = certificate.encapsulate_handshake_client(&TEST_POOL);
    let initial_data_encrypted = client_initial_cipher.encrypt_auth(initial_data, None::<&StaticByteBuffer>).expect("initial data encryption failed");

    let (server_data, mut server_initial_cipher) = server_secret.decapsulate_handshake_server(client_handshake);
    let initial_data_decrypted = server_initial_cipher.decrypt_auth(initial_data_encrypted, None::<&StaticByteBuffer>).expect("initial data decryption failed");

    assert_eq!(client_data.shared_secret, server_data.shared_secret, "client and server should derive the same shared secret");
    assert_eq!(initial_data_data.as_slice(), initial_data_decrypted.slice(), "client and server should get the same initial data");

    let session_data_data = b"Secret session data message";
    let session_data = TEST_POOL.allocate_precise_from_slice_with_capacity(session_data_data, 0, NONCE_LEN + SYMMETRIC_BUILT_IN_AUTH_LEN);

    let (server_handshake, mut server_session_cipher) = server_secret.encapsulate_handshake_server(server_data, &TEST_POOL);
    let session_data_encrypted = server_session_cipher.encrypt_auth(session_data, None::<&StaticByteBuffer>).expect("session data encryption failed");

    let client_session_key_bytes = certificate.decapsulate_handshake_client(client_data, server_handshake).expect("client handshake decapsulation failed");
    let mut client_session_cipher = Symmetric::new(&client_session_key_bytes);
    let session_data_decrypted = client_session_cipher.decrypt_auth(session_data_encrypted, None::<&StaticByteBuffer>).expect("session data decryption failed");

    assert_eq!(session_data_data.as_slice(), session_data_decrypted.slice(), "client and server should get the same session data");
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
