use classic_mceliece_rust::{CRYPTO_PUBLICKEYBYTES, CRYPTO_SECRETKEYBYTES, PublicKey as McEliecePublicKey, SecretKey, keypair_boxed};
use ed25519_dalek::{SecretKey as X25519SecretKey, SigningKey, VerifyingKey};
use lazy_static::lazy_static;
use std::sync::Mutex;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

use crate::bytes::ByteBuffer;
use crate::crypto::symmetric::{NONCE_LEN, SYMMETRIC_FIRST_AUTH_LEN};

#[cfg(feature = "full")]
use crate::crypto::symmetric::ANONYMOUS_NONCE_LEN;

#[cfg(feature = "fast")]
use crate::crypto::symmetric::SYMMETRIC_KEY_LENGTH;

#[cfg(feature = "client")]
use crate::crypto::certificate::Certificate;

#[cfg(feature = "server")]
use crate::crypto::certificate::ServerSecret;

use crate::random::get_rng;

const X25519_KEY_LENGTH: usize = 32;
const NONCE_LENGTH: usize = 32;

#[cfg(feature = "full")]
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
}

#[cfg(feature = "fast")]
#[inline]
fn get_obfuscation_key() -> ByteBuffer {
    ByteBuffer::from(&[0x55u8; SYMMETRIC_KEY_LENGTH])
}

#[inline]
fn get_mceliece_keypair() -> (McEliecePublicKey<'static>, SecretKey<'static>) {
    let pk = McEliecePublicKey::from(Box::new(*MCELIECE_KEYPAIR_BYTES.0));
    let sk = SecretKey::from(Box::new(*MCELIECE_KEYPAIR_BYTES.1));
    (pk, sk)
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

#[cfg(all(feature = "client", feature = "fast"))]
#[inline]
fn create_test_certificate() -> Certificate<'static> {
    let (epk, _) = get_mceliece_keypair();
    let (_, vpk) = get_ed25519_keypair();
    Certificate {
        epk,
        vpk,
        obfs: get_obfuscation_key(),
    }
}

#[cfg(all(feature = "server", feature = "fast"))]
#[inline]
fn create_test_server_secret() -> ServerSecret<'static> {
    let (_, esk) = get_mceliece_keypair();
    let (vsk, _) = get_ed25519_keypair();
    ServerSecret {
        esk,
        vsk,
        obfs: get_obfuscation_key(),
    }
}

#[cfg(all(feature = "client", feature = "full"))]
#[inline]
fn create_test_certificate() -> Certificate<'static> {
    let (epk, _) = get_mceliece_keypair();
    let (_, vpk) = get_ed25519_keypair();
    let (_, opk) = get_x25519_keypair();
    Certificate {
        epk,
        vpk,
        opk,
    }
}

#[cfg(all(feature = "server", feature = "full"))]
#[inline]
fn create_test_server_secret() -> ServerSecret<'static> {
    let (_, esk) = get_mceliece_keypair();
    let (vsk, _) = get_ed25519_keypair();
    let (osk, opk) = get_x25519_keypair();
    ServerSecret {
        esk,
        vsk,
        opk,
        osk,
    }
}

// Test: handshake produces matching shared secrets and session keys.
#[cfg(all(feature = "client", feature = "server"))]
#[test]
fn test_handshake_cycle() {
    let certificate = create_test_certificate();
    let mut server_secret = create_test_server_secret();

    let initial_data_data = b"Secret initial data message";
    let initial_data = ByteBuffer::from_slice_with_capacity(initial_data_data, NONCE_LEN, SYMMETRIC_FIRST_AUTH_LEN);

    let (client_data, client_handshake, mut client_initial_cipher) = certificate.encapsulate_handshake_client().expect("client handshake encapsulation failed");
    let initial_data_encrypted = client_initial_cipher.encrypt_auth(initial_data, None).expect("initial data encryption failed");

    let (server_data, mut server_initial_cipher) = server_secret.decapsulate_handshake_server(client_handshake).expect("server handshake decapsulation failed");
    let initial_data_decrypted = server_initial_cipher.decrypt_auth(initial_data_encrypted, None).expect("initial data decryption failed");

    assert_eq!(client_data.shared_secret, server_data.shared_secret, "client and server should derive the same shared secret");
    assert_eq!(initial_data_data, initial_data_decrypted.slice(), "client and server should get the same initial data");

    let session_data_data = b"Secret session data message";
    let session_data = ByteBuffer::from_slice_with_capacity(session_data_data, NONCE_LEN, SYMMETRIC_FIRST_AUTH_LEN);

    let (server_handshake, mut server_session_cipher) = server_secret.encapsulate_handshake_server(server_data).expect("server handshake encapsulation failed");
    let session_data_encrypted = server_session_cipher.encrypt_auth(session_data, None).expect("session data encryption failed");

    let mut client_session_key = certificate.decapsulate_handshake_client(client_data, server_handshake).expect("client handshake decapsulation failed");
    let session_data_decrypted = client_session_key.decrypt_auth(session_data_encrypted, None).expect("session data decryption failed");

    assert_eq!(session_data_data, session_data_decrypted.slice(), "client and server should get the same session data");
}

// Test: full mode encrypt/obfuscate then decrypt/deobfuscate cycle succeeds.
#[cfg(all(feature = "full", feature = "client", feature = "server"))]
#[test]
fn test_obfuscate_cycle() {
    let certificate = create_test_certificate();
    let server_secret = create_test_server_secret();

    let plaintext_data = ByteBuffer::from(b"Secret initial data message");
    let plaintext = ByteBuffer::from_slice_with_capacity(plaintext_data.slice(), ENCRYPT_OBFUSCATE_HEADER, SYMMETRIC_FIRST_AUTH_LEN);

    let ciphertext = certificate.encrypt_obfuscate(plaintext).expect("encryption failed");
    let decrypted = server_secret.decrypt_deobfuscate(ciphertext).expect("decryption failed");

    assert_eq!(decrypted, plaintext_data, "decrypted message should match original");
}
