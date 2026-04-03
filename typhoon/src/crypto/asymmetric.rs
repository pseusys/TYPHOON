#[cfg(test)]
#[path = "../../tests/crypto/asymmetric.rs"]
mod tests;

use blake3::Hasher;
use blake3::hazmat::hash_derive_key_context;
use cfg_if::cfg_if;
use classic_mceliece_rust::{CRYPTO_BYTES, CRYPTO_CIPHERTEXTBYTES};
#[cfg(feature = "server")]
use classic_mceliece_rust::{Ciphertext, decapsulate};
#[cfg(feature = "client")]
use classic_mceliece_rust::encapsulate;
use ed25519_dalek::Signature;
use x25519_dalek::{EphemeralSecret, PublicKey};

use crate::bytes::{ByteBuffer, ByteBufferMut, BytePool, DynamicByteBuffer, FixedByteBuffer, StaticByteBuffer};
use crate::certificate::ObfuscationBufferContainer;
#[cfg(any(feature = "client", feature = "full_software", feature = "full_hardware"))]
use crate::crypto::error::HandshakeError;
use crate::crypto::symmetric::{ANONYMOUS_NONCE_LEN, decrypt_anonymously, encrypt_anonymously};
use crate::crypto::symmetric::Symmetric;
use crate::utils::random::{SupportRng, get_rng};

cfg_if! {
    if #[cfg(feature = "server")] {
        use ed25519_dalek::ed25519::signature::Signer;
        use crate::certificate::ServerSecret;
        use crate::crypto::ServerData;
    }
}

#[cfg(any(feature = "full_software", feature = "full_hardware"))]
use x25519_dalek::StaticSecret;

#[cfg(feature = "client")]
use crate::certificate::ClientCertificate;
#[cfg(feature = "client")]
use crate::crypto::ClientData;

const X25519_KEY_LENGTH: usize = 32;
const NONCE_LENGTH: usize = 32;

const CLIENT_HANDSHAKE_HEADER_SIZE: usize = X25519_KEY_LENGTH + CRYPTO_CIPHERTEXTBYTES + 2 * ANONYMOUS_NONCE_LEN + NONCE_LENGTH;
const SERVER_HANDSHAKE_HEADER_SIZE: usize = X25519_KEY_LENGTH + Signature::BYTE_SIZE + ANONYMOUS_NONCE_LEN + NONCE_LENGTH;

const INITIAL_DATA_KEY: &str = "handshake client obfuscation key";
const CLIENT_HANDSHAKE_OBFUSCATION_KEY: &str = "handshake client obfuscation key";
const SERVER_HANDSHAKE_OBFUSCATION_KEY: &str = "handshake server obfuscation key";
const SESSION_KEY: &str = "session key";

#[cfg(any(feature = "full_software", feature = "full_hardware"))]
const MARSHALLING_OBFUSCATION_KEY: &str = "marshalling obfuscation key";

#[cfg(any(feature = "full_software", feature = "full_hardware"))]
const MARSHALLING_ENCRYPTION_KEY: &str = "marshalling encryption key";

#[cfg(feature = "client")]
impl ClientCertificate {
    /// Client handshake: generate ephemeral keys, encapsulate with McEliece, obfuscate.
    /// If `initial_data` is non-empty, encrypts it with the initial key and appends to the handshake.
    /// Args: buffer pool, initial data bytes. Returns: (ClientData, handshake_secret, initial_encryption_key).
    pub(crate) fn encapsulate_handshake_client(&self, pool: &BytePool, initial_data: &[u8]) -> (ClientData, DynamicByteBuffer, FixedByteBuffer<32>) {
        let nonce = get_rng().random_byte_buffer::<NONCE_LENGTH>();

        let ephemeral_secret = EphemeralSecret::random_from_rng(get_rng());
        let mut ephemeral_public = pool.allocate_precise_from_array_with_capacity(&PublicKey::from(&ephemeral_secret).to_bytes(), 0, ANONYMOUS_NONCE_LEN);

        let mut shared_secret_buffer = [0u8; CRYPTO_BYTES];
        let (ciphertext, shared_secret) = encapsulate(&self.epk, &mut shared_secret_buffer, &mut get_rng());
        let mut ciphertext_buffer = pool.allocate_precise_from_array_with_capacity(ciphertext.as_array(), 0, ANONYMOUS_NONCE_LEN);
        let shared_fixed = FixedByteBuffer::from(shared_secret.as_array());

        let masking_key_hash = Hasher::new_keyed(&hash_derive_key_context(CLIENT_HANDSHAKE_OBFUSCATION_KEY)).update(self.obfuscation_buffer().slice()).update(nonce.slice()).finalize();

        let ephemeral_public_obfuscated = encrypt_anonymously(masking_key_hash.as_bytes(), &mut ephemeral_public);
        let ciphertext_obfuscated = encrypt_anonymously(masking_key_hash.as_bytes(), &mut ciphertext_buffer);

        let initial_encryption_key_hash = Hasher::new_keyed(&hash_derive_key_context(INITIAL_DATA_KEY)).update(shared_fixed.slice()).update(ephemeral_public_obfuscated.slice()).update(nonce.slice()).finalize();
        let initial_encryption_key = FixedByteBuffer::from(*initial_encryption_key_hash.as_bytes());

        let client_data = ClientData {
            ephemeral_key: ephemeral_secret,
            shared_secret: shared_fixed,
            nonce,
            initial_key: initial_encryption_key,
        };

        let handshake_buffer = pool.allocate_precise(0, 0, CLIENT_HANDSHAKE_HEADER_SIZE);
        let handshake_secret = handshake_buffer.append_buf(&ephemeral_public_obfuscated).append_buf(&ciphertext_obfuscated).append_buf(&nonce);

        let handshake_secret = if !initial_data.is_empty() {
            let plaintext = pool.allocate_precise_from_slice_with_capacity(initial_data, 0, 0);
            let mut cipher = Symmetric::new(&initial_encryption_key);
            let encrypted = cipher.encrypt_auth(plaintext, None::<&DynamicByteBuffer>).expect("initial data encryption failed");
            handshake_secret.append_buf(&encrypted)
        } else {
            handshake_secret
        };

        (client_data, handshake_secret, initial_encryption_key)
    }

    /// Process server handshake response: deobfuscate, verify signature, derive session key.
    /// If the response contains encrypted initial data beyond the crypto header, decrypts it with the initial key.
    /// Args: client ephemeral data, server handshake. Returns: (session_key, server_initial_data).
    pub(crate) fn decapsulate_handshake_client(&self, data: ClientData, handshake_secret: DynamicByteBuffer) -> Result<(FixedByteBuffer<32>, StaticByteBuffer), HandshakeError> {
        let (crypto_header, encrypted_initial_data) = if handshake_secret.len() > SERVER_HANDSHAKE_HEADER_SIZE {
            let (header, enc_data) = handshake_secret.split_buf(SERVER_HANDSHAKE_HEADER_SIZE);
            (header, Some(enc_data))
        } else {
            (handshake_secret, None)
        };

        let (mut ephemeral_public_obfuscated, rest) = crypto_header.split_buf(X25519_KEY_LENGTH + ANONYMOUS_NONCE_LEN);
        let (transcript_signed, nonce) = rest.split_buf(Signature::BYTE_SIZE);

        let masking_key_hash = Hasher::new_keyed(&hash_derive_key_context(SERVER_HANDSHAKE_OBFUSCATION_KEY)).update(self.obfuscation_buffer().slice()).update(nonce.slice()).finalize();
        let ephemeral_public_deobfuscated = decrypt_anonymously(masking_key_hash.as_bytes(), &mut ephemeral_public_obfuscated);

        let ephemeral_public_bytes: [u8; X25519_KEY_LENGTH] = (&ephemeral_public_deobfuscated).into();
        let ephemeral_public = PublicKey::from(ephemeral_public_bytes);
        let shared_secret = data.ephemeral_key.diffie_hellman(&ephemeral_public);

        let transcript_signed_bytes: [u8; Signature::BYTE_SIZE] = (&transcript_signed).into();
        let transcript_signed = Signature::from_bytes(&transcript_signed_bytes);
        let transcript = Hasher::new().update(data.shared_secret.slice()).update(shared_secret.as_bytes()).update(data.nonce.slice()).update(nonce.slice()).finalize();
        if let Err(err) = self.vpk.verify_strict(transcript.as_bytes(), &transcript_signed) {
            return Err(HandshakeError::handshake_authentication_error(&format!("server identity verification error: {}", err.to_string())));
        };

        let session_key_hash = Hasher::new_keyed(&hash_derive_key_context(SESSION_KEY)).update(data.shared_secret.slice()).update(shared_secret.as_bytes()).update(transcript.as_bytes()).finalize();
        let session_key = FixedByteBuffer::from(*session_key_hash.as_bytes());

        let initial_data = if let Some(encrypted) = encrypted_initial_data {
            let mut cipher = Symmetric::new(&data.initial_key);
            cipher.decrypt_auth(encrypted, None::<&DynamicByteBuffer>)
                .map(|buf| StaticByteBuffer::from_slice(buf.slice()))
                .map_err(|e| HandshakeError::handshake_crypto_error("decrypting server initial data", e))?
        } else {
            StaticByteBuffer::from_slice(&[])
        };

        Ok((session_key, initial_data))
    }

    /// Full mode: encrypt and obfuscate plaintext with X25519 ephemeral exchange.
    /// Args: plaintext. Returns: ciphertext || obfuscated_key || nonce.
    #[cfg(any(feature = "full_software", feature = "full_hardware"))]
    pub fn encrypt_obfuscate(&self, plaintext: DynamicByteBuffer, pool: &BytePool) -> Result<DynamicByteBuffer, HandshakeError> {
        let nonce = get_rng().random_byte_buffer::<NONCE_LENGTH>();

        let ephemeral_secret = StaticSecret::random_from_rng(get_rng());
        let mut ephemeral_public = pool.allocate_precise_from_array_with_capacity(&PublicKey::from(&ephemeral_secret).to_bytes(), 0, ANONYMOUS_NONCE_LEN);
        let shared_secret = ephemeral_secret.diffie_hellman(&self.opk);

        let masking_key_hash = Hasher::new_keyed(&hash_derive_key_context(MARSHALLING_OBFUSCATION_KEY)).update(self.opk.as_bytes()).update(nonce.slice()).finalize();
        let ephemeral_public_obfuscated = encrypt_anonymously(masking_key_hash.as_bytes(), &mut ephemeral_public);

        let encryption_key_hash = Hasher::new_keyed(&hash_derive_key_context(MARSHALLING_ENCRYPTION_KEY)).update(shared_secret.as_bytes()).finalize();
        let encryption_key = FixedByteBuffer::from(*encryption_key_hash.as_bytes());

        let ciphertext = Symmetric::new(&encryption_key).encrypt_auth(plaintext, Some(&nonce)).map_err(|e| HandshakeError::handshake_crypto_error("encrypting plaintext", e))?;
        let payload = ciphertext.append_buf(&ephemeral_public_obfuscated).append_buf(&nonce);
        Ok(payload)
    }
}

#[cfg(feature = "server")]
impl<'a> ServerSecret<'a> {
    /// Server decapsulate client handshake: deobfuscate, decapsulate McEliece, derive key.
    /// If the handshake contains encrypted initial data beyond the crypto header, decrypts it with the initial key.
    /// Args: client handshake_secret. Returns: (ServerData, initial_encryption_key, client_initial_data).
    pub fn decapsulate_handshake_server(&self, handshake_secret: DynamicByteBuffer) -> (ServerData, FixedByteBuffer<32>, StaticByteBuffer) {
        let (crypto_header, encrypted_initial_data) = if handshake_secret.len() > CLIENT_HANDSHAKE_HEADER_SIZE {
            let (header, enc_data) = handshake_secret.split_buf(CLIENT_HANDSHAKE_HEADER_SIZE);
            (header, Some(enc_data))
        } else {
            (handshake_secret, None)
        };

        let (mut ephemeral_public_obfuscated, rest) = crypto_header.split_buf(X25519_KEY_LENGTH + ANONYMOUS_NONCE_LEN);
        let (mut ciphertext_obfuscated, nonce) = rest.split_buf(CRYPTO_CIPHERTEXTBYTES + ANONYMOUS_NONCE_LEN);

        let masking_key_hash = Hasher::new_keyed(&hash_derive_key_context(CLIENT_HANDSHAKE_OBFUSCATION_KEY)).update(self.obfuscation_buffer().slice()).update(nonce.slice()).finalize();

        let ciphertext_buffer = decrypt_anonymously(masking_key_hash.as_bytes(), &mut ciphertext_obfuscated);
        let ciphertext_bytes: [u8; CRYPTO_CIPHERTEXTBYTES] = (&ciphertext_buffer).into();
        let ciphertext = Ciphertext::from(ciphertext_bytes);

        let mut shared_secret_buffer = [0u8; CRYPTO_BYTES];
        let shared_secret = decapsulate(&ciphertext, &self.esk, &mut shared_secret_buffer);

        let initial_encryption_key_hash = Hasher::new_keyed(&hash_derive_key_context(INITIAL_DATA_KEY)).update(shared_secret.as_array()).update(ephemeral_public_obfuscated.slice()).update(nonce.slice()).finalize();
        let initial_encryption_key = FixedByteBuffer::from(*initial_encryption_key_hash.as_bytes());

        let client_initial_data = if let Some(encrypted) = encrypted_initial_data {
            let mut cipher = Symmetric::new(&initial_encryption_key);
            cipher.decrypt_auth(encrypted, None::<&DynamicByteBuffer>)
                .map(|buf| StaticByteBuffer::from_slice(buf.slice()))
                .unwrap_or_else(|_| StaticByteBuffer::from_slice(&[]))
        } else {
            StaticByteBuffer::from_slice(&[])
        };

        let ephemeral_public_deobfuscated = decrypt_anonymously(masking_key_hash.as_bytes(), &mut ephemeral_public_obfuscated);
        let ephemeral_public_bytes: [u8; X25519_KEY_LENGTH] = (&ephemeral_public_deobfuscated).into();
        let ephemeral_public = PublicKey::from(ephemeral_public_bytes);
        let nonce_fixed = FixedByteBuffer::from(<[u8; NONCE_LENGTH]>::try_from(nonce.slice()).expect("nonce must be NONCE_LENGTH bytes"));

        let server_data = ServerData {
            ephemeral_key: ephemeral_public,
            shared_secret: FixedByteBuffer::from(shared_secret.as_array()),
            nonce: nonce_fixed,
        };

        (server_data, initial_encryption_key, client_initial_data)
    }

    /// Server handshake response: generate ephemeral X25519, sign transcript, derive session key.
    /// If `initial_data` is non-empty, encrypts it with the initial key and appends to the response.
    /// Args: server data, buffer pool, initial data bytes, initial key. Returns: (handshake_secret, session_key).
    pub fn encapsulate_handshake_server(&self, data: ServerData, pool: &BytePool, initial_data: &[u8], initial_key: &impl ByteBuffer) -> (DynamicByteBuffer, FixedByteBuffer<32>) {
        let nonce = get_rng().random_byte_buffer::<NONCE_LENGTH>();

        let ephemeral_secret = EphemeralSecret::random_from_rng(get_rng());
        let mut ephemeral_public = pool.allocate_precise_from_array_with_capacity(&PublicKey::from(&ephemeral_secret).to_bytes(), 0, ANONYMOUS_NONCE_LEN);
        let shared_secret = ephemeral_secret.diffie_hellman(&data.ephemeral_key);

        let transcript = Hasher::new().update(data.shared_secret.slice()).update(shared_secret.as_bytes()).update(data.nonce.slice()).update(nonce.slice()).finalize();
        let transcript_signed = self.vsk.sign(transcript.as_bytes());

        let masking_key_hash = Hasher::new_keyed(&hash_derive_key_context(SERVER_HANDSHAKE_OBFUSCATION_KEY)).update(self.obfuscation_buffer().slice()).update(nonce.slice()).finalize();
        let ephemeral_public_obfuscated = encrypt_anonymously(masking_key_hash.as_bytes(), &mut ephemeral_public);

        let session_key_hash = Hasher::new_keyed(&hash_derive_key_context(SESSION_KEY)).update(data.shared_secret.slice()).update(shared_secret.as_bytes()).update(transcript.as_bytes()).finalize();
        let session_key = FixedByteBuffer::from(*session_key_hash.as_bytes());

        let handshake_buffer = pool.allocate_precise(0, 0, SERVER_HANDSHAKE_HEADER_SIZE);
        let handshake_secret = handshake_buffer.append_buf(&ephemeral_public_obfuscated).append(&transcript_signed.to_bytes()).append_buf(&nonce);

        let handshake_secret = if !initial_data.is_empty() {
            let plaintext = pool.allocate_precise_from_slice_with_capacity(initial_data, 0, 0);
            let mut cipher = Symmetric::new(initial_key);
            let encrypted = cipher.encrypt_auth(plaintext, None::<&DynamicByteBuffer>).expect("server initial data encryption failed");
            handshake_secret.append_buf(&encrypted)
        } else {
            handshake_secret
        };

        (handshake_secret, session_key)
    }

    /// Full mode: deobfuscate and decrypt ciphertext using server's X25519 secret.
    /// Args: ciphertext || obfuscated_key || nonce. Returns: plaintext.
    #[cfg(any(feature = "full_software", feature = "full_hardware"))]
    pub fn decrypt_deobfuscate(&self, ciphertext: DynamicByteBuffer) -> Result<DynamicByteBuffer, HandshakeError> {
        let (ciphertext, rest) = ciphertext.split_buf(ciphertext.len() - X25519_KEY_LENGTH - ANONYMOUS_NONCE_LEN - NONCE_LENGTH);
        let (mut ephemeral_public_obfuscated, nonce) = rest.split_buf(rest.len() - NONCE_LENGTH);

        let masking_key_hash = Hasher::new_keyed(&hash_derive_key_context(MARSHALLING_OBFUSCATION_KEY)).update(self.opk.as_bytes()).update(nonce.slice()).finalize();
        let ephemeral_public_deobfuscated = decrypt_anonymously(masking_key_hash.as_bytes(), &mut ephemeral_public_obfuscated);

        let ephemeral_public_bytes: [u8; X25519_KEY_LENGTH] = (&ephemeral_public_deobfuscated).into();
        let ephemeral_public = PublicKey::from(ephemeral_public_bytes);
        let shared_secret = self.osk.diffie_hellman(&ephemeral_public);

        let encryption_key_hash = Hasher::new_keyed(&hash_derive_key_context(MARSHALLING_ENCRYPTION_KEY)).update(shared_secret.as_bytes()).finalize();
        let encryption_key = FixedByteBuffer::from(*encryption_key_hash.as_bytes());

        Symmetric::new(&encryption_key).decrypt_auth(ciphertext, Some(&nonce)).map_err(|e| HandshakeError::handshake_crypto_error("decrypting plaintext", e))
    }
}
