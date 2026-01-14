#[cfg(test)]
#[path = "../../tests/crypto/asymmetric.rs"]
mod tests;

use blake3::Hasher;
use blake3::hazmat::hash_derive_key_context;
use cfg_if::cfg_if;
use classic_mceliece_rust::{CRYPTO_BYTES, CRYPTO_CIPHERTEXTBYTES, Ciphertext, decapsulate, encapsulate};
use ed25519_dalek::Signature;
use generic_array::typenum::U32;
use x25519_dalek::{EphemeralSecret, PublicKey};

use crate::bytes::ByteBuffer;
use crate::crypto::certificate::ObfuscationBufferContainer;
use crate::crypto::error::CryptoError;
use crate::crypto::symmetric::{ANONYMOUS_NONCE_LEN, Symmetric, decrypt_anonymously, encrypt_anonymously};
use crate::random::{SupportRng, get_rng};

cfg_if! {
    if #[cfg(feature = "server")] {
        use ed25519_dalek::ed25519::signature::SignerMut;
        use crate::crypto::certificate::{ServerData, ServerSecret};
    }
}

#[cfg(feature = "full")]
use x25519_dalek::StaticSecret;

#[cfg(feature = "client")]
use crate::crypto::certificate::{Certificate, ClientData};

const X25519_KEY_LENGTH: usize = 32;
const NONCE_LENGTH: usize = 32;

const INITIAL_DATA_KEY: &str = "handshake client obfuscation key";
const CLIENT_HANDSHAKE_OBFUSCATION_KEY: &str = "handshake client obfuscation key";
const SERVER_HANDSHAKE_OBFUSCATION_KEY: &str = "handshake server obfuscation key";
const SESSION_KEY: &str = "session key";

#[cfg(feature = "full")]
const MARSHALLING_OBFUSCATION_KEY: &str = "marshalling obfuscation key";

#[cfg(feature = "full")]
const MARSHALLING_ENCRYPTION_KEY: &str = "marshalling encryption key";

#[cfg(feature = "client")]
impl<'a> Certificate<'a> {
    /// Client handshake: generate ephemeral keys, encapsulate with McEliece, obfuscate.
    /// Args: buffer for nonce. Returns: (ClientData, handshake_secret, initial_cipher).
    pub fn encapsulate_handshake_client(&self) -> Result<(ClientData, ByteBuffer, Symmetric), CryptoError> {
        let nonce = ByteBuffer::from(get_rng().random_byte_array::<U32>().as_slice());

        let ephemeral_secret = EphemeralSecret::random_from_rng(get_rng());
        let mut ephemeral_public = ByteBuffer::from_array_with_capacity(&PublicKey::from(&ephemeral_secret).to_bytes(), 0, ANONYMOUS_NONCE_LEN);

        let mut shared_secret_buffer = [0u8; CRYPTO_BYTES];
        let (ciphertext, shared_secret) = encapsulate(&self.epk, &mut shared_secret_buffer, &mut get_rng());
        let mut ciphertext_buffer = ByteBuffer::from_array_with_capacity(ciphertext.as_array(), 0, ANONYMOUS_NONCE_LEN);
        let shared_buffer = ByteBuffer::from(shared_secret.as_array());

        let masking_key_hash = Hasher::new_keyed(&hash_derive_key_context(CLIENT_HANDSHAKE_OBFUSCATION_KEY)).update(&self.obfuscation_buffer().slice()).update(&nonce.slice()).finalize();
        let masking_key = ByteBuffer::from(masking_key_hash.as_bytes());
        let ephemeral_public_obfuscated = encrypt_anonymously(&masking_key, &mut ephemeral_public)?;
        let ciphertext_obfuscated = encrypt_anonymously(&masking_key, &mut ciphertext_buffer)?;

        let initial_encryption_key_hash = Hasher::new_keyed(&hash_derive_key_context(INITIAL_DATA_KEY)).update(&shared_buffer.slice()).update(&ephemeral_public_obfuscated.slice()).update(&nonce.slice()).finalize();
        let initial_encryption_key = ByteBuffer::from(initial_encryption_key_hash.as_bytes());

        let client_data = ClientData {
            ephemeral_key: ephemeral_secret,
            shared_secret: shared_buffer,
            nonce: nonce.copy(),
        };
        let handshake_buffer = ByteBuffer::empty_with_capacity(0, 0, X25519_KEY_LENGTH + CRYPTO_CIPHERTEXTBYTES + ANONYMOUS_NONCE_LEN * 2 + NONCE_LENGTH);
        let handshake_secret = handshake_buffer.append_buf(&ephemeral_public_obfuscated).append_buf(&ciphertext_obfuscated).append_buf(&nonce);
        let initial_encryption_symmetric = Symmetric::new(&initial_encryption_key)?;
        Ok((client_data, handshake_secret, initial_encryption_symmetric))
    }

    /// Process server handshake response: deobfuscate, verify signature, derive session key.
    /// Args: client ephemeral data, server handshake. Returns: session cipher.
    pub fn decapsulate_handshake_client(&self, data: ClientData, handshake_secret: ByteBuffer) -> Result<Symmetric, CryptoError> {
        let (mut ephemeral_public_obfuscated, rest) = handshake_secret.split_buf(X25519_KEY_LENGTH + ANONYMOUS_NONCE_LEN);
        let (transcript_signed, nonce) = rest.split_buf(Signature::BYTE_SIZE);

        let masking_key_hash = Hasher::new_keyed(&hash_derive_key_context(SERVER_HANDSHAKE_OBFUSCATION_KEY)).update(&self.obfuscation_buffer().slice()).update(&nonce.slice()).finalize();
        let masking_key = ByteBuffer::from(masking_key_hash.as_bytes());
        let ephemeral_public_deobfuscated = decrypt_anonymously(&masking_key, &mut ephemeral_public_obfuscated)?;

        let ephemeral_public_bytes: [u8; X25519_KEY_LENGTH] = match (&ephemeral_public_deobfuscated).try_into() {
            Ok(res) => res,
            Err(err) => return Err(CryptoError::ArrayExtractionError(err)),
        };
        let ephemeral_public = PublicKey::from(ephemeral_public_bytes);
        let shared_secret = data.ephemeral_key.diffie_hellman(&ephemeral_public);

        let transcript_signed_bytes: [u8; Signature::BYTE_SIZE] = match (&transcript_signed).try_into() {
            Ok(res) => res,
            Err(err) => return Err(CryptoError::ArrayExtractionError(err)),
        };
        let transcript_signed = Signature::from_bytes(&transcript_signed_bytes);
        let transcript = Hasher::new().update(&data.shared_secret.slice()).update(shared_secret.as_bytes()).update(&data.nonce.slice()).update(&nonce.slice()).finalize();
        if let Err(err) = self.vpk.verify_strict(transcript.as_bytes(), &transcript_signed) {
            return Err(CryptoError::AuthenticationError(format!("server identity verification error: {}", err.to_string())));
        };

        let session_key_hash = Hasher::new_keyed(&hash_derive_key_context(SESSION_KEY)).update(&data.shared_secret.slice()).update(shared_secret.as_bytes()).update(transcript.as_bytes()).finalize();
        let session_key = ByteBuffer::from(session_key_hash.as_bytes());
        let session_symmetric = Symmetric::new(&session_key)?;
        Ok(session_symmetric)
    }

    /// Full mode: encrypt and obfuscate plaintext with X25519 ephemeral exchange.
    /// Args: plaintext. Returns: nonce || obfuscated_key || ciphertext.
    #[cfg(feature = "full")]
    pub fn encrypt_obfuscate(&self, plaintext: ByteBuffer) -> Result<ByteBuffer, CryptoError> {
        let nonce = ByteBuffer::from(get_rng().random_byte_array::<U32>().as_slice());

        let ephemeral_secret = StaticSecret::random_from_rng(get_rng());
        let mut ephemeral_public = ByteBuffer::from_array_with_capacity(&PublicKey::from(&ephemeral_secret).to_bytes(), 0, ANONYMOUS_NONCE_LEN);
        let shared_secret = ephemeral_secret.diffie_hellman(&self.opk);

        let masking_key_hash = Hasher::new_keyed(&hash_derive_key_context(MARSHALLING_OBFUSCATION_KEY)).update(self.opk.as_bytes()).update(&nonce.slice()).finalize();
        let masking_key = ByteBuffer::from(masking_key_hash.as_bytes());
        let ephemeral_public_obfuscated = encrypt_anonymously(&masking_key, &mut ephemeral_public)?;

        let encryption_key_hash = Hasher::new_keyed(&hash_derive_key_context(MARSHALLING_ENCRYPTION_KEY)).update(shared_secret.as_bytes()).finalize();
        let encryption_key = ByteBuffer::from(encryption_key_hash.as_bytes());

        let ciphertext = Symmetric::new(&encryption_key)?.encrypt_auth(plaintext, Some(&nonce))?;
        let payload = ciphertext.prepend_buf(&ephemeral_public_obfuscated).prepend_buf(&nonce);
        Ok(payload)
    }
}

#[cfg(feature = "server")]
impl<'a> ServerSecret<'a> {
    /// Server decapsulate client handshake: deobfuscate, decapsulate McEliece, derive cipher.
    /// Args: client handshake_secret. Returns: (ServerData, initial_cipher).
    fn decapsulate_handshake_server(&self, handshake_secret: ByteBuffer) -> Result<(ServerData, Symmetric), CryptoError> {
        let (mut ephemeral_public_obfuscated, rest) = handshake_secret.split_buf(X25519_KEY_LENGTH + ANONYMOUS_NONCE_LEN);
        let (mut ciphertext_obfuscated, nonce) = rest.split_buf(CRYPTO_CIPHERTEXTBYTES + ANONYMOUS_NONCE_LEN);

        let masking_key_hash = Hasher::new_keyed(&hash_derive_key_context(CLIENT_HANDSHAKE_OBFUSCATION_KEY)).update(&self.obfuscation_buffer().slice()).update(&nonce.slice()).finalize();
        let masking_key = ByteBuffer::from(masking_key_hash.as_bytes());

        let ciphertext_buffer = decrypt_anonymously(&masking_key, &mut ciphertext_obfuscated)?;
        let ciphertext_bytes: [u8; CRYPTO_CIPHERTEXTBYTES] = match (&ciphertext_buffer).try_into() {
            Ok(res) => res,
            Err(err) => return Err(CryptoError::ArrayExtractionError(err)),
        };
        let ciphertext = Ciphertext::from(ciphertext_bytes);

        let mut shared_secret_buffer = [0u8; CRYPTO_BYTES];
        let shared_secret = decapsulate(&ciphertext, &self.esk, &mut shared_secret_buffer);
        let shared_buffer = ByteBuffer::from(shared_secret.as_array());

        let initial_encryption_key_hash = Hasher::new_keyed(&hash_derive_key_context(INITIAL_DATA_KEY)).update(shared_secret.as_array()).update(&ephemeral_public_obfuscated.slice()).update(&nonce.slice()).finalize();
        let initial_encryption_key = ByteBuffer::from(initial_encryption_key_hash.as_bytes());

        let ephemeral_public_deobfuscated = decrypt_anonymously(&masking_key, &mut ephemeral_public_obfuscated)?;
        let ephemeral_public_bytes: [u8; X25519_KEY_LENGTH] = match (&ephemeral_public_deobfuscated).try_into() {
            Ok(res) => res,
            Err(err) => return Err(CryptoError::ArrayExtractionError(err)),
        };
        let ephemeral_public = PublicKey::from(ephemeral_public_bytes);

        let server_data = ServerData {
            ephemeral_key: ephemeral_public,
            shared_secret: shared_buffer,
            nonce: nonce.copy(),
        };
        let initial_encryption_symmetric = Symmetric::new(&initial_encryption_key)?;
        Ok((server_data, initial_encryption_symmetric))
    }

    /// Server handshake response: generate ephemeral X25519, sign transcript, derive session key.
    /// Args: server data, buffer. Returns: (handshake_secret, session_cipher).
    fn encapsulate_handshake_server(&mut self, data: ServerData) -> Result<(ByteBuffer, Symmetric), CryptoError> {
        let nonce = ByteBuffer::from(get_rng().random_byte_array::<U32>().as_slice());

        let ephemeral_secret = EphemeralSecret::random_from_rng(get_rng());
        let mut ephemeral_public = ByteBuffer::from_array_with_capacity(&PublicKey::from(&ephemeral_secret).to_bytes(), 0, ANONYMOUS_NONCE_LEN);
        let shared_secret = ephemeral_secret.diffie_hellman(&data.ephemeral_key);

        let transcript = Hasher::new().update(&data.shared_secret.slice()).update(shared_secret.as_bytes()).update(&data.nonce.slice()).update(&nonce.slice()).finalize();
        let transcript_signed = self.vsk.sign(transcript.as_bytes());

        let masking_key_hash = Hasher::new_keyed(&hash_derive_key_context(SERVER_HANDSHAKE_OBFUSCATION_KEY)).update(&self.obfuscation_buffer().slice()).update(&nonce.slice()).finalize();
        let masking_key = ByteBuffer::from(masking_key_hash.as_bytes());
        let ephemeral_public_obfuscated = encrypt_anonymously(&masking_key, &mut ephemeral_public)?;

        let session_key_hash = Hasher::new_keyed(&hash_derive_key_context(SESSION_KEY)).update(&data.shared_secret.slice()).update(shared_secret.as_bytes()).update(transcript.as_bytes()).finalize();
        let session_key = ByteBuffer::from(session_key_hash.as_bytes());

        let handshake_buffer = ByteBuffer::empty_with_capacity(0, 0, X25519_KEY_LENGTH + Signature::BYTE_SIZE + ANONYMOUS_NONCE_LEN + NONCE_LENGTH);
        let handshake_secret = handshake_buffer.append_buf(&ephemeral_public_obfuscated).append(&transcript_signed.to_bytes()).append_buf(&nonce);
        let session_symmetric = Symmetric::new(&session_key)?;
        Ok((handshake_secret, session_symmetric))
    }

    /// Full mode: deobfuscate and decrypt ciphertext using server's X25519 secret.
    /// Args: nonce || obfuscated_key || ciphertext. Returns: plaintext.
    #[cfg(feature = "full")]
    pub fn decrypt_deobfuscate(&self, ciphertext: ByteBuffer) -> Result<ByteBuffer, CryptoError> {
        let (nonce, rest) = ciphertext.split_buf(NONCE_LENGTH);
        let (mut ephemeral_public_obfuscated, ciphertext) = rest.split_buf(X25519_KEY_LENGTH + ANONYMOUS_NONCE_LEN);

        let masking_key_hash = Hasher::new_keyed(&hash_derive_key_context(MARSHALLING_OBFUSCATION_KEY)).update(self.opk.as_bytes()).update(&nonce.slice()).finalize();
        let masking_key = ByteBuffer::from(masking_key_hash.as_bytes());
        let ephemeral_public_deobfuscated = decrypt_anonymously(&masking_key, &mut ephemeral_public_obfuscated)?;

        let ephemeral_public_bytes: [u8; X25519_KEY_LENGTH] = match (&ephemeral_public_deobfuscated).try_into() {
            Ok(res) => res,
            Err(err) => return Err(CryptoError::ArrayExtractionError(err)),
        };
        let ephemeral_public = PublicKey::from(ephemeral_public_bytes);
        let shared_secret = self.osk.diffie_hellman(&ephemeral_public);

        let encryption_key_hash = Hasher::new_keyed(&hash_derive_key_context(MARSHALLING_ENCRYPTION_KEY)).update(shared_secret.as_bytes()).finalize();
        let encryption_key = ByteBuffer::from(encryption_key_hash.as_bytes());

        let plaintext = Symmetric::new(&encryption_key)?.decrypt_auth(ciphertext, Some(&nonce))?;
        Ok(plaintext)
    }
}
