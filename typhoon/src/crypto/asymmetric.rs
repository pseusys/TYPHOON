use blake3::{KEY_LEN, Hasher};
use blake3::hazmat::hash_derive_key_context;
use classic_mceliece_rust::{CRYPTO_BYTES, encapsulate};
use ed25519_dalek::Signature;
use generic_array::typenum::U32;
use simple_error::try_with;
use x25519_dalek::{PublicKey, EphemeralSecret};

use crate::bytes::ByteBuffer;
use crate::crypto::certificate::ClientData;
use crate::crypto::symmetric::{Symmetric, encrypt_anonymously, decrypt_anonymously};
use crate::random::{DEFAULT_KEY_LENGTH, SupportRng, get_rng};
use crate::generic::DynResult;

#[cfg(all(feature = "client"))]
use crate::crypto::certificate::Certificate;

#[cfg(all(feature = "server"))]
use crate::crypto::certificate::ServerData;

const X25519_KEY_LENGTH: usize = 32;

const INITIAL_DATA_KEY: &str = "handshake client obfuscation key";
const CLIENT_OBFUSCATION_KEY: &str = "handshake client obfuscation key";
const SERVER_OBFUSCATION_KEY: &str = "handshake server obfuscation key";
const SESSION_KEY: &str = "session key";

#[cfg(all(feature = "client"))]
impl Certificate<'_> {
    pub fn encrypt<'a, 'b>(&'_ self, plaintext: ByteBuffer<'a>, initial_data: Option<ByteBuffer<'b>>) -> DynResult<(ByteBuffer<'a>, Option<ByteBuffer<'b>>, ClientData<'_>)> {
        let nonce = ByteBuffer::from(&get_rng().random_byte_array::<U32>()[..]);

        let ephemeral_secret = EphemeralSecret::random_from_rng(get_rng());
        let mut ephemeral_public = ByteBuffer::from(&PublicKey::from(&ephemeral_secret).to_bytes()[..]);

        let mut shared_secret_buffer = [0u8; CRYPTO_BYTES];
        let (ciphertext, shared_secret) = encapsulate(&self.epk, &mut shared_secret_buffer, &mut get_rng());
        let mut ciphertext_buffer = ByteBuffer::from(&ciphertext.as_array()[..]);
        let shared_buffer = ByteBuffer::from(&shared_secret.as_array()[..]);

        let masking_key_hash = Hasher::new_keyed(&hash_derive_key_context(CLIENT_OBFUSCATION_KEY)).update(&self.obfs.slice()).update(&nonce.slice()).finalize();
        let masking_key = ByteBuffer::from(&masking_key_hash.as_bytes()[..]);
        let ephemeral_public_obfuscated = encrypt_anonymously(&masking_key, &mut ephemeral_public)?;
        let ciphertext_obfuscated = encrypt_anonymously(&masking_key, &mut ciphertext_buffer)?;

        let initial_encryption_key_hash = Hasher::new_keyed(&hash_derive_key_context(INITIAL_DATA_KEY)).update(&shared_buffer.slice()).update(&ephemeral_public_obfuscated.slice()).update(&nonce.slice()).finalize();
        let initial_encryption_key = ByteBuffer::from(&initial_encryption_key_hash.as_bytes()[..]);

        let tailor = Symmetric::new(&self.obfs)?.encrypt_auth_twice(plaintext, None, &initial_encryption_key)?.append_buf(&nonce).append_buf(&ciphertext_obfuscated).append_buf(&ephemeral_public_obfuscated);
        let client_data = ClientData {
            private_key: ephemeral_secret,
            shared_secret: shared_buffer,
            nonce,
        };

        if let Some(initial) = initial_data {
            let initial_encrypted = Symmetric::new(&initial_encryption_key)?.encrypt_auth(initial, None)?;
            Ok((tailor, Some(initial_encrypted), client_data))
        } else {
            Ok((tailor, None, client_data))
        }
    }

    pub fn decrypt<'a, 'b>(&self, ciphertext: ByteBuffer<'a>, initial_data: Option<ByteBuffer<'b>>, data: ClientData) -> DynResult<(ByteBuffer<'a>, Option<ByteBuffer<'b>>, Symmetric)> {
        let (ciphertext, rest) = ciphertext.split_buf(KEY_LEN);
        let (mut ephemeral_public_obfuscated, rest) = rest.split_buf(X25519_KEY_LENGTH);
        let (transcript_authenticated, rest) = rest.split_buf(Signature::BYTE_SIZE);
        let nonce = rest.rebuffer_end(DEFAULT_KEY_LENGTH);

        let masking_key_hash = Hasher::new_keyed(&hash_derive_key_context(SERVER_OBFUSCATION_KEY)).update(&self.obfs.slice()).update(&nonce.slice()).finalize();
        let masking_key = ByteBuffer::from(&masking_key_hash.as_bytes()[..]);
        let ephemeral_public_deobfuscated = decrypt_anonymously(&masking_key, &mut ephemeral_public_obfuscated)?;

        let ephemeral_public_bytes = <[u8; X25519_KEY_LENGTH]>::try_from(&ephemeral_public_deobfuscated.slice()[..])?;
        let ephemeral_public = PublicKey::from(ephemeral_public_bytes);
        let shared_secret = data.private_key.diffie_hellman(&ephemeral_public);

        let signature_bytes = <[u8; Signature::BYTE_SIZE]>::try_from(&transcript_authenticated.slice()[..])?;
        let signature = Signature::from_bytes(&signature_bytes);
        let transcript = Hasher::new().update(&data.shared_secret.slice()).update(shared_secret.as_bytes()).update(&data.nonce.slice()).update(&nonce.slice()).finalize();
        try_with!(self.vpk.verify_strict(transcript.as_bytes(), &signature), "Signature verification error");

        let session_key_hash = Hasher::new_keyed(&hash_derive_key_context(SESSION_KEY)).update(&data.shared_secret.slice()).update(&shared_secret.as_bytes()[..]).update(transcript.as_bytes()).finalize();
        let session_key = ByteBuffer::from(&session_key_hash.as_bytes()[..]);

        let mut session_symmetric = Symmetric::new(&session_key)?;
        let mut obfuscation_symmetric = Symmetric::new(&self.obfs)?;
        let (tailor, encrypted_tailor, authentication) = obfuscation_symmetric.decrypt_auth_twice(ciphertext, None)?;
        obfuscation_symmetric.verify_second_auth(&encrypted_tailor, None, &session_key, &authentication)?;

        if let Some(initial) = initial_data {
            let initial_decrypted = session_symmetric.decrypt_auth(initial, None)?;
            Ok((tailor, Some(initial_decrypted), session_symmetric))
        } else {
            Ok((tailor, None, session_symmetric))
        }
    }
}

#[cfg(all(feature = "server"))]
impl ServerData<'_> {
    fn decrypt<'a, 'b>(&self, ciphertext: ByteBuffer<'a>, initial_data: ByteBuffer<'b>) -> DynResult<(ByteBuffer<'a>, ByteBuffer<'b>)> {
        todo!()
    }

    fn encrypt<'a, 'b>(&'_ self, plaintext: ByteBuffer<'a>, initial_data: ByteBuffer<'b>) -> DynResult<(ByteBuffer<'a>, ByteBuffer<'b>, Symmetric)> {
        todo!()
    }
}
