use blake3::Hasher;
use blake3::hazmat::hash_derive_key_context;
use cfg_if::cfg_if;
use classic_mceliece_rust::{CRYPTO_BYTES, CRYPTO_CIPHERTEXTBYTES, Ciphertext, encapsulate, decapsulate};
use ed25519_dalek::Signature;
use rand::RngCore;
use simple_error::try_with;
use x25519_dalek::{PublicKey, EphemeralSecret};

use crate::bytes::ByteBuffer;
use crate::crypto::certificate::ObfuscationBufferContainer;
use crate::crypto::symmetric::{Symmetric, encrypt_anonymously, decrypt_anonymously};
use crate::random::get_rng;
use crate::generic::DynResult;

cfg_if! {
    if #[cfg(feature = "server")] {
        use ed25519_dalek::ed25519::signature::SignerMut;
        use crate::crypto::certificate::{ServerData, ServerSecret};
    }
}

cfg_if! {
    if #[cfg(feature = "full")] {
        use x25519_dalek::StaticSecret;
        use generic_array::typenum::U32;
        use crate::random::SupportRng;
    }
}

#[cfg(feature = "client")]
use crate::crypto::certificate::{Certificate, ClientData};

const X25519_KEY_LENGTH: usize = 32;
const NONCE_LENGTH: usize = 32;

const INITIAL_DATA_KEY: &str = "handshake client obfuscation key";
const CLIENT_HANDSHAKE_OBFUSCATION_KEY: &str = "handshake client obfuscation key";
const SERVER_HANDSHAKE_OBFUSCATION_KEY: &str = "handshake server obfuscation key";
const SESSION_KEY: &str = "session key";
const MARSHALLING_OBFUSCATION_KEY: &str = "marshalling obfuscation key";
const MARSHALLING_ENCRYPTION_KEY: &str = "marshalling encryption key";

#[cfg(feature = "client")]
impl<'a> Certificate<'a> {
    pub fn encapsulate_handshake_client<'b>(&'a self, buffer: ByteBuffer<'b>) -> DynResult<(ClientData<'_>, ByteBuffer<'b>, Symmetric)> {
        let nonce = buffer.ensure_size(NONCE_LENGTH);
        get_rng().fill_bytes(&mut nonce.slice_mut());

        let ephemeral_secret = EphemeralSecret::random_from_rng(get_rng());
        let mut ephemeral_public = ByteBuffer::from(&PublicKey::from(&ephemeral_secret).to_bytes()[..]);

        let mut shared_secret_buffer = [0u8; CRYPTO_BYTES];
        let (ciphertext, shared_secret) = encapsulate(&self.epk, &mut shared_secret_buffer, &mut get_rng());
        let mut ciphertext_buffer = ByteBuffer::from(&ciphertext.as_array()[..]);
        let shared_buffer = ByteBuffer::from(&shared_secret.as_array()[..]);

        let masking_key_hash = Hasher::new_keyed(&hash_derive_key_context(CLIENT_HANDSHAKE_OBFUSCATION_KEY)).update(&self.obfuscation_buffer().slice()).update(&nonce.slice()).finalize();
        let masking_key = ByteBuffer::from(&masking_key_hash.as_bytes()[..]);
        let ephemeral_public_obfuscated = encrypt_anonymously(&masking_key, &mut ephemeral_public)?;
        let ciphertext_obfuscated = encrypt_anonymously(&masking_key, &mut ciphertext_buffer)?;

        let initial_encryption_key_hash = Hasher::new_keyed(&hash_derive_key_context(INITIAL_DATA_KEY)).update(&shared_buffer.slice()).update(&ephemeral_public_obfuscated.slice()).update(&nonce.slice()).finalize();
        let initial_encryption_key = ByteBuffer::from(&initial_encryption_key_hash.as_bytes()[..]);

        let client_data = ClientData {
            ephemeral_key: ephemeral_secret,
            shared_secret: shared_buffer,
            nonce: ByteBuffer::from(&nonce.slice()[..]),
        };
        let handshake_secret = nonce.append_buf(&ciphertext_obfuscated).append_buf(&ephemeral_public_obfuscated);
        let initial_encryption_symmetric = Symmetric::new(&initial_encryption_key)?;
        Ok((client_data, handshake_secret, initial_encryption_symmetric))
    }

    pub fn decapsulate_handshake_client<'b>(&'a self, data: ClientData, handshake_secret: ByteBuffer<'b>) -> DynResult<Symmetric> {
        let (mut ephemeral_public_obfuscated, rest) = handshake_secret.split_buf(X25519_KEY_LENGTH);
        let (transcript_signed, rest) = rest.split_buf(Signature::BYTE_SIZE);
        let nonce = rest.rebuffer_end(NONCE_LENGTH);

        let masking_key_hash = Hasher::new_keyed(&hash_derive_key_context(SERVER_HANDSHAKE_OBFUSCATION_KEY)).update(&self.obfuscation_buffer().slice()).update(&nonce.slice()).finalize();
        let masking_key = ByteBuffer::from(&masking_key_hash.as_bytes()[..]);
        let ephemeral_public_deobfuscated = decrypt_anonymously(&masking_key, &mut ephemeral_public_obfuscated)?;

        let ephemeral_public_bytes = <[u8; X25519_KEY_LENGTH]>::try_from(&ephemeral_public_deobfuscated.slice()[..])?;
        let ephemeral_public = PublicKey::from(ephemeral_public_bytes);
        let shared_secret = data.ephemeral_key.diffie_hellman(&ephemeral_public);

        let transcript_signed_bytes = <[u8; Signature::BYTE_SIZE]>::try_from(&transcript_signed.slice()[..])?;
        let transcript_signed = Signature::from_bytes(&transcript_signed_bytes);
        let transcript = Hasher::new().update(&data.shared_secret.slice()).update(shared_secret.as_bytes()).update(&data.nonce.slice()).update(&nonce.slice()).finalize();
        try_with!(self.vpk.verify_strict(transcript.as_bytes(), &transcript_signed), "Signature verification error");

        let session_key_hash = Hasher::new_keyed(&hash_derive_key_context(SESSION_KEY)).update(&data.shared_secret.slice()).update(&shared_secret.as_bytes()[..]).update(transcript.as_bytes()).finalize();
        let session_key = ByteBuffer::from(&session_key_hash.as_bytes()[..]);
        let session_symmetric = Symmetric::new(&session_key)?;
        Ok(session_symmetric)
    }

    #[cfg(feature = "full")]
    pub fn encrypt_obfuscate<'b>(&'a self, plaintext: ByteBuffer<'b>) -> DynResult<ByteBuffer<'b>> {
        let nonce = ByteBuffer::from(&get_rng().random_byte_array::<U32>()[..]);

        let ephemeral_secret = StaticSecret::random_from_rng(get_rng());
        let mut ephemeral_public = ByteBuffer::from(&PublicKey::from(&ephemeral_secret).to_bytes()[..]);
        let shared_secret = ephemeral_secret.diffie_hellman(&self.opk);

        let masking_key_hash = Hasher::new_keyed(&hash_derive_key_context(MARSHALLING_OBFUSCATION_KEY)).update(self.opk.as_bytes()).update(&nonce.slice()).finalize();
        let masking_key = ByteBuffer::from(&masking_key_hash.as_bytes()[..]);
        let ephemeral_public_obfuscated = encrypt_anonymously(&masking_key, &mut ephemeral_public)?;

        let encryption_key_hash = Hasher::new_keyed(&hash_derive_key_context(MARSHALLING_ENCRYPTION_KEY)).update(shared_secret.as_bytes()).finalize();
        let encryption_key = ByteBuffer::from(&encryption_key_hash.as_bytes()[..]);

        let ciphertext = Symmetric::new(&encryption_key)?.encrypt_auth(plaintext, Some(&nonce))?;
        let payload = ciphertext.prepend_buf(&ephemeral_public_obfuscated).prepend_buf(&nonce);
        Ok(payload)
    }

}

#[cfg(feature = "server")]
impl<'a> ServerSecret<'a> {
    fn decapsulate_handshake_server(&'a self, handshake_secret: ByteBuffer) -> DynResult<(ServerData<'_>, Symmetric)> {
        let (mut ephemeral_public_obfuscated, rest) = handshake_secret.split_buf(X25519_KEY_LENGTH);
        let (mut ciphertext_obfuscated, rest) = rest.split_buf(Signature::BYTE_SIZE);
        let nonce = rest.rebuffer_end(NONCE_LENGTH);

        let masking_key_hash = Hasher::new_keyed(&hash_derive_key_context(CLIENT_HANDSHAKE_OBFUSCATION_KEY)).update(&self.obfuscation_buffer().slice()).update(&nonce.slice()).finalize();
        let masking_key = ByteBuffer::from(&masking_key_hash.as_bytes()[..]);

        let ciphertext_buffer = decrypt_anonymously(&masking_key, &mut ciphertext_obfuscated)?;
        let ciphertext_bytes = <[u8; CRYPTO_CIPHERTEXTBYTES]>::try_from(&ciphertext_buffer.slice()[..])?;
        let ciphertext = Ciphertext::from(ciphertext_bytes);

        let mut shared_secret_buffer = [0u8; CRYPTO_BYTES];
        let shared_secret = decapsulate(&ciphertext, &self.esk, &mut shared_secret_buffer);
        let shared_buffer = ByteBuffer::from(&shared_secret.as_array()[..]);

        let initial_encryption_key_hash = Hasher::new_keyed(&hash_derive_key_context(INITIAL_DATA_KEY)).update(shared_secret.as_array()).update(&ephemeral_public_obfuscated.slice()).update(&nonce.slice()).finalize();
        let initial_encryption_key = ByteBuffer::from(&initial_encryption_key_hash.as_bytes()[..]);

        let ephemeral_public_deobfuscated = decrypt_anonymously(&masking_key, &mut ephemeral_public_obfuscated)?;
        let ephemeral_public_bytes = <[u8; X25519_KEY_LENGTH]>::try_from(&ephemeral_public_deobfuscated.slice()[..])?;
        let ephemeral_public = PublicKey::from(ephemeral_public_bytes);

        let server_data = ServerData {
            ephemeral_key: ephemeral_public,
            shared_secret: shared_buffer,
            nonce: ByteBuffer::from(&nonce.slice()[..])
        };
        let initial_encryption_symmetric = Symmetric::new(&initial_encryption_key)?;
        Ok((server_data, initial_encryption_symmetric))
    }

    fn encapsulate_handshake_server<'b>(&'a mut self, data: ServerData, buffer: ByteBuffer<'b>) -> DynResult<(ByteBuffer<'b>, Symmetric)> {
        let nonce = buffer.ensure_size(NONCE_LENGTH);
        get_rng().fill_bytes(&mut nonce.slice_mut());

        let ephemeral_secret = EphemeralSecret::random_from_rng(get_rng());
        let mut ephemeral_public = ByteBuffer::from(&PublicKey::from(&ephemeral_secret).to_bytes()[..]);
        let shared_secret = ephemeral_secret.diffie_hellman(&data.ephemeral_key);

        let transcript = Hasher::new().update(&data.shared_secret.slice()).update(shared_secret.as_bytes()).update(&data.nonce.slice()).update(&nonce.slice()).finalize();
        let transcript_signed = self.vsk.sign(transcript.as_bytes());

        let masking_key_hash = Hasher::new_keyed(&hash_derive_key_context(SERVER_HANDSHAKE_OBFUSCATION_KEY)).update(&self.obfuscation_buffer().slice()).update(&nonce.slice()).finalize();
        let masking_key = ByteBuffer::from(&masking_key_hash.as_bytes()[..]);
        let ephemeral_public_obfuscated = encrypt_anonymously(&masking_key, &mut ephemeral_public)?;

        let session_key_hash = Hasher::new_keyed(&hash_derive_key_context(SESSION_KEY)).update(&data.shared_secret.slice()).update(&shared_secret.as_bytes()[..]).update(transcript.as_bytes()).finalize();
        let session_key = ByteBuffer::from(&session_key_hash.as_bytes()[..]);

        let handshake_secret = nonce.append(&transcript_signed.to_bytes()).append_buf(&ephemeral_public_obfuscated);
        let session_symmetric = Symmetric::new(&session_key)?;
        Ok((handshake_secret, session_symmetric))
    }

    #[cfg(feature = "full")]
    pub fn decrypt_deobfuscate<'b>(&'a self, ciphertext: ByteBuffer<'b>) -> DynResult<ByteBuffer<'b>> {
        let (nonce, rest) = ciphertext.split_buf(NONCE_LENGTH);
        let (mut ephemeral_public_obfuscated, ciphertext) = rest.split_buf(Signature::BYTE_SIZE);

        let masking_key_hash = Hasher::new_keyed(&hash_derive_key_context(MARSHALLING_OBFUSCATION_KEY)).update(self.opk.as_bytes()).update(&nonce.slice()).finalize();
        let masking_key = ByteBuffer::from(&masking_key_hash.as_bytes()[..]);
        let ephemeral_public_deobfuscated = encrypt_anonymously(&masking_key, &mut ephemeral_public_obfuscated)?;

        let ephemeral_public_bytes = <[u8; X25519_KEY_LENGTH]>::try_from(&ephemeral_public_deobfuscated.slice()[..])?;
        let ephemeral_public = PublicKey::from(ephemeral_public_bytes);
        let shared_secret = self.osk.diffie_hellman(&ephemeral_public);

        let encryption_key_hash = Hasher::new_keyed(&hash_derive_key_context(MARSHALLING_ENCRYPTION_KEY)).update(shared_secret.as_bytes()).finalize();
        let encryption_key = ByteBuffer::from(&encryption_key_hash.as_bytes()[..]);

        let plaintext = Symmetric::new(&encryption_key)?.decrypt_auth(ciphertext, Some(&nonce))?;
        Ok(plaintext)
    }
}
