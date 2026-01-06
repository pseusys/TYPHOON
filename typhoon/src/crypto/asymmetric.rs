use hkdf::Hkdf;
use sha2::{Digest, Sha256};

use simple_error::try_with;
use ed25519_dalek::Signature;
use x25519_dalek::{PublicKey, EphemeralSecret};

use crate::bytes::ByteBuffer;
use crate::crypto::certificate::ClientData;
use crate::crypto::math::xor_bytes;
use crate::crypto::symmetric::{KEY_LEN, MAC_LEN, Symmetric};
use crate::random::{DEFAULT_KEY_LENGTH, SupportRng, get_rng};
use crate::generic::DynResult;

#[cfg(feature = "fast")]
use classic_mceliece_rust::{CRYPTO_BYTES, CRYPTO_CIPHERTEXTBYTES, encapsulate};

#[cfg(all(feature = "client"))]
use crate::crypto::certificate::Certificate;

#[cfg(all(feature = "server"))]
use crate::crypto::certificate::ServerData;

const X25519_KEY_LENGTH: usize = 32;

fn generate_key<'a>(inputs: &[&[u8]], salt: &[u8], info: &str, container: &mut ByteBuffer<'a>) -> DynResult<()> {
    let mut hasher = Sha256::new();
    for input in inputs {
        let len = (input.len() as u64).to_be_bytes();
        hasher.update(len);
        hasher.update(input);
    }

    let raw_key_material = hasher.finalize();
    let hkdf = Hkdf::<Sha256>::new(Some(salt), raw_key_material.as_slice());
    try_with!(hkdf.expand(info.as_bytes(), &mut container.slice_mut()), "Invalid HKDF expansion length");
    Ok(())
}

#[cfg(all(feature = "client", feature = "fast"))]
impl Certificate<'_> {
    pub fn encrypt<'a, 'b>(&'_ self, plaintext: ByteBuffer<'a>, initial_data: Option<ByteBuffer<'b>>) -> DynResult<(ByteBuffer<'a>, Option<ByteBuffer<'b>>, ClientData<'_>)> {
        let plaintext_buffer = plaintext.ensure_size(plaintext.len() + MAC_LEN + DEFAULT_KEY_LENGTH + X25519_KEY_LENGTH + CRYPTO_CIPHERTEXTBYTES);
        let nonce = ByteBuffer::from(&get_rng().generate_key()[..]);

        let ephemeral_secret = EphemeralSecret::random_from_rng(get_rng());
        let ephemeral_public = ByteBuffer::from(&PublicKey::from(&ephemeral_secret).to_bytes()[..]);

        let mut shared_secret_buffer = [0u8; CRYPTO_BYTES];
        let (ciphertext, shared_secret) = encapsulate(&self.epk, &mut shared_secret_buffer, &mut get_rng());
        let shared_buffer = ByteBuffer::from(&shared_secret.as_array()[..]);

        let mut masking_key = ByteBuffer::empty(X25519_KEY_LENGTH + CRYPTO_CIPHERTEXTBYTES);
        generate_key(&[&self.obfs.slice()], &nonce.slice(), "handshake client obfuscation key", &mut masking_key)?;
        let (ephemeral_public_obfuscated, ciphertext_obfuscated) = masking_key.split_buf(X25519_KEY_LENGTH);
        xor_bytes(&mut ephemeral_public_obfuscated.slice_mut(), &ephemeral_public.slice());
        xor_bytes(&mut ciphertext_obfuscated.slice_mut(), ciphertext.as_array());

        let mut initial_encryption_key = ByteBuffer::empty(X25519_KEY_LENGTH);
        generate_key(&[&shared_buffer.slice(), &ephemeral_public.slice()], &nonce.slice(), "initial data key", &mut initial_encryption_key)?;

        let tailor = Symmetric::new(&self.obfs)?.encrypt(plaintext_buffer, Some(&initial_encryption_key))?.append_buf(&nonce).append_buf(&ciphertext_obfuscated).append_buf(&ephemeral_public);
        let client_data = ClientData {
            private_key: ephemeral_secret,
            shared_secret: shared_buffer,
            nonce,
        };

        if let Some(initial) = initial_data {
            let initial_encrypted = Symmetric::new(&initial_encryption_key)?.encrypt(initial, None)?;
            Ok((tailor, Some(initial_encrypted), client_data))
        } else {
            Ok((tailor, None, client_data))
        }
    }

    pub fn decrypt<'a, 'b>(&self, ciphertext: ByteBuffer<'a>, initial_data: Option<ByteBuffer<'b>>, data: ClientData) -> DynResult<(ByteBuffer<'a>, Option<ByteBuffer<'b>>, Symmetric)> {
        let (ciphertext, rest) = ciphertext.split_buf(KEY_LEN);
        let (ephemeral_public_obfuscated, rest) = rest.split_buf(X25519_KEY_LENGTH);
        let (transcript_authenticated, rest) = rest.split_buf(Signature::BYTE_SIZE);
        let nonce = rest.rebuffer_end(DEFAULT_KEY_LENGTH);

        let mut masking_key = ByteBuffer::empty(X25519_KEY_LENGTH);
        generate_key(&[&self.obfs.slice()], &nonce.slice(), "handshake server obfuscation key", &mut masking_key)?;
        xor_bytes(&mut ephemeral_public_obfuscated.slice_mut(), &masking_key.slice());

        let ephemeral_public_bytes = <[u8; X25519_KEY_LENGTH]>::try_from(&ephemeral_public_obfuscated.slice()[..])?;
        let ephemeral_public = PublicKey::from(ephemeral_public_bytes);
        let shared_secret = data.private_key.diffie_hellman(&ephemeral_public);

        let signature_bytes = <[u8; Signature::BYTE_SIZE]>::try_from(&transcript_authenticated.slice()[..])?;
        let signature = Signature::from_bytes(&signature_bytes);
        let transcript = Sha256::new().chain_update(&data.shared_secret).chain_update(&shared_secret).chain_update(&data.nonce).chain_update(nonce).finalize();
        try_with!(self.vpk.verify_strict(&transcript, &signature), "Signature verification error");

        let mut session_key = ByteBuffer::empty(DEFAULT_KEY_LENGTH);
        generate_key(&[&data.shared_secret.slice(), &shared_secret.as_bytes()[..]], &transcript.as_slice(), "session key", &mut session_key)?;

        let mut session_symmetric = Symmetric::new(&session_key)?;
        let tailor = Symmetric::new(&self.obfs)?.decrypt(ciphertext, Some(&session_key))?;

        if let Some(initial) = initial_data {
            let initial_decrypted = session_symmetric.decrypt(initial, None)?;
            Ok((tailor, Some(initial_decrypted), session_symmetric))
        } else {
            Ok((tailor, None, session_symmetric))
        }
    }
}

#[cfg(all(feature = "client", feature = "full"))]
impl Encrypting for Certificate<'_> {
    pub fn encrypt<'a, 'b>(&'_ self, plaintext: ByteBuffer<'a>, initial_data: ByteBuffer<'b>) -> DynResult<(ByteBuffer<'a>, ByteBuffer<'b>, ClientData<'_>)> {

    }

    pub fn decrypt<'a, 'b>(&self, ciphertext: ByteBuffer<'a>, initial_data: ByteBuffer<'b>, data: ClientData) -> DynResult<(ByteBuffer<'a>, ByteBuffer<'b>, Symmetric)> {

    }
}

#[cfg(all(feature = "server", feature = "fast"))]
impl ServerData<'_> {
    fn decrypt<'a, 'b>(&self, ciphertext: ByteBuffer<'a>, initial_data: ByteBuffer<'b>) -> DynResult<(ByteBuffer<'a>, ByteBuffer<'b>)> {
        todo!()
    }

    fn encrypt<'a, 'b>(&'_ self, plaintext: ByteBuffer<'a>, initial_data: ByteBuffer<'b>) -> DynResult<(ByteBuffer<'a>, ByteBuffer<'b>, Symmetric)> {
        todo!()
    }
}

#[cfg(all(feature = "server", feature = "full"))]
impl Decrypting for ServerData<'_> {
    fn decrypt<'a, 'b>(&self, ciphertext: ByteBuffer<'a>, initial_data: ByteBuffer<'b>) -> DynResult<(ByteBuffer<'a>, ByteBuffer<'b>)> {
        todo!()
    }

    fn encrypt<'a, 'b>(&'_ self, plaintext: ByteBuffer<'a>, initial_data: ByteBuffer<'b>) -> DynResult<(ByteBuffer<'a>, ByteBuffer<'b>, Symmetric)> {
        todo!()
    }
}

