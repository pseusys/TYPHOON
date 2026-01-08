use cfg_if::cfg_if;
use simple_error::bail;

use crate::bytes::ByteBuffer;
use crate::random::get_rng;
use crate::generic::DynResult;

cfg_if! {
    if #[cfg(feature = "fast")] {
        use blake3::{KEY_LEN, Hasher, keyed_hash};
        use constant_time_eq::constant_time_eq;
        use simple_error::ensure_with;
    }
}

cfg_if! {
    if #[cfg(feature = "software")] {
        use chacha20::XChaCha20;
        use chacha20::cipher::{KeyIvInit, StreamCipher};
        use chacha20poly1305::aead::AeadMutInPlace;
        use chacha20poly1305::aead::generic_array::GenericArray;
        use chacha20poly1305::consts::U16;
        use chacha20poly1305::{AeadCore, Key, KeyInit, Tag, XChaCha20Poly1305, XNonce};
        type AnonymousCypher = XChaCha20;
        type Cipher = XChaCha20Poly1305;
        type CipherKey = Key;
        type CipherTag = Tag;
        type CipherNonce = XNonce;
    } else if #[cfg(feature = "hardware")] {
        use aes::Aes256;
        use aes::cipher::{KeyIvInit, StreamCipher};
        use aes_gcm::aead::AeadMutInPlace;
        use aes_gcm::aead::consts::{U12, U16};
        use aes_gcm::aead::generic_array::GenericArray;
        use aes_gcm::{AeadCore, Aes256Gcm, Key, KeyInit, Tag, Nonce};
        use ctr::Ctr128BE;
        type AnonymousCypher = Ctr128BE<Aes256>;
        type Cipher = Aes256Gcm;
        type CipherKey = Key::<Aes256Gcm>;
        type CipherTag = Tag;
        type CipherNonce = Nonce::<U12>;
    }
}

pub const SYMMETRIC_KEY_LENGTH: usize = 32;
pub const SYMMETRIC_FIRST_AUTH_LEN: usize = 16;
pub const SYMMETRIC_SECOND_AUTH_LEN: usize = 16;

#[cfg(feature = "software")]
pub const NONCE_LEN: usize = 24;

#[cfg(feature = "hardware")]
pub const NONCE_LEN: usize = 16;

pub fn encrypt_anonymously<'a>(key: &ByteBuffer, plaintext: &mut ByteBuffer<'a>) -> DynResult<ByteBuffer<'a>> {
    let key_bytes = <[u8; SYMMETRIC_KEY_LENGTH]>::try_from(&key.slice()[..])?;
    let nonce = AnonymousCypher::generate_iv(get_rng());
    AnonymousCypher::new(&key_bytes.into(), &nonce.into()).apply_keystream(&mut plaintext.slice_mut());
    Ok(plaintext.append(&nonce))
}

pub fn decrypt_anonymously<'a>(key: &ByteBuffer, ciphertext_with_nonce: &mut ByteBuffer<'a>) -> DynResult<ByteBuffer<'a>> {
    let (nonce_bytes, ciphertext) = ciphertext_with_nonce.split_buf(NONCE_LEN);
    let key_bytes = <[u8; SYMMETRIC_KEY_LENGTH]>::try_from(&key.slice()[..])?;
    let nonce = <[u8; NONCE_LEN]>::try_from(&nonce_bytes.slice()[..])?;
    AnonymousCypher::new(&key_bytes.into(), &nonce.into()).apply_keystream(&mut ciphertext.slice_mut());
    Ok(ciphertext)
}

#[derive(Clone)]
pub struct Symmetric {
    cipher: Cipher,
}

impl Symmetric {
    pub fn new(key: &ByteBuffer) -> DynResult<Self> {
        let private_bytes = <[u8; SYMMETRIC_KEY_LENGTH]>::try_from(&key.slice()[..])?;
        let cipher = Cipher::new(CipherKey::from_slice(&private_bytes));
        Ok(Self { cipher })
    }

    #[inline]
    fn encrypt_internal<'a, 'b>(&mut self, plaintext: ByteBuffer<'a>, additional_data: Option<&ByteBuffer>) -> DynResult<(ByteBuffer<'a>, GenericArray<u8, U16>)> {
        let nonce = Cipher::generate_nonce(get_rng());
        let result = match additional_data {
            Some(res) => self.cipher.encrypt_in_place_detached(&nonce, &res.slice(), &mut plaintext.slice_mut()),
            None => self.cipher.encrypt_in_place_detached(&nonce, &[], &mut plaintext.slice_mut()),
        };
        match result {
            Ok(res) => Ok((plaintext.prepend(&nonce), res)),
            Err(err) => bail!("Error encrypting plaintext: {err}"),
        }
    }

    pub fn encrypt_auth<'a>(&mut self, plaintext: ByteBuffer<'a>, additional_data: Option<&ByteBuffer>) -> DynResult<ByteBuffer<'a>> {
        match self.encrypt_internal(plaintext, additional_data) {
            Ok((ciphertext, auth)) => Ok(ciphertext.append(&auth)),
            Err(err) => Err(err),
        }
    }

    #[cfg(feature = "fast")]
    pub fn encrypt_auth_twice<'a>(&mut self, plaintext: ByteBuffer<'a>, additional_data: Option<&ByteBuffer>, second_hash_key: &ByteBuffer) -> DynResult<ByteBuffer<'a>> {
        match self.encrypt_internal(plaintext, additional_data) {
            Ok((ciphertext, auth)) => {
                let second_hash_key_bytes = <[u8; KEY_LEN]>::try_from(&second_hash_key.slice()[..])?;
                let hash = if let Some(additional) = additional_data {
                    Hasher::new_keyed(&second_hash_key_bytes).update(&ciphertext.slice()).update(&additional.slice()).finalize()
                } else {
                    keyed_hash(&second_hash_key_bytes, &ciphertext.slice())
                };
                Ok(ciphertext.append(&auth).append(hash.as_bytes()))
            },
            Err(err) => Err(err),
        }
    }

    #[inline]
    pub fn decrypt_internal<'a>(&mut self, ciphertext_with_nonce: ByteBuffer<'a>, tag_buffer: &ByteBuffer, additional_data: Option<&ByteBuffer>) -> DynResult<ByteBuffer<'a>> {
        let (nonce_bytes, ciphertext) = ciphertext_with_nonce.split_buf(NONCE_LEN);
        let nonce_slice = nonce_bytes.slice();
        let nonce = CipherNonce::from_slice(&nonce_slice);
        let tag_slice = tag_buffer.slice();
        let tag = CipherTag::from_slice(&tag_slice);
        let result = match additional_data {
            Some(res) => self.cipher.decrypt_in_place_detached(&nonce, &res.slice(), &mut ciphertext.slice_mut(), &tag),
            None => self.cipher.decrypt_in_place_detached(&nonce, &[], &mut ciphertext.slice_mut(), &tag),
        };
        match result {
            Ok(_) => Ok(ciphertext),
            Err(err) => bail!("Error encrypting plaintext: {err}"),
        }
    }

    pub fn decrypt_auth<'a>(&mut self, ciphertext_authenticated: ByteBuffer<'a>, additional_data: Option<&ByteBuffer>) -> DynResult<ByteBuffer<'a>> {
        let (ciphertext_with_nonce, authentication) = ciphertext_authenticated.split_buf(ciphertext_authenticated.len() - SYMMETRIC_FIRST_AUTH_LEN);
        match self.decrypt_internal(ciphertext_with_nonce, &authentication, additional_data) {
            Ok(plaintext) => Ok(plaintext),
            Err(err) => Err(err),
        }
    }

    #[cfg(feature = "fast")]
    pub fn decrypt_auth_twice<'a>(&mut self, ciphertext_authenticated_twice: ByteBuffer<'a>, additional_data: Option<&ByteBuffer>) -> DynResult<(ByteBuffer<'a>, ByteBuffer<'a>, ByteBuffer<'a>)> {
        let (ciphertext_authenticated, second_authentication) = ciphertext_authenticated_twice.split_buf(ciphertext_authenticated_twice.len() - SYMMETRIC_SECOND_AUTH_LEN);
        let (ciphertext_with_nonce, authentication) = ciphertext_authenticated.split_buf(ciphertext_authenticated_twice.len() - SYMMETRIC_FIRST_AUTH_LEN);
        match self.decrypt_internal(ciphertext_with_nonce.clone(), &authentication, additional_data) {
            Ok(plaintext) => Ok((plaintext, ciphertext_with_nonce, second_authentication)),
            Err(err) => Err(err),
        }
    }

    #[cfg(feature = "fast")]
    pub fn verify_second_auth(&mut self, ciphertext_with_nonce: &ByteBuffer, additional_data: Option<&ByteBuffer>, second_hash_key: &ByteBuffer, second_authentication: &ByteBuffer) -> DynResult<()> {
        let second_hash_key_bytes = <[u8; KEY_LEN]>::try_from(&second_hash_key.slice()[..])?;
        let hash = if let Some(additional) = additional_data {
            Hasher::new_keyed(&second_hash_key_bytes).update(&ciphertext_with_nonce.slice()).update(&additional.slice()).finalize()
        } else {
            keyed_hash(&second_hash_key_bytes, &ciphertext_with_nonce.slice())
        };
        ensure_with!(constant_time_eq(hash.as_bytes(), &second_authentication.slice()), "second authentication verification failed");
        Ok(())
    }
}
