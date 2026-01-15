#[cfg(test)]
#[path = "../../tests/crypto/symmetric.rs"]
mod tests;

use cfg_if::cfg_if;

use crate::bytes::ByteBuffer;
use crate::crypto::error::{CryptoError, array_extraction_error, encryption_error};
use crate::random::get_rng;

cfg_if! {
    if #[cfg(feature = "fast")] {
        use blake3::{KEY_LEN, Hasher, keyed_hash};
        use constant_time_eq::constant_time_eq;
        use crate::crypto::error::authentication_error;
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
pub const SYMMETRIC_SECOND_AUTH_LEN: usize = 32;

#[cfg(feature = "software")]
pub const NONCE_LEN: usize = 24;

#[cfg(feature = "software")]
pub const ANONYMOUS_NONCE_LEN: usize = 24;

#[cfg(feature = "hardware")]
pub const NONCE_LEN: usize = 12;

#[cfg(feature = "hardware")]
pub const ANONYMOUS_NONCE_LEN: usize = 16;

/// Encrypt plaintext using unauthenticated stream cipher. Appends nonce to output.
/// Args: key (32-byte), plaintext (modified in-place). Returns: ciphertext with nonce.
pub fn encrypt_anonymously(key: &ByteBuffer, plaintext: &mut ByteBuffer) -> Result<ByteBuffer, CryptoError> {
    let key_bytes: [u8; SYMMETRIC_KEY_LENGTH] = match key.try_into() {
        Ok(res) => res,
        Err(err) => return Err(array_extraction_error("anonymous encryption key", err)),
    };
    let nonce = AnonymousCypher::generate_iv(get_rng());
    AnonymousCypher::new(&key_bytes.into(), &nonce.into()).apply_keystream(&mut plaintext.slice_mut());
    Ok(plaintext.append(&nonce))
}

/// Decrypt ciphertext using unauthenticated stream cipher. Extracts nonce from end.
/// Args: key (32-byte), ciphertext_with_nonce. Returns: plaintext.
pub fn decrypt_anonymously(key: &ByteBuffer, ciphertext_with_nonce: &mut ByteBuffer) -> Result<ByteBuffer, CryptoError> {
    let (ciphertext, nonce_bytes) = ciphertext_with_nonce.split_buf(ciphertext_with_nonce.len() - ANONYMOUS_NONCE_LEN);
    let key_bytes: [u8; SYMMETRIC_KEY_LENGTH] = match key.try_into() {
        Ok(res) => res,
        Err(err) => return Err(array_extraction_error("anonymous decryption key", err)),
    };
    let nonce: [u8; ANONYMOUS_NONCE_LEN] = match (&nonce_bytes).try_into() {
        Ok(res) => res,
        Err(err) => return Err(array_extraction_error("anonymous decryption nonce", err)),
    };
    AnonymousCypher::new(&key_bytes.into(), &nonce.into()).apply_keystream(&mut ciphertext.slice_mut());
    Ok(ciphertext)
}

/// Authenticated symmetric cipher for marshalling encryption (XChaCha20-Poly1305 or AES-GCM).
#[derive(Clone)]
pub struct Symmetric {
    cipher: Cipher,
}

impl Symmetric {
    /// Create cipher from 32-byte key. Returns: Symmetric instance.
    pub fn new(key: &ByteBuffer) -> Result<Self, CryptoError> {
        let private_bytes: [u8; SYMMETRIC_KEY_LENGTH] = match key.try_into() {
            Ok(res) => res,
            Err(err) => return Err(array_extraction_error("cipher key", err)),
        };
        let cipher = Cipher::new(CipherKey::from_slice(&private_bytes));
        Ok(Self { cipher })
    }

    /// Internal: encrypt with AEAD, return ciphertext with prepended nonce and detached tag.
    #[inline]
    fn encrypt_internal(&mut self, plaintext: ByteBuffer, additional_data: Option<&ByteBuffer>) -> Result<(ByteBuffer, GenericArray<u8, U16>), CryptoError> {
        let nonce = Cipher::generate_nonce(get_rng());
        let result = match additional_data {
            Some(res) => self.cipher.encrypt_in_place_detached(&nonce, &res.slice(), &mut plaintext.slice_mut()),
            None => self.cipher.encrypt_in_place_detached(&nonce, &[], &mut plaintext.slice_mut()),
        };
        match result {
            Ok(res) => Ok((plaintext.prepend(&nonce), res)),
            Err(err) => Err(encryption_error("symmetric encryption", err)),
        }
    }

    /// Encrypt with authentication. Returns: nonce || ciphertext || 16-byte tag.
    pub fn encrypt_auth(&mut self, plaintext: ByteBuffer, additional_data: Option<&ByteBuffer>) -> Result<ByteBuffer, CryptoError> {
        match self.encrypt_internal(plaintext, additional_data) {
            Ok((ciphertext, auth)) => Ok(ciphertext.append(&auth)),
            Err(err) => Err(err),
        }
    }

    /// Encrypt with dual authentication: AEAD tag + BLAKE3 keyed hash. Returns: nonce || ciphertext || tag || hash.
    #[cfg(feature = "fast")]
    pub fn encrypt_auth_twice(&mut self, plaintext: ByteBuffer, additional_data: Option<&ByteBuffer>, second_hash_key: &ByteBuffer) -> Result<ByteBuffer, CryptoError> {
        match self.encrypt_internal(plaintext, additional_data) {
            Ok((ciphertext, auth)) => {
                let second_hash_key_bytes: [u8; KEY_LEN] = match second_hash_key.try_into() {
                    Ok(res) => res,
                    Err(err) => return Err(array_extraction_error("second hash key (encryption)", err)),
                };
                let hash = if let Some(additional) = additional_data { Hasher::new_keyed(&second_hash_key_bytes).update(&ciphertext.slice()).update(&additional.slice()).finalize() } else { keyed_hash(&second_hash_key_bytes, &ciphertext.slice()) };
                Ok(ciphertext.append(&auth).append(hash.as_bytes()))
            }
            Err(err) => Err(err),
        }
    }

    /// Internal: decrypt with AEAD using detached tag.
    #[inline]
    fn decrypt_internal(&mut self, ciphertext_with_nonce: ByteBuffer, tag_buffer: &ByteBuffer, additional_data: Option<&ByteBuffer>) -> Result<ByteBuffer, CryptoError> {
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
            Err(err) => Err(encryption_error("symmetric decryption", err)),
        }
    }

    /// Decrypt and verify authentication tag. Args: nonce || ciphertext || tag. Returns: plaintext.
    pub fn decrypt_auth(&mut self, ciphertext_authenticated: ByteBuffer, additional_data: Option<&ByteBuffer>) -> Result<ByteBuffer, CryptoError> {
        let (ciphertext_with_nonce, authentication) = ciphertext_authenticated.split_buf(ciphertext_authenticated.len() - SYMMETRIC_FIRST_AUTH_LEN);
        match self.decrypt_internal(ciphertext_with_nonce, &authentication, additional_data) {
            Ok(plaintext) => Ok(plaintext),
            Err(err) => Err(err),
        }
    }

    /// Decrypt dual-authenticated ciphertext. Returns: (plaintext, ciphertext_with_nonce, second_auth).
    #[cfg(feature = "fast")]
    pub fn decrypt_auth_twice(&mut self, ciphertext_authenticated_twice: ByteBuffer, additional_data: Option<&ByteBuffer>) -> Result<(ByteBuffer, ByteBuffer, ByteBuffer), CryptoError> {
        let (ciphertext_authenticated, second_authentication) = ciphertext_authenticated_twice.split_buf(ciphertext_authenticated_twice.len() - SYMMETRIC_SECOND_AUTH_LEN);
        let (ciphertext_with_nonce, authentication) = ciphertext_authenticated.split_buf(ciphertext_authenticated.len() - SYMMETRIC_FIRST_AUTH_LEN);
        match self.decrypt_internal(ciphertext_with_nonce.copy(), &authentication, additional_data) {
            Ok(plaintext) => Ok((plaintext, ciphertext_with_nonce, second_authentication)),
            Err(err) => Err(err),
        }
    }

    #[cfg(feature = "fast")]
    pub fn verify_second_auth(&mut self, ciphertext_with_nonce: &ByteBuffer, additional_data: Option<&ByteBuffer>, second_hash_key: &ByteBuffer, second_authentication: &ByteBuffer) -> Result<(), CryptoError> {
        let second_hash_key_bytes: [u8; KEY_LEN] = match second_hash_key.try_into() {
            Ok(res) => res,
            Err(err) => return Err(array_extraction_error("second hash key (decryption)", err)),
        };
        let hash = if let Some(additional) = additional_data { Hasher::new_keyed(&second_hash_key_bytes).update(&ciphertext_with_nonce.slice()).update(&additional.slice()).finalize() } else { keyed_hash(&second_hash_key_bytes, &ciphertext_with_nonce.slice()) };
        if !constant_time_eq(hash.as_bytes(), &second_authentication.slice()) {
            return Err(authentication_error("second authentication error (hashes not equal)"))
        }
        return Ok(())
    }
}
