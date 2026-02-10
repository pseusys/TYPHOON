#[cfg(test)]
#[path = "../../tests/crypto/symmetric.rs"]
mod tests;

use cfg_if::cfg_if;

use crate::bytes::{ByteBuffer, ByteBufferMut, DynamicByteBuffer, StaticByteBuffer};
use crate::crypto::error::CryptoError;
use crate::utils::random::get_rng;

cfg_if! {
    if #[cfg(feature = "fast")] {
        use blake3::{KEY_LEN, keyed_hash};
        use constant_time_eq::constant_time_eq;
    }
}

cfg_if! {
    if #[cfg(feature = "software")] {
        use chacha20::XChaCha20;
        use chacha20::cipher::{KeyIvInit, StreamCipher};
        use chacha20poly1305::aead::AeadMutInPlace;
        use chacha20poly1305::{AeadCore, Key, KeyInit, Tag, XChaCha20Poly1305, XNonce};
        type AnonymousCipher = XChaCha20;
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
        type AnonymousCipher = Ctr128BE<Aes256>;
        type Cipher = Aes256Gcm;
        type CipherKey = Key::<Aes256Gcm>;
        type CipherTag = Tag;
        type CipherNonce = Nonce::<U12>;
    }
}

pub const SYMMETRIC_KEY_LENGTH: usize = 32;
pub const SYMMETRIC_BUILT_IN_AUTH_LEN: usize = 16;
pub const SYMMETRIC_ADDITIONAL_AUTH_LEN: usize = 32;

#[cfg(feature = "software")]
pub const NONCE_LEN: usize = 24;

#[cfg(feature = "software")]
pub const ANONYMOUS_NONCE_LEN: usize = 24;

#[cfg(feature = "hardware")]
pub const NONCE_LEN: usize = 12;

#[cfg(feature = "hardware")]
pub const ANONYMOUS_NONCE_LEN: usize = 16;

/// Transcript for delayed tailor verification (fast mode only).
#[cfg(feature = "fast")]
pub struct ObfuscationTranscript {
    pub(crate) ciphertext_copy: DynamicByteBuffer,
    pub(crate) auth_transcript: DynamicByteBuffer,
}

/// Transcript placeholder (full mode).
#[cfg(feature = "full")]
pub struct ObfuscationTranscript {}


/// Encrypt plaintext using unauthenticated stream cipher. Appends nonce to output.
/// Args: key (32-byte), plaintext (modified in-place). Returns: ciphertext with nonce.
#[inline]
pub fn encrypt_anonymously(key: &StaticByteBuffer, plaintext: &mut DynamicByteBuffer) -> DynamicByteBuffer {
    let key_bytes: [u8; SYMMETRIC_KEY_LENGTH] = key.into();
    let nonce = AnonymousCipher::generate_iv(get_rng());
    AnonymousCipher::new(&key_bytes.into(), &nonce.into()).apply_keystream(&mut plaintext.slice_mut());
    plaintext.append(&nonce)
}

/// Decrypt ciphertext using unauthenticated stream cipher. Extracts nonce from end.
/// Args: key (32-byte), ciphertext_with_nonce. Returns: plaintext.
#[inline]
pub fn decrypt_anonymously(key: &StaticByteBuffer, ciphertext_with_nonce: &mut DynamicByteBuffer) -> DynamicByteBuffer {
    let (ciphertext, nonce_bytes) = ciphertext_with_nonce.split_buf(ciphertext_with_nonce.len() - ANONYMOUS_NONCE_LEN);
    let key_bytes: [u8; SYMMETRIC_KEY_LENGTH] = key.into();
    let nonce: [u8; ANONYMOUS_NONCE_LEN] = (&nonce_bytes).into();
    AnonymousCipher::new(&key_bytes.into(), &nonce.into()).apply_keystream(&mut ciphertext.slice_mut());
    ciphertext
}

/// Encrypt with dual authentication: AEAD tag + BLAKE3 keyed hash. 
/// Args: key (32-byte), plaintext (modified in-place), additional data (optional), hashing key. Returns: nonce || ciphertext || hash.
#[cfg(feature = "fast")]
pub fn encrypt_auth(key: &StaticByteBuffer, mut plaintext: DynamicByteBuffer, hash_key: &StaticByteBuffer) -> DynamicByteBuffer {
    let hash_key_bytes: [u8; KEY_LEN] = hash_key.into();
    let ciphertext = encrypt_anonymously(key, &mut plaintext);
    let hash = keyed_hash(&hash_key_bytes, ciphertext.slice());
    ciphertext.append(hash.as_bytes())
}

/// Decrypt dual-authenticated ciphertext. 
/// Args: key (32-byte), ciphertext_authenticated (modified in-place). Returns: (plaintext, ciphertext_with_nonce, second_auth).
#[cfg(feature = "fast")]
pub fn decrypt_auth(key: &StaticByteBuffer, ciphertext_authenticated: DynamicByteBuffer) -> (DynamicByteBuffer, ObfuscationTranscript) {
    let (ciphertext_with_nonce, authentication) = ciphertext_authenticated.split_buf(ciphertext_authenticated.len() - SYMMETRIC_ADDITIONAL_AUTH_LEN);
    let plaintext = decrypt_anonymously(key, &mut ciphertext_with_nonce.copy());
    (plaintext, ObfuscationTranscript {
        ciphertext_copy: ciphertext_with_nonce,
        auth_transcript: authentication,
    })
}

#[cfg(feature = "fast")]
pub fn verify_auth(obfuscation_transcript: ObfuscationTranscript, hash_key: &StaticByteBuffer) -> Result<(), CryptoError> {
    let second_hash_key_bytes: [u8; KEY_LEN] = hash_key.into();
    let hash = keyed_hash(&second_hash_key_bytes, obfuscation_transcript.ciphertext_copy.slice());
    if !constant_time_eq(hash.as_bytes(), obfuscation_transcript.auth_transcript.slice()) {
        return Err(CryptoError::authentication_error("authentication error (hashes not equal)"));
    }
    return Ok(());
}

/// Authenticated symmetric cipher for marshalling encryption (XChaCha20-Poly1305 or AES-GCM).
#[derive(Clone)]
pub struct Symmetric {
    cipher: Cipher,
}

impl Symmetric {
    /// Create cipher from 32-byte key. Returns: Symmetric instance.
    pub fn new(key: &StaticByteBuffer) -> Self {
        let private_bytes: [u8; SYMMETRIC_KEY_LENGTH] = key.into();
        let cipher = Cipher::new(CipherKey::from_slice(&private_bytes));
        Self {
            cipher,
        }
    }

    /// Encrypt with authentication. Returns: nonce || ciphertext || 16-byte tag.
    pub fn encrypt_auth<A: ByteBuffer>(&mut self, plaintext: DynamicByteBuffer, additional_data: Option<&A>) -> Result<DynamicByteBuffer, CryptoError> {
        let nonce = Cipher::generate_nonce(get_rng());
        let result = match additional_data {
            Some(res) => self.cipher.encrypt_in_place_detached(&nonce, res.slice(), &mut plaintext.slice_mut()),
            None => self.cipher.encrypt_in_place_detached(&nonce, &[], &mut plaintext.slice_mut()),
        };
        match result {
            Ok(res) => Ok(plaintext.append(&nonce).append(&res)),
            Err(err) => Err(CryptoError::encryption_error("symmetric encryption", err)),
        }
    }

    /// Internal: decrypt with AEAD using detached tag.
    #[inline]
    fn decrypt_internal<C: ByteBufferMut, A: ByteBuffer, T: ByteBuffer>(&mut self, ciphertext_with_nonce: C, tag_buffer: &A, additional_data: Option<&T>) -> Result<C, CryptoError> {
        let (ciphertext, nonce_bytes) = ciphertext_with_nonce.split_buf(ciphertext_with_nonce.len() - NONCE_LEN);
        let nonce_slice = nonce_bytes.slice();
        let nonce = CipherNonce::from_slice(&nonce_slice);
        let tag_slice = tag_buffer.slice();
        let tag = CipherTag::from_slice(&tag_slice);
        let result = match additional_data {
            Some(res) => self.cipher.decrypt_in_place_detached(&nonce, res.slice(), &mut ciphertext.slice_mut(), &tag),
            None => self.cipher.decrypt_in_place_detached(&nonce, &[], &mut ciphertext.slice_mut(), &tag),
        };
        match result {
            Ok(_) => Ok(ciphertext),
            Err(err) => Err(CryptoError::encryption_error("symmetric decryption", err)),
        }
    }

    /// Decrypt and verify authentication tag. Args: nonce || ciphertext || tag. Returns: plaintext.
    pub fn decrypt_auth<A: ByteBuffer>(&mut self, ciphertext_authenticated: DynamicByteBuffer, additional_data: Option<&A>) -> Result<DynamicByteBuffer, CryptoError> {
        let (ciphertext_with_nonce, authentication) = ciphertext_authenticated.split_buf(ciphertext_authenticated.len() - SYMMETRIC_BUILT_IN_AUTH_LEN);
        let (ciphertext, nonce_bytes) = ciphertext_with_nonce.split_buf(ciphertext_with_nonce.len() - NONCE_LEN);
        let nonce_slice = nonce_bytes.slice();
        let nonce = CipherNonce::from_slice(&nonce_slice);
        let tag_slice = authentication.slice();
        let tag = CipherTag::from_slice(&tag_slice);
        let result = match additional_data {
            Some(res) => self.cipher.decrypt_in_place_detached(&nonce, res.slice(), &mut ciphertext.slice_mut(), &tag),
            None => self.cipher.decrypt_in_place_detached(&nonce, &[], &mut ciphertext.slice_mut(), &tag),
        };
        match result {
            Ok(_) => Ok(ciphertext),
            Err(err) => Err(CryptoError::encryption_error("symmetric decryption", err)),
        }
    }
}
