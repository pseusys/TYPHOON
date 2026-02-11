#[cfg(test)]
#[path = "../../tests/crypto/symmetric.rs"]
mod tests;

use cfg_if::cfg_if;

use crate::bytes::{ByteBuffer, ByteBufferMut, DynamicByteBuffer, StaticByteBuffer};
use crate::crypto::error::CryptoError;
use crate::utils::random::{SupportRng, get_rng};

cfg_if! {
    if #[cfg(any(feature = "fast_software", feature = "fast_hardware"))] {
        use blake3::{KEY_LEN, Hasher, keyed_hash, derive_key};
        use subtle::ConstantTimeEq;
    }
}

cfg_if! {
    if #[cfg(any(feature = "fast_software", feature = "full_software"))] {
        use chacha20::XChaCha20;
        use chacha20::cipher::{KeyIvInit, StreamCipher};
        type AnonymousCipher = XChaCha20;
    }
}

cfg_if! {
    if #[cfg(any(feature = "fast_hardware", feature = "full_hardware"))] {
        use aes::Aes256;
        use aes::cipher::{KeyIvInit, StreamCipher};
        use ctr::Ctr128BE;
        type AnonymousCipher = Ctr128BE<Aes256>;
    }
}

cfg_if! {
    if #[cfg(feature = "full_software")] {
        use chacha20poly1305::aead::AeadMutInPlace;
        use chacha20poly1305::{AeadCore, Key, KeyInit, Tag, XChaCha20Poly1305, XNonce};
        type Cipher = XChaCha20Poly1305;
        type CipherKey = Key;
        type CipherTag = Tag;
        type CipherNonce = XNonce;
    } else if #[cfg(feature = "full_hardware")] {
        use aes_gcm::aead::AeadMutInPlace;
        use aes_gcm::aead::consts::U12;
        use aes_gcm::{AeadCore, Aes256Gcm, Key, KeyInit, Tag, Nonce};
        type Cipher = Aes256Gcm;
        type CipherKey = Key::<Aes256Gcm>;
        type CipherTag = Tag;
        type CipherNonce = Nonce::<U12>;
    }
}

pub const SYMMETRIC_KEY_LENGTH: usize = 32;
pub const SYMMETRIC_BUILT_IN_AUTH_LEN: usize = 16;
pub const SYMMETRIC_ADDITIONAL_AUTH_LEN: usize = 32;

#[cfg(any(feature = "fast_software", feature = "full_software"))]
pub const NONCE_LEN: usize = 24;

#[cfg(any(feature = "fast_software", feature = "full_software"))]
pub const ANONYMOUS_NONCE_LEN: usize = 24;

#[cfg(any(feature = "fast_hardware", feature = "full_hardware"))]
pub const NONCE_LEN: usize = 12;

#[cfg(any(feature = "fast_hardware", feature = "full_hardware"))]
pub const ANONYMOUS_NONCE_LEN: usize = 16;

#[cfg(any(feature = "fast_software", feature = "fast_hardware"))]
const VERIFICATION_KEY_DERIVATION: &str = "obfuscation key derivation key";

#[cfg(any(feature = "fast_software", feature = "fast_hardware"))]
const ENCRYPTION_KEY_DERIVATION: &str = "encryption key derivation key";

/// Transcript for delayed tailor verification (fast mode only).
#[cfg(any(feature = "fast_software", feature = "fast_hardware"))]
pub struct ObfuscationTranscript {
    pub(crate) ciphertext_copy: DynamicByteBuffer,
    pub(crate) auth_transcript: DynamicByteBuffer,
}

/// Transcript placeholder (full mode).
#[cfg(any(feature = "full_software", feature = "full_hardware"))]
pub struct ObfuscationTranscript {}

/// Encrypt plaintext using unauthenticated stream cipher. Appends nonce to output.
/// Args: key (32-byte), plaintext (modified in-place). Returns: ciphertext with nonce.
#[inline]
pub fn encrypt_anonymously(key: &StaticByteBuffer, plaintext: &mut DynamicByteBuffer) -> DynamicByteBuffer {
    let key_bytes: [u8; SYMMETRIC_KEY_LENGTH] = key.into();
    let nonce = get_rng().random_byte_array::<ANONYMOUS_NONCE_LEN>();
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

/// Authenticated symmetric cipher for marshalling encryption (XChaCha20-Poly1305 or AES-GCM).
#[derive(Clone)]
pub struct Symmetric {
    #[cfg(all(any(feature = "fast_software", feature = "fast_hardware")))]
    encryption_key: StaticByteBuffer,
    #[cfg(all(any(feature = "fast_software", feature = "fast_hardware")))]
    verification_key: StaticByteBuffer,
    #[cfg(all(any(feature = "full_software", feature = "full_hardware")))]
    cipher: Cipher,
}

impl Symmetric {
    #[cfg(all(any(feature = "fast_software", feature = "fast_hardware")))]
    pub fn new_split(encryption_key: StaticByteBuffer, verification_key: StaticByteBuffer) -> Self {
        Self {
            encryption_key,
            verification_key,
        }
    }

    /// Create cipher from 32-byte key. Returns: Symmetric instance.
    #[cfg(all(any(feature = "fast_software", feature = "fast_hardware")))]
    pub fn new(key: &StaticByteBuffer) -> Self {
        Self {
            encryption_key: StaticByteBuffer::from_slice(&derive_key(ENCRYPTION_KEY_DERIVATION, key.slice())),
            verification_key: StaticByteBuffer::from_slice(&derive_key(VERIFICATION_KEY_DERIVATION, key.slice())),
        }
    }

    /// Create cipher from 32-byte key. Returns: Symmetric instance.
    #[cfg(all(any(feature = "full_software", feature = "full_hardware")))]
    pub fn new(key: &StaticByteBuffer) -> Self {
        let private_bytes: [u8; SYMMETRIC_KEY_LENGTH] = key.into();
        let cipher = Cipher::new(CipherKey::from_slice(&private_bytes));
        Self {
            cipher,
        }
    }

    /// Encrypt with authentication. Returns: nonce || ciphertext || 16-byte tag.
    #[cfg(all(any(feature = "fast_software", feature = "fast_hardware")))]
    pub fn encrypt_auth<A: ByteBuffer>(&mut self, mut plaintext: DynamicByteBuffer, additional_data: Option<&A>) -> Result<DynamicByteBuffer, CryptoError> {
        let hash_key_bytes: [u8; KEY_LEN] = (&self.verification_key).into();
        let ciphertext = encrypt_anonymously(&self.encryption_key, &mut plaintext);
        let hash = match additional_data {
            Some(res) => Hasher::new_keyed(&hash_key_bytes).update(ciphertext.slice()).update(res.slice()).finalize(),
            None => keyed_hash(&hash_key_bytes, ciphertext.slice()),
        };
        Ok(ciphertext.append(hash.as_bytes()))
    }

    /// Encrypt with authentication. Returns: nonce || ciphertext || 16-byte tag.
    #[cfg(all(any(feature = "full_software", feature = "full_hardware")))]
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

    #[cfg(all(any(feature = "fast_software", feature = "fast_hardware")))]
    pub fn decrypt_no_verify(&mut self, ciphertext_authenticated: DynamicByteBuffer) -> (DynamicByteBuffer, ObfuscationTranscript) {
        let (ciphertext_with_nonce, authentication) = ciphertext_authenticated.split_buf(ciphertext_authenticated.len() - SYMMETRIC_ADDITIONAL_AUTH_LEN);
        let plaintext = decrypt_anonymously(&self.encryption_key, &mut ciphertext_with_nonce.copy());
        (plaintext, ObfuscationTranscript {
            ciphertext_copy: ciphertext_with_nonce,
            auth_transcript: authentication,
        })
    }

    #[cfg(all(any(feature = "fast_software", feature = "fast_hardware")))]
    pub fn verify_decrypted<A: ByteBuffer>(&mut self, obfuscation_transcript: ObfuscationTranscript, additional_data: Option<&A>) -> Result<(), CryptoError> {
        let hash_key_bytes: [u8; KEY_LEN] = (&self.verification_key).into();
        let hash = match additional_data {
            Some(res) => Hasher::new_keyed(&hash_key_bytes).update(obfuscation_transcript.ciphertext_copy.slice()).update(res.slice()).finalize(),
            None => keyed_hash(&hash_key_bytes, obfuscation_transcript.ciphertext_copy.slice()),
        };
        if hash.as_bytes().ct_eq(obfuscation_transcript.auth_transcript.slice()).unwrap_u8() == 0 {
            return Err(CryptoError::authentication_error("authentication error (hashes not equal)"));
        }
        Ok(())
    }

    /// Decrypt and verify authentication tag. Args: nonce || ciphertext || tag. Returns: plaintext.
    #[cfg(all(any(feature = "fast_software", feature = "fast_hardware")))]
    pub fn decrypt_auth<A: ByteBuffer>(&mut self, ciphertext_authenticated: DynamicByteBuffer, additional_data: Option<&A>) -> Result<DynamicByteBuffer, CryptoError> {
        let (plaintext, transcript) = self.decrypt_no_verify(ciphertext_authenticated);
        self.verify_decrypted(transcript, additional_data).map(|_| plaintext)
    }

    /// Decrypt and verify authentication tag. Args: nonce || ciphertext || tag. Returns: plaintext.
    #[cfg(all(any(feature = "full_software", feature = "full_hardware")))]
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
