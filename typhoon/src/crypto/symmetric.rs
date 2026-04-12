#[cfg(test)]
#[path = "../../tests/crypto/symmetric.rs"]
mod tests;

use cfg_if::cfg_if;

#[cfg(any(feature = "fast_software", feature = "fast_hardware"))]
use crate::bytes::BytePool;
use crate::bytes::{ByteBuffer, ByteBufferMut, DynamicByteBuffer};
use crate::crypto::error::CryptoError;
use crate::utils::random::{SupportRng, get_rng};

cfg_if! {
    if #[cfg(any(feature = "fast_software", feature = "fast_hardware"))] {
        use blake3::{Hasher, keyed_hash, derive_key};
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

pub(crate) const SYMMETRIC_KEY_LENGTH: usize = 32;
pub(crate) const SYMMETRIC_BUILT_IN_AUTH_LEN: usize = 16;
pub(crate) const SYMMETRIC_ADDITIONAL_AUTH_LEN: usize = 32;

/// Bytes added to a payload by `encrypt_auth` (nonce + authentication tag).
/// Used to compute the maximum user-data that fits within MTU.
#[cfg(any(feature = "fast_software", feature = "fast_hardware"))]
pub(crate) const PAYLOAD_CRYPTO_OVERHEAD: usize = ANONYMOUS_NONCE_LEN + SYMMETRIC_ADDITIONAL_AUTH_LEN;

#[cfg(any(feature = "full_software", feature = "full_hardware"))]
pub(crate) const PAYLOAD_CRYPTO_OVERHEAD: usize = NONCE_LEN + SYMMETRIC_BUILT_IN_AUTH_LEN;

#[cfg(any(feature = "fast_software", feature = "full_software"))]
pub(crate) const NONCE_LEN: usize = 24;

#[cfg(any(feature = "fast_software", feature = "full_software"))]
pub(crate) const ANONYMOUS_NONCE_LEN: usize = 24;

#[cfg(any(feature = "fast_hardware", feature = "full_hardware"))]
pub(crate) const NONCE_LEN: usize = 12;

#[cfg(any(feature = "fast_hardware", feature = "full_hardware"))]
pub(crate) const ANONYMOUS_NONCE_LEN: usize = 16;

#[cfg(any(feature = "fast_software", feature = "fast_hardware"))]
const VERIFICATION_KEY_DERIVATION: &str = "obfuscation key derivation key";

#[cfg(any(feature = "fast_software", feature = "fast_hardware"))]
const ENCRYPTION_KEY_DERIVATION: &str = "encryption key derivation key";

/// Transcript for delayed tailor verification (fast mode only).
#[cfg(any(feature = "fast_software", feature = "fast_hardware"))]
pub(crate) struct ObfuscationTranscript {
    /// Pool-backed copy of the ciphertext for deferred BLAKE3 MAC verification.
    pub(crate) ciphertext_copy: DynamicByteBuffer,
    pub(crate) auth_transcript: DynamicByteBuffer,
}

/// Transcript placeholder (full mode).
#[cfg(any(feature = "full_software", feature = "full_hardware"))]
pub(crate) struct ObfuscationTranscript {}

/// Encrypt plaintext using unauthenticated stream cipher. Appends nonce to output.
/// Args: key (32-byte slice), plaintext (modified in-place). Returns: ciphertext with nonce.
#[inline]
pub(crate) fn encrypt_anonymously(key: &[u8], plaintext: &mut DynamicByteBuffer) -> DynamicByteBuffer {
    let key_bytes: [u8; SYMMETRIC_KEY_LENGTH] = key.try_into().expect("key must be 32 bytes");
    let nonce = get_rng().random_byte_array::<ANONYMOUS_NONCE_LEN>();
    AnonymousCipher::new(&key_bytes.into(), &nonce.into()).apply_keystream(&mut plaintext.slice_mut());
    plaintext.append(&nonce)
}

/// Decrypt ciphertext using unauthenticated stream cipher. Extracts nonce from end.
/// Args: key (32-byte slice), ciphertext_with_nonce. Returns: plaintext.
#[inline]
pub(crate) fn decrypt_anonymously(key: &[u8], ciphertext_with_nonce: &mut DynamicByteBuffer) -> DynamicByteBuffer {
    let (ciphertext, nonce_bytes) = ciphertext_with_nonce.split_buf(ciphertext_with_nonce.len() - ANONYMOUS_NONCE_LEN);
    let key_bytes: [u8; SYMMETRIC_KEY_LENGTH] = key.try_into().expect("key must be 32 bytes");
    let nonce: [u8; ANONYMOUS_NONCE_LEN] = nonce_bytes.slice().try_into().expect("nonce must be ANONYMOUS_NONCE_LEN bytes");
    AnonymousCipher::new(&key_bytes.into(), &nonce.into()).apply_keystream(&mut ciphertext.slice_mut());
    ciphertext
}

/// Authenticated symmetric cipher for marshalling encryption (XChaCha20-Poly1305 or AES-GCM).
#[derive(Clone)]
pub(crate) struct Symmetric {
    /// Encryption key derived from the session key (fast mode).
    #[cfg(any(feature = "fast_software", feature = "fast_hardware"))]
    encryption_key: [u8; SYMMETRIC_KEY_LENGTH],
    /// Verification key derived from the session key (fast mode).
    #[cfg(any(feature = "fast_software", feature = "fast_hardware"))]
    verification_key: [u8; SYMMETRIC_KEY_LENGTH],
    #[cfg(any(feature = "full_software", feature = "full_hardware"))]
    cipher: Cipher,
}

impl Symmetric {
    /// Create cipher from two raw 32-byte keys (fast mode: encryption + verification split).
    #[cfg(any(feature = "fast_software", feature = "fast_hardware"))]
    pub(crate) fn new_split(encryption_key: &impl ByteBuffer, verification_key: &impl ByteBuffer) -> Self {
        Self {
            encryption_key: encryption_key.slice().try_into().expect("encryption key must be 32 bytes"),
            verification_key: verification_key.slice().try_into().expect("verification key must be 32 bytes"),
        }
    }

    /// Create cipher from 32-byte key, deriving encryption and verification sub-keys. Returns: Symmetric instance.
    #[cfg(any(feature = "fast_software", feature = "fast_hardware"))]
    pub(crate) fn new(key: &impl ByteBuffer) -> Self {
        Self {
            encryption_key: derive_key(ENCRYPTION_KEY_DERIVATION, key.slice()),
            verification_key: derive_key(VERIFICATION_KEY_DERIVATION, key.slice()),
        }
    }

    /// Create cipher from 32-byte key. Returns: Symmetric instance.
    #[cfg(any(feature = "full_software", feature = "full_hardware"))]
    pub(crate) fn new(key: &impl ByteBuffer) -> Self {
        let private_bytes: [u8; SYMMETRIC_KEY_LENGTH] = key.slice().try_into().expect("key must be 32 bytes");
        let cipher = Cipher::new(CipherKey::from_slice(&private_bytes));
        Self {
            cipher,
        }
    }

    /// Encrypt with authentication. Returns: nonce || ciphertext || 32-byte tag.
    #[cfg(any(feature = "fast_software", feature = "fast_hardware"))]
    pub(crate) fn encrypt_auth<A: ByteBuffer>(&mut self, mut plaintext: DynamicByteBuffer, additional_data: Option<&A>) -> Result<DynamicByteBuffer, CryptoError> {
        let ciphertext = encrypt_anonymously(&self.encryption_key, &mut plaintext);
        let hash = match additional_data {
            Some(res) => Hasher::new_keyed(&self.verification_key).update(ciphertext.slice()).update(res.slice()).finalize(),
            None => keyed_hash(&self.verification_key, ciphertext.slice()),
        };
        Ok(ciphertext.append(hash.as_bytes()))
    }

    /// Encrypt with authentication. Returns: nonce || ciphertext || 16-byte tag.
    #[cfg(any(feature = "full_software", feature = "full_hardware"))]
    pub(crate) fn encrypt_auth<A: ByteBuffer>(&mut self, plaintext: DynamicByteBuffer, additional_data: Option<&A>) -> Result<DynamicByteBuffer, CryptoError> {
        let nonce = Cipher::generate_nonce(get_rng());
        let result = match additional_data {
            Some(res) => self.cipher.encrypt_in_place_detached(&nonce, res.slice(), &mut plaintext.slice_mut()),
            None => self.cipher.encrypt_in_place_detached(&nonce, &[], &mut plaintext.slice_mut()),
        }
        .map_err(|e| CryptoError::encryption_error("symmetric encryption", e))?;
        Ok(plaintext.append(&nonce).append(&result))
    }

    #[cfg(any(feature = "fast_software", feature = "fast_hardware"))]
    pub(crate) fn decrypt_no_verify(&mut self, ciphertext_authenticated: DynamicByteBuffer, pool: &BytePool) -> (DynamicByteBuffer, ObfuscationTranscript) {
        let (mut ciphertext_with_nonce, authentication) = ciphertext_authenticated.split_buf(ciphertext_authenticated.len() - SYMMETRIC_ADDITIONAL_AUTH_LEN);
        let ciphertext_copy = pool.allocate_precise_from_slice_with_capacity(ciphertext_with_nonce.slice(), 0, 0);
        let plaintext = decrypt_anonymously(&self.encryption_key, &mut ciphertext_with_nonce);
        (
            plaintext,
            ObfuscationTranscript {
                ciphertext_copy,
                auth_transcript: authentication,
            },
        )
    }

    #[cfg(any(feature = "fast_software", feature = "fast_hardware"))]
    pub(crate) fn verify_decrypted<A: ByteBuffer>(&mut self, obfuscation_transcript: ObfuscationTranscript, additional_data: Option<&A>) -> Result<(), CryptoError> {
        let hash = match additional_data {
            Some(res) => Hasher::new_keyed(&self.verification_key).update(obfuscation_transcript.ciphertext_copy.slice()).update(res.slice()).finalize(),
            None => keyed_hash(&self.verification_key, obfuscation_transcript.ciphertext_copy.slice()),
        };
        if hash.as_bytes().ct_eq(obfuscation_transcript.auth_transcript.slice()).unwrap_u8() == 0 {
            return Err(CryptoError::authentication_error("authentication error (hashes not equal)"));
        }
        Ok(())
    }

    /// Decrypt and verify authentication tag. Args: nonce || ciphertext || tag. Returns: plaintext.
    /// Verifies MAC over the ciphertext before decrypting; no copy or pool allocation needed.
    #[cfg(any(feature = "fast_software", feature = "fast_hardware"))]
    pub(crate) fn decrypt_auth<A: ByteBuffer>(&mut self, ciphertext_authenticated: DynamicByteBuffer, additional_data: Option<&A>) -> Result<DynamicByteBuffer, CryptoError> {
        let (mut ciphertext_with_nonce, authentication) = ciphertext_authenticated.split_buf(ciphertext_authenticated.len() - SYMMETRIC_ADDITIONAL_AUTH_LEN);
        let hash = match additional_data {
            Some(res) => Hasher::new_keyed(&self.verification_key).update(ciphertext_with_nonce.slice()).update(res.slice()).finalize(),
            None => keyed_hash(&self.verification_key, ciphertext_with_nonce.slice()),
        };
        if hash.as_bytes().ct_eq(authentication.slice()).unwrap_u8() == 0 {
            return Err(CryptoError::authentication_error("authentication error (hashes not equal)"));
        }
        Ok(decrypt_anonymously(&self.encryption_key, &mut ciphertext_with_nonce))
    }

    /// Decrypt and verify authentication tag. Args: nonce || ciphertext || tag. Returns: plaintext.
    #[cfg(any(feature = "full_software", feature = "full_hardware"))]
    pub(crate) fn decrypt_auth<A: ByteBuffer>(&mut self, ciphertext_authenticated: DynamicByteBuffer, additional_data: Option<&A>) -> Result<DynamicByteBuffer, CryptoError> {
        let (ciphertext_with_nonce, authentication) = ciphertext_authenticated.split_buf(ciphertext_authenticated.len() - SYMMETRIC_BUILT_IN_AUTH_LEN);
        let (ciphertext, nonce_bytes) = ciphertext_with_nonce.split_buf(ciphertext_with_nonce.len() - NONCE_LEN);
        let nonce_slice = nonce_bytes.slice();
        let nonce = CipherNonce::from_slice(&nonce_slice);
        let tag_slice = authentication.slice();
        let tag = CipherTag::from_slice(&tag_slice);
        match additional_data {
            Some(res) => self.cipher.decrypt_in_place_detached(&nonce, res.slice(), &mut ciphertext.slice_mut(), &tag),
            None => self.cipher.decrypt_in_place_detached(&nonce, &[], &mut ciphertext.slice_mut(), &tag),
        }
        .map_err(|e| CryptoError::encryption_error("symmetric decryption", e))?;
        Ok(ciphertext)
    }
}
