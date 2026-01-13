use cfg_if::cfg_if;

use crate::bytes::ByteBuffer;
use crate::crypto::symmetric::{Symmetric, NONCE_LEN, SYMMETRIC_FIRST_AUTH_LEN};
use crate::error::{TyphoonError, TyphoonResult};
use crate::tailor::structure::Tailor;

cfg_if! {
    if #[cfg(feature = "fast")] {
        use blake3::{KEY_LEN, keyed_hash};
        use constant_time_eq::constant_time_eq;
        use crate::crypto::symmetric::SYMMETRIC_SECOND_AUTH_LEN;
    }
}

/// Overhead added by tailor encryption.
/// In fast mode: nonce + first auth tag + second auth hash.
/// In full mode for server->client: nonce + auth tag.
/// In full mode for client->server: additional X25519 overhead (handled separately).
#[cfg(feature = "fast")]
pub const TAILOR_ENCRYPTION_OVERHEAD: usize =
    NONCE_LEN + SYMMETRIC_FIRST_AUTH_LEN + SYMMETRIC_SECOND_AUTH_LEN;

#[cfg(all(feature = "full", not(feature = "fast")))]
pub const TAILOR_ENCRYPTION_OVERHEAD: usize = NONCE_LEN + SYMMETRIC_FIRST_AUTH_LEN;

/// Total encrypted tailor size.
pub const ENCRYPTED_TAILOR_SIZE: usize = Tailor::SIZE + TAILOR_ENCRYPTION_OVERHEAD;

/// Tailor codec for encryption and decryption.
///
/// In `fast` mode, tailors are encrypted with the obfuscation key (OBFS)
/// and authenticated with both AEAD and BLAKE3 using the session key.
///
/// In `full` mode, the encryption method depends on direction:
/// - Server to client: simple marshalling encryption with session key
/// - Client to server: X25519 ephemeral exchange (not implemented here)
pub struct TailorCodec {
    /// Obfuscation cipher (uses OBFS key in fast mode).
    obfuscation_cipher: Symmetric,
}

impl TailorCodec {
    /// Create a new tailor codec with the given obfuscation key.
    pub fn new(obfuscation_key: &ByteBuffer) -> TyphoonResult<Self> {
        let obfuscation_cipher = Symmetric::new(obfuscation_key)
            .map_err(|e| TyphoonError::KeyDerivationFailed(e.to_string()))?;
        Ok(Self { obfuscation_cipher })
    }

    /// Encrypt a tailor in fast mode.
    ///
    /// Returns: nonce || ciphertext || AEAD tag || BLAKE3 hash
    #[cfg(feature = "fast")]
    pub fn encrypt(&mut self, tailor: &Tailor, session_key: &ByteBuffer) -> TyphoonResult<ByteBuffer> {
        // Allocate buffer with capacity for nonce (before) and tags (after)
        let after_cap = SYMMETRIC_FIRST_AUTH_LEN + SYMMETRIC_SECOND_AUTH_LEN;
        let plaintext = tailor.to_buffer_with_capacity(NONCE_LEN, after_cap);

        let encrypted = self
            .obfuscation_cipher
            .encrypt_auth_twice(plaintext, None, session_key)
            .map_err(|e| TyphoonError::EncryptionFailed(e.to_string()))?;

        Ok(encrypted)
    }

    /// Decrypt a tailor in fast mode.
    ///
    /// Input: nonce || ciphertext || AEAD tag || BLAKE3 hash
    /// Returns: decrypted Tailor
    #[cfg(feature = "fast")]
    pub fn decrypt(&mut self, encrypted: ByteBuffer, session_key: &ByteBuffer) -> TyphoonResult<Tailor> {
        let (plaintext, ciphertext_with_nonce, second_auth) = self
            .obfuscation_cipher
            .decrypt_auth_twice(encrypted, None)
            .map_err(|e| TyphoonError::DecryptionFailed(e.to_string()))?;

        // Verify second authentication (BLAKE3)
        self.obfuscation_cipher
            .verify_second_auth(&ciphertext_with_nonce, None, session_key, &second_auth)
            .map_err(|e| TyphoonError::TailorVerificationFailed(e.to_string()))?;

        Tailor::from_buffer(&plaintext)
    }

    /// Decrypt and verify tailor authentication only (for server-side demultiplexing).
    ///
    /// This method first decrypts the tailor using the obfuscation key,
    /// then extracts the session ID from the tailor to look up the session key.
    /// Verification of the second auth hash is deferred until the session key is known.
    #[cfg(feature = "fast")]
    pub fn decrypt_without_session_verify(&mut self, encrypted: ByteBuffer) -> TyphoonResult<(Tailor, ByteBuffer, ByteBuffer)> {
        let (plaintext, ciphertext_with_nonce, second_auth) = self
            .obfuscation_cipher
            .decrypt_auth_twice(encrypted, None)
            .map_err(|e| TyphoonError::DecryptionFailed(e.to_string()))?;

        let tailor = Tailor::from_buffer(&plaintext)?;
        Ok((tailor, ciphertext_with_nonce, second_auth))
    }

    /// Verify tailor second authentication after session lookup.
    #[cfg(feature = "fast")]
    pub fn verify_session_auth(
        &mut self,
        ciphertext_with_nonce: &ByteBuffer,
        session_key: &ByteBuffer,
        second_auth: &ByteBuffer,
    ) -> TyphoonResult<()> {
        self.obfuscation_cipher
            .verify_second_auth(ciphertext_with_nonce, None, session_key, second_auth)
            .map_err(|e| TyphoonError::TailorVerificationFailed(e.to_string()))
    }

    /// Encrypt a tailor in full mode (server to client direction).
    ///
    /// Uses simple marshalling encryption with session key.
    #[cfg(all(feature = "full", not(feature = "fast")))]
    pub fn encrypt(&mut self, tailor: &Tailor, session_key: &ByteBuffer) -> TyphoonResult<ByteBuffer> {
        let mut session_cipher = Symmetric::new(session_key)
            .map_err(|e| TyphoonError::KeyDerivationFailed(e.to_string()))?;

        // Allocate buffer with capacity for nonce (before) and tag (after)
        let plaintext = tailor.to_buffer_with_capacity(NONCE_LEN, SYMMETRIC_FIRST_AUTH_LEN);
        let encrypted = session_cipher
            .encrypt_auth(plaintext, None)
            .map_err(|e| TyphoonError::EncryptionFailed(e.to_string()))?;

        Ok(encrypted)
    }

    /// Decrypt a tailor in full mode (server to client direction).
    #[cfg(all(feature = "full", not(feature = "fast")))]
    pub fn decrypt(&mut self, encrypted: ByteBuffer, session_key: &ByteBuffer) -> TyphoonResult<Tailor> {
        let mut session_cipher = Symmetric::new(session_key)
            .map_err(|e| TyphoonError::KeyDerivationFailed(e.to_string()))?;

        let plaintext = session_cipher
            .decrypt_auth(encrypted, None)
            .map_err(|e| TyphoonError::DecryptionFailed(e.to_string()))?;

        Tailor::from_buffer(&plaintext)
    }
}

/// Extract encrypted tailor from a packet buffer.
///
/// The tailor is always at the end of the packet.
/// Returns: (packet_body, encrypted_tailor)
pub fn extract_encrypted_tailor(packet: ByteBuffer) -> TyphoonResult<(ByteBuffer, ByteBuffer)> {
    if packet.len() < ENCRYPTED_TAILOR_SIZE {
        return Err(TyphoonError::InvalidPacket(format!(
            "Packet too small for tailor: {} < {}",
            packet.len(),
            ENCRYPTED_TAILOR_SIZE
        )));
    }

    let split_point = packet.len() - ENCRYPTED_TAILOR_SIZE;
    Ok(packet.split_buf(split_point))
}

/// Append encrypted tailor to a packet body.
pub fn append_encrypted_tailor(body: ByteBuffer, encrypted_tailor: ByteBuffer) -> ByteBuffer {
    body.append_buf(&encrypted_tailor)
}

#[cfg(test)]
#[path = "../../tests/tailor/codec.rs"]
mod tests;
