//! Server-side cryptographic tool for TYPHOON protocol.

#[cfg(any(feature = "full_software", feature = "full_hardware"))]
use std::future::ready;
use std::hash::Hash;

use cfg_if::cfg_if;
use x25519_dalek::PublicKey as X25519PublicKey;

use crate::bytes::{ByteBuffer, ByteBufferMut, BytePool, DynamicByteBuffer, FixedByteBuffer};
use crate::cache::CachedMap;
use crate::crypto::error::CryptoError;
cfg_if! {
    if #[cfg(any(feature = "full_software", feature = "full_hardware"))] {
        use std::sync::Arc;
        use crate::certificate::ServerSecret;
    }
}

/// Ephemeral server handshake state: client X25519 public key, `McEliece` shared secret, nonce.
pub(crate) struct ServerData {
    pub(crate) ephemeral_key: X25519PublicKey,
    pub(crate) shared_secret: FixedByteBuffer<32>,
    pub(crate) nonce: FixedByteBuffer<32>,
}
use crate::crypto::symmetric::{ObfuscationTranscript, Symmetric};
use crate::settings::consts::ID_OFFSET;
use crate::trailer::{IdentityType, Trailer};

/// Per-user cryptographic state.
#[derive(Clone)]
pub(crate) struct UserCryptoState {
    key: Symmetric,
    #[cfg(any(feature = "fast_software", feature = "fast_hardware"))]
    obfuscation_key: Symmetric,
}

impl UserCryptoState {
    /// Create a new user crypto state from key material (fast mode).
    #[cfg(any(feature = "fast_software", feature = "fast_hardware"))]
    pub(crate) fn new(session_key: &impl ByteBuffer, obfuscation_buffer: impl ByteBuffer) -> Self {
        Self {
            key: Symmetric::new(session_key),
            obfuscation_key: Symmetric::new_split(&obfuscation_buffer, session_key),
        }
    }

    /// Create a new user crypto state from key material (full mode).
    #[cfg(any(feature = "full_software", feature = "full_hardware"))]
    pub(crate) fn new(session_key: &impl ByteBuffer) -> Self {
        Self {
            key: Symmetric::new(session_key),
        }
    }
}

impl UserCryptoState {
    /// Encrypt payload data with session key.
    pub(crate) fn encrypt_payload(&mut self, plaintext: DynamicByteBuffer, additional_data: Option<&DynamicByteBuffer>) -> Result<DynamicByteBuffer, CryptoError> {
        self.key.encrypt_auth(plaintext, additional_data)
    }

    /// Decrypt payload data with session key.
    pub(crate) fn decrypt_payload(&mut self, ciphertext: DynamicByteBuffer, additional_data: Option<&DynamicByteBuffer>) -> Result<DynamicByteBuffer, CryptoError> {
        self.key.decrypt_auth(ciphertext, additional_data)
    }
}

/// Combined per-user server state: crypto keys only.
/// Stored in the global `SharedMap`, accessed via `CachedMap` by crypto tool and flow managers.
/// Per-flow source addresses are tracked locally by each `ServerFlowManager`.
/// Active flow tracking is done lock-free in the session manager via `AtomicBitSet`.
#[derive(Clone)]
pub(crate) struct UserServerState {
    crypto: UserCryptoState,
}

impl UserServerState {
    pub(crate) fn new(crypto: UserCryptoState) -> Self {
        Self {
            crypto,
        }
    }

    /// Get mutable reference to the user's crypto state.
    #[inline]
    pub(crate) fn crypto_mut(&mut self) -> &mut UserCryptoState {
        &mut self.crypto
    }

    /// Replace the user's crypto state with one derived from the session key.
    /// Used after handshake to upgrade from initial key to session key.
    #[cfg(any(feature = "fast_software", feature = "fast_hardware"))]
    pub(crate) fn upgrade_crypto(&mut self, session_key: &impl ByteBuffer, obfuscation_buffer: impl ByteBuffer) {
        self.crypto = UserCryptoState::new(session_key, obfuscation_buffer);
    }

    /// Replace the user's crypto state with one derived from the session key.
    /// Used after handshake to upgrade from initial key to session key.
    #[cfg(any(feature = "full_software", feature = "full_hardware"))]
    pub(crate) fn upgrade_crypto(&mut self, session_key: &impl ByteBuffer) {
        self.crypto = UserCryptoState::new(session_key);
    }
}

/// Server-side cryptographic tool that manages per-user trailer encryption.
pub(crate) struct ServerCryptoTool<T: IdentityType + Clone + Eq + Hash + Send + ToString> {
    users: CachedMap<T, UserServerState>,
    /// Shared decryptor using OBFS-derived encryption key (fast mode only).
    /// All users share the same encryption key; only verification keys differ.
    #[cfg(any(feature = "fast_software", feature = "fast_hardware"))]
    shared_obfs_decryptor: Symmetric,
    #[cfg(any(feature = "full_software", feature = "full_hardware"))]
    secret: Arc<ServerSecret<'static>>,
}

impl<T: IdentityType + Clone + Eq + Hash + Send + ToString> ServerCryptoTool<T> {
    /// Create a new server crypto tool (fast mode).
    #[cfg(any(feature = "fast_software", feature = "fast_hardware"))]
    pub(crate) fn new(users: CachedMap<T, UserServerState>, obfs_buffer: impl ByteBuffer) -> Self {
        Self {
            users,
            shared_obfs_decryptor: Symmetric::new_split(&obfs_buffer, &obfs_buffer),
        }
    }

    /// Create a new server crypto tool (full mode).
    #[cfg(any(feature = "full_software", feature = "full_hardware"))]
    pub(crate) fn new(users: CachedMap<T, UserServerState>, secret: Arc<ServerSecret<'static>>) -> Self {
        Self {
            users,
            secret,
        }
    }

    /// Extract user identity from a raw trailer buffer.
    pub(crate) fn extract_identity(buffer: &DynamicByteBuffer) -> T {
        let correct_buffer = buffer.ensure_size(Trailer::<T>::len());
        T::from_bytes(correct_buffer.rebuffer_both(ID_OFFSET, ID_OFFSET + T::length()).slice())
    }

    /// Obfuscate trailer for sending to a specific user (fast mode).
    #[cfg(any(feature = "fast_software", feature = "fast_hardware"))]
    pub(crate) async fn obfuscate_trailer(&mut self, plaintext: DynamicByteBuffer, _: &BytePool) -> Result<DynamicByteBuffer, CryptoError> {
        let identity = Self::extract_identity(&plaintext);
        let user = self.users.get_mut(&identity).await.map_err(|e| CryptoError::authentication_error(&e.to_string()))?;
        user.crypto.obfuscation_key.encrypt_auth(plaintext, None::<&DynamicByteBuffer>)
    }

    /// Obfuscate trailer for sending to a specific user (full mode: encrypt with session key).
    #[cfg(any(feature = "full_software", feature = "full_hardware"))]
    pub(crate) async fn obfuscate_trailer(&mut self, plaintext: DynamicByteBuffer, _: &BytePool) -> Result<DynamicByteBuffer, CryptoError> {
        let identity = Self::extract_identity(&plaintext);
        let user = self.users.get_mut(&identity).await.map_err(|e| CryptoError::authentication_error(&e.to_string()))?;
        user.crypto.key.encrypt_auth(plaintext, None::<&DynamicByteBuffer>)
    }

    /// Deobfuscate received trailer (fast mode: decrypt with shared OBFS key, defer verification).
    #[cfg(any(feature = "fast_software", feature = "fast_hardware"))]
    pub(crate) fn deobfuscate_trailer(&mut self, ciphertext: DynamicByteBuffer, pool: &BytePool) -> Result<(DynamicByteBuffer, ObfuscationTranscript), CryptoError> {
        self.shared_obfs_decryptor.decrypt_no_verify(ciphertext, pool)
    }

    /// Deobfuscate received trailer (full mode: decrypt with server's X25519 secret).
    #[cfg(any(feature = "full_software", feature = "full_hardware"))]
    pub(crate) fn deobfuscate_trailer(&mut self, ciphertext: DynamicByteBuffer, _pool: &BytePool) -> Result<(DynamicByteBuffer, ObfuscationTranscript), CryptoError> {
        self.secret.decrypt_deobfuscate(ciphertext).map(|r| (r, ObfuscationTranscript {})).map_err(|e| CryptoError::authentication_error(&e.to_string()))
    }

    /// Verify trailer authentication (fast mode: verify with per-user key).
    #[cfg(any(feature = "fast_software", feature = "fast_hardware"))]
    pub(crate) async fn verify_trailer(&mut self, identity: &T, transcript: ObfuscationTranscript) -> Result<(), CryptoError> {
        let user = self.users.get_mut(identity).await.map_err(|e| CryptoError::authentication_error(&e.to_string()))?;
        user.crypto.obfuscation_key.verify_decrypted(transcript, None::<&DynamicByteBuffer>)
    }

    /// Verify trailer authentication (full mode: no-op).
    #[cfg(any(feature = "full_software", feature = "full_hardware"))]
    #[allow(clippy::unused_self)] // keeps the same call-site shape as the fast-mode variant
    pub(crate) fn verify_trailer(&mut self, _: &T, _: ObfuscationTranscript) -> impl Future<Output = Result<(), CryptoError>> {
        ready(Ok(()))
    }
}
