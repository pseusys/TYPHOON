use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use parking_lot::RwLock;

use crate::constants::tailor::TYPHOON_ID_LENGTH;
use crate::crypto::symmetric::Symmetric;

/// Shared session state for TYPHOON connections.
///
/// Thread-safe through atomic operations and RwLock for the cipher.
pub struct SessionState {
    /// Session identifier (UUID).
    session_id: [u8; TYPHOON_ID_LENGTH],
    /// Session cipher for marshalling encryption (protected by RwLock for interior mutability).
    session_cipher: RwLock<Symmetric>,
    /// Whether the session is currently active.
    active: AtomicBool,
    /// Current incremental packet number counter.
    incremental_pn: AtomicU32,
    /// Last validated incremental packet number (for replay protection).
    last_valid_pn: AtomicU32,
}

impl SessionState {
    /// Create a new session state.
    pub fn new(session_id: [u8; TYPHOON_ID_LENGTH], session_cipher: Symmetric) -> Self {
        Self {
            session_id,
            session_cipher: RwLock::new(session_cipher),
            active: AtomicBool::new(true),
            incremental_pn: AtomicU32::new(0),
            last_valid_pn: AtomicU32::new(0),
        }
    }

    /// Get the session ID.
    #[inline]
    pub fn session_id(&self) -> &[u8; TYPHOON_ID_LENGTH] {
        &self.session_id
    }

    /// Get read access to the session cipher.
    #[inline]
    pub fn cipher_read(&self) -> parking_lot::RwLockReadGuard<'_, Symmetric> {
        self.session_cipher.read()
    }

    /// Get write access to the session cipher.
    #[inline]
    pub fn cipher_write(&self) -> parking_lot::RwLockWriteGuard<'_, Symmetric> {
        self.session_cipher.write()
    }

    /// Check if the session is active.
    #[inline]
    pub fn is_active(&self) -> bool {
        self.active.load(Ordering::Acquire)
    }

    /// Deactivate the session.
    pub fn deactivate(&self) {
        self.active.store(false, Ordering::Release);
    }

    /// Activate the session.
    pub fn activate(&self) {
        self.active.store(true, Ordering::Release);
    }

    /// Generate the next packet number.
    ///
    /// Returns a 64-bit packet number with:
    /// - Upper 32 bits: current Unix timestamp in seconds
    /// - Lower 32 bits: incremental counter
    pub fn next_packet_number(&self) -> u64 {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as u32)
            .unwrap_or(0);

        let incremental = self.incremental_pn.fetch_add(1, Ordering::AcqRel);
        ((timestamp as u64) << 32) | (incremental as u64)
    }

    /// Get the current incremental packet number without incrementing.
    pub fn current_incremental(&self) -> u32 {
        self.incremental_pn.load(Ordering::Acquire)
    }

    /// Validate a received packet number.
    ///
    /// For replay protection, we check that the incremental portion
    /// is greater than the last validated incremental, with some
    /// tolerance for reordering.
    ///
    /// Returns true if the packet number is valid.
    pub fn validate_packet_number(&self, packet_number: u64) -> bool {
        let pn_incremental = packet_number as u32;
        let last_valid = self.last_valid_pn.load(Ordering::Acquire);

        // Allow some reordering (up to 100 packets behind)
        // but reject obvious replays
        if pn_incremental > last_valid || last_valid.saturating_sub(pn_incremental) < 100 {
            // Update last valid if this is higher
            if pn_incremental > last_valid {
                self.last_valid_pn.store(pn_incremental, Ordering::Release);
            }
            true
        } else {
            false
        }
    }

    /// Extract timestamp from a packet number.
    #[inline]
    pub fn extract_timestamp(packet_number: u64) -> u32 {
        (packet_number >> 32) as u32
    }

    /// Extract incremental from a packet number.
    #[inline]
    pub fn extract_incremental(packet_number: u64) -> u32 {
        packet_number as u32
    }

    /// Compose a packet number from timestamp and incremental.
    #[inline]
    pub fn compose_packet_number(timestamp: u32, incremental: u32) -> u64 {
        ((timestamp as u64) << 32) | (incremental as u64)
    }
}

impl Clone for SessionState {
    fn clone(&self) -> Self {
        Self {
            session_id: self.session_id,
            session_cipher: RwLock::new(self.session_cipher.read().clone()),
            active: AtomicBool::new(self.active.load(Ordering::Acquire)),
            incremental_pn: AtomicU32::new(self.incremental_pn.load(Ordering::Acquire)),
            last_valid_pn: AtomicU32::new(self.last_valid_pn.load(Ordering::Acquire)),
        }
    }
}

#[cfg(test)]
#[path = "../../tests/session/state.rs"]
mod tests;
