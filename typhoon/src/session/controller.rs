use crate::bytes::ByteBuffer;
use crate::constants::tailor::TYPHOON_ID_LENGTH;
use crate::crypto::symmetric::Symmetric;
use crate::error::TyphoonResult;
use crate::session::health::HealthCheckProvider;
use crate::session::state::SessionState;
use crate::tailor::Tailor;

/// Core session controller interface.
///
/// Defines the common interface for both client and server session managers.
pub trait SessionController: Send + Sync {
    /// Process an incoming data packet.
    ///
    /// Decrypts the payload and returns the plaintext data.
    /// Returns None if the packet should be discarded (e.g., decoy or health-check-only).
    fn process_data(&self, packet: ByteBuffer, tailor: &Tailor) -> TyphoonResult<Option<ByteBuffer>>;

    /// Prepare outgoing data for transmission.
    ///
    /// Encrypts the payload and creates the tailor.
    fn prepare_data(&self, payload: ByteBuffer) -> TyphoonResult<(ByteBuffer, Tailor)>;

    /// Get the session ID.
    fn session_id(&self) -> &[u8; TYPHOON_ID_LENGTH];

    /// Check if the session is active.
    fn is_active(&self) -> bool;

    /// Terminate the session.
    fn terminate(&self) -> TyphoonResult<()>;
}

/// Base session manager with common functionality.
///
/// Provides shared implementation for client and server sessions.
pub struct BaseSessionManager {
    /// Session state.
    state: SessionState,
    /// Health check provider.
    health: HealthCheckProvider,
}

impl BaseSessionManager {
    /// Create a new base session manager.
    pub fn new(session_id: [u8; TYPHOON_ID_LENGTH], session_cipher: Symmetric) -> Self {
        Self {
            state: SessionState::new(session_id, session_cipher),
            health: HealthCheckProvider::new(),
        }
    }

    /// Get a reference to the session state.
    pub fn state(&self) -> &SessionState {
        &self.state
    }

    /// Get a reference to the health check provider.
    pub fn health(&self) -> &HealthCheckProvider {
        &self.health
    }

    /// Get a mutable reference to the health check provider.
    pub fn health_mut(&mut self) -> &mut HealthCheckProvider {
        &mut self.health
    }

    /// Get the session ID.
    pub fn session_id(&self) -> &[u8; TYPHOON_ID_LENGTH] {
        self.state.session_id()
    }

    /// Check if the session is active.
    pub fn is_active(&self) -> bool {
        self.state.is_active() && self.health.is_active()
    }

    /// Generate the next packet number.
    pub fn next_packet_number(&self) -> u64 {
        self.state.next_packet_number()
    }

    /// Validate a received packet number.
    pub fn validate_packet_number(&self, packet_number: u64) -> bool {
        self.state.validate_packet_number(packet_number)
    }

    /// Process a received health check.
    pub fn process_health_check(&self, packet_number: u64, next_in: u32) -> bool {
        self.health.process_received(packet_number, next_in)
    }

    /// Mark handshake as complete.
    pub fn handshake_complete(&self) {
        self.health.handshake_complete();
    }

    /// Encrypt payload data.
    pub fn encrypt_payload(&self, plaintext: ByteBuffer) -> TyphoonResult<ByteBuffer> {
        self.state
            .cipher_write()
            .encrypt_auth(plaintext, None)
            .map_err(|e| crate::error::TyphoonError::EncryptionFailed(e.to_string()))
    }

    /// Decrypt payload data.
    pub fn decrypt_payload(&self, ciphertext: ByteBuffer) -> TyphoonResult<ByteBuffer> {
        self.state
            .cipher_write()
            .decrypt_auth(ciphertext, None)
            .map_err(|e| crate::error::TyphoonError::DecryptionFailed(e.to_string()))
    }

    /// Terminate the session.
    pub fn terminate(&self) {
        self.state.deactivate();
        self.health.terminate();
    }

    /// Get current RTT estimate.
    pub fn get_rtt(&self) -> u32 {
        self.health.get_rtt()
    }

    /// Get current timeout value.
    pub fn get_timeout(&self) -> u32 {
        self.health.get_timeout()
    }
}

#[cfg(test)]
#[path = "../../tests/session/controller.rs"]
mod tests;
