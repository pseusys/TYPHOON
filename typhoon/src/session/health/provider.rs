use std::sync::Arc;

use tokio::sync::mpsc;

use crate::error::TyphoonResult;
use crate::session::health::decay::{DecayCycle, DecayState, ShadowrideRequest};
use crate::session::health::rtt::RttTracker;

/// Health check provider for session management.
///
/// Integrates RTT tracking and decay cycle management to provide
/// health check functionality for TYPHOON sessions.
pub struct HealthCheckProvider {
    /// RTT tracker for adaptive timing.
    rtt_tracker: Arc<RttTracker>,
    /// Decay cycle manager.
    decay_cycle: Arc<DecayCycle>,
    /// Sender for shadowride completion.
    shadowride_done_tx: mpsc::Sender<()>,
    /// Receiver for shadowride requests.
    shadowride_req_rx: Option<mpsc::Receiver<ShadowrideRequest>>,
}

impl HealthCheckProvider {
    /// Create a new health check provider.
    pub fn new() -> Self {
        let rtt_tracker = Arc::new(RttTracker::new());
        let (decay_cycle, shadowride_done_tx, shadowride_req_rx) =
            DecayCycle::new(Arc::clone(&rtt_tracker));

        Self {
            rtt_tracker,
            decay_cycle: Arc::new(decay_cycle),
            shadowride_done_tx,
            shadowride_req_rx: Some(shadowride_req_rx),
        }
    }

    /// Get a reference to the RTT tracker.
    pub fn rtt_tracker(&self) -> &Arc<RttTracker> {
        &self.rtt_tracker
    }

    /// Get a reference to the decay cycle.
    pub fn decay_cycle(&self) -> &Arc<DecayCycle> {
        &self.decay_cycle
    }

    /// Take the shadowride request receiver.
    ///
    /// This can only be called once; subsequent calls return None.
    pub fn take_shadowride_receiver(&mut self) -> Option<mpsc::Receiver<ShadowrideRequest>> {
        self.shadowride_req_rx.take()
    }

    /// Check if a health check response is needed.
    pub fn should_send_response(&self) -> bool {
        matches!(
            self.decay_cycle.state(),
            DecayState::Idle | DecayState::WaitingForShadowride
        )
    }

    /// Get the current RTT estimate in milliseconds.
    pub fn get_rtt(&self) -> u32 {
        self.rtt_tracker.get_rtt()
    }

    /// Get the current timeout value in milliseconds.
    pub fn get_timeout(&self) -> u32 {
        self.rtt_tracker.get_timeout()
    }

    /// Get the current retry count.
    pub fn retry_count(&self) -> u32 {
        self.decay_cycle.retry_count()
    }

    /// Check if the health check system is active.
    pub fn is_active(&self) -> bool {
        self.decay_cycle.is_active()
    }

    /// Check if the health check system has failed.
    pub fn is_failed(&self) -> bool {
        self.decay_cycle.is_failed()
    }

    /// Mark the handshake as complete.
    pub fn handshake_complete(&self) {
        self.decay_cycle.handshake_complete();
    }

    /// Process a received health check packet.
    ///
    /// Returns true if the packet was valid and processed.
    pub fn process_received(&self, packet_number: u64, next_in: u32) -> bool {
        self.decay_cycle.process_health_check(packet_number, next_in)
    }

    /// Notify that a shadowride was completed successfully.
    pub async fn notify_shadowride_complete(&self) -> TyphoonResult<()> {
        self.shadowride_done_tx
            .send(())
            .await
            .map_err(|_| crate::error::TyphoonError::ChannelError("Shadowride channel closed".into()))
    }

    /// Generate a next_in value for outgoing health check.
    pub fn generate_next_in() -> u32 {
        DecayCycle::generate_next_in()
    }

    /// Terminate the health check system.
    pub fn terminate(&self) {
        self.decay_cycle.terminate();
    }
}

impl Default for HealthCheckProvider {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
#[path = "../../../tests/session/health/provider.rs"]
mod tests;
