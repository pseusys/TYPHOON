use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::RwLock;
use tokio::sync::mpsc;
use tokio::time::timeout;

use crate::constants::timing::{
    TYPHOON_HEALTH_CHECK_NEXT_IN_MAX, TYPHOON_HEALTH_CHECK_NEXT_IN_MIN, TYPHOON_MAX_RETRIES,
};
use crate::error::{TyphoonError, TyphoonResult};
use crate::random::get_rng;
use crate::session::health::rtt::RttTracker;

/// State of the decay cycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecayState {
    /// Waiting for initial handshake to complete.
    Handshaking,
    /// Normal idle state - waiting for next health check.
    Idle,
    /// Attempting to shadowride a health check onto a data packet.
    WaitingForShadowride,
    /// Waiting for a health check response from the peer.
    WaitingForResponse,
    /// Connection has failed due to timeout or max retries.
    Failed,
    /// Connection has been terminated gracefully.
    Terminated,
}

/// Request to embed a health check in the next data packet (shadowride).
#[derive(Debug)]
pub struct ShadowrideRequest {
    /// The packet number to use for the health check.
    pub packet_number: u64,
    /// The next_in value to send.
    pub next_in: u32,
}

/// Decay cycle manager for health check protocol.
///
/// Manages the decay cycle state machine as specified in the README:
/// - Client initiates health check exchanges
/// - Server responds after next_in delay
/// - Both sides track RTT and timeout
/// - Connection fails after max retries
pub struct DecayCycle {
    /// Current state of the decay cycle.
    state: RwLock<DecayState>,
    /// Number of consecutive retry attempts.
    retry_count: AtomicU32,
    /// RTT tracker for adaptive timeout.
    rtt_tracker: Arc<RttTracker>,
    /// Expected packet number for current health check.
    expected_pn: AtomicU64,
    /// Timestamp when current health check was sent.
    sent_at: RwLock<Option<Instant>>,
    /// Next-in value from the last received packet.
    last_next_in: AtomicU32,
    /// Channel to request shadowriding.
    shadowride_tx: mpsc::Sender<ShadowrideRequest>,
    /// Channel to receive shadowride completion notification.
    shadowride_rx: RwLock<mpsc::Receiver<()>>,
}

impl DecayCycle {
    /// Create a new decay cycle manager.
    ///
    /// Returns the manager and a sender for shadowride completion notifications.
    pub fn new(rtt_tracker: Arc<RttTracker>) -> (Self, mpsc::Sender<()>, mpsc::Receiver<ShadowrideRequest>) {
        let (shadowride_tx, shadowride_req_rx) = mpsc::channel(1);
        let (shadowride_done_tx, shadowride_done_rx) = mpsc::channel(1);

        let cycle = Self {
            state: RwLock::new(DecayState::Handshaking),
            retry_count: AtomicU32::new(0),
            rtt_tracker,
            expected_pn: AtomicU64::new(0),
            sent_at: RwLock::new(None),
            last_next_in: AtomicU32::new(TYPHOON_HEALTH_CHECK_NEXT_IN_MIN),
            shadowride_tx,
            shadowride_rx: RwLock::new(shadowride_done_rx),
        };

        (cycle, shadowride_done_tx, shadowride_req_rx)
    }

    /// Get the current decay state.
    pub fn state(&self) -> DecayState {
        *self.state.read()
    }

    /// Get the current retry count.
    pub fn retry_count(&self) -> u32 {
        self.retry_count.load(Ordering::Acquire)
    }

    /// Check if the decay cycle has failed.
    pub fn is_failed(&self) -> bool {
        matches!(self.state(), DecayState::Failed)
    }

    /// Check if the decay cycle is active (not failed or terminated).
    pub fn is_active(&self) -> bool {
        !matches!(self.state(), DecayState::Failed | DecayState::Terminated)
    }

    /// Generate a random next_in value within allowed bounds.
    pub fn generate_next_in() -> u32 {
        use rand::Rng;
        get_rng().gen_range(TYPHOON_HEALTH_CHECK_NEXT_IN_MIN..=TYPHOON_HEALTH_CHECK_NEXT_IN_MAX)
    }

    /// Clamp a next_in value to allowed bounds (for safety on received values).
    pub fn clamp_next_in(next_in: u32) -> u32 {
        next_in.clamp(TYPHOON_HEALTH_CHECK_NEXT_IN_MIN, TYPHOON_HEALTH_CHECK_NEXT_IN_MAX)
    }

    /// Mark handshake as complete and transition to idle state.
    pub fn handshake_complete(&self) {
        let mut state = self.state.write();
        if *state == DecayState::Handshaking {
            *state = DecayState::Idle;
            self.retry_count.store(0, Ordering::Release);
        }
    }

    /// Process a received health check packet.
    ///
    /// Returns true if the packet was valid and processed.
    pub fn process_health_check(&self, packet_number: u64, next_in: u32) -> bool {
        let expected = self.expected_pn.load(Ordering::Acquire);

        // Check if this is the expected response
        if packet_number != expected && expected != 0 {
            return false;
        }

        // Calculate RTT if we were waiting for a response
        if let Some(sent_at) = *self.sent_at.read() {
            let last_next_in = self.last_next_in.load(Ordering::Acquire);
            let elapsed_ms = sent_at.elapsed().as_millis() as u32;
            // Subtract last_next_in to get actual network RTT
            let rtt = elapsed_ms.saturating_sub(last_next_in);
            self.rtt_tracker.update(rtt);
        }

        // Update state
        self.last_next_in.store(Self::clamp_next_in(next_in), Ordering::Release);
        self.retry_count.store(0, Ordering::Release);
        *self.state.write() = DecayState::Idle;
        *self.sent_at.write() = None;

        true
    }

    /// Prepare to send a health check.
    ///
    /// Sets the expected packet number and updates state.
    pub fn prepare_send(&self, packet_number: u64) {
        self.expected_pn.store(packet_number, Ordering::Release);
        *self.sent_at.write() = Some(Instant::now());
        *self.state.write() = DecayState::WaitingForResponse;
    }

    /// Handle a timeout waiting for health check response.
    ///
    /// Returns true if max retries exceeded (connection failed).
    pub fn handle_timeout(&self) -> bool {
        let retries = self.retry_count.fetch_add(1, Ordering::AcqRel) + 1;

        if retries >= TYPHOON_MAX_RETRIES {
            *self.state.write() = DecayState::Failed;
            true
        } else {
            // Reset to idle for retry
            *self.state.write() = DecayState::Idle;
            *self.sent_at.write() = None;
            false
        }
    }

    /// Mark the connection as terminated.
    pub fn terminate(&self) {
        *self.state.write() = DecayState::Terminated;
    }

    /// Run the client-side decay cycle loop.
    ///
    /// This manages the health check initiation for clients.
    pub async fn run_client_loop<F, Fut>(&self, mut send_health_check: F) -> TyphoonResult<()>
    where
        F: FnMut(u64, u32) -> Fut,
        Fut: std::future::Future<Output = TyphoonResult<()>>,
    {
        loop {
            let state = self.state();

            match state {
                DecayState::Handshaking => {
                    // Wait for handshake to complete
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
                DecayState::Idle => {
                    // Calculate sleep duration: next_in - RTT (for shadowride window)
                    let next_in = self.last_next_in.load(Ordering::Acquire);
                    let rtt = self.rtt_tracker.get_rtt();
                    let sleep_ms = (next_in as u64).saturating_sub(rtt as u64);

                    tokio::time::sleep(Duration::from_millis(sleep_ms)).await;

                    // Try to shadowride on a data packet
                    let pn = self.generate_packet_number();
                    let next_in = Self::generate_next_in();

                    // Request shadowride
                    let request = ShadowrideRequest {
                        packet_number: pn,
                        next_in,
                    };
                    if self.shadowride_tx.send(request).await.is_ok() {
                        *self.state.write() = DecayState::WaitingForShadowride;

                        // Wait for shadowride or timeout
                        let shadowride_timeout = Duration::from_millis((rtt * 2) as u64);
                        let mut rx = self.shadowride_rx.write();
                        match timeout(shadowride_timeout, rx.recv()).await {
                            Ok(Some(())) => {
                                // Shadowride succeeded
                                self.prepare_send(pn);
                            }
                            _ => {
                                // Shadowride failed, send dedicated health check
                                self.prepare_send(pn);
                                send_health_check(pn, next_in).await?;
                            }
                        }
                    }
                }
                DecayState::WaitingForShadowride => {
                    // Handled in Idle branch
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
                DecayState::WaitingForResponse => {
                    // Wait for response with timeout
                    let timeout_ms = self.rtt_tracker.get_timeout();
                    tokio::time::sleep(Duration::from_millis(timeout_ms as u64)).await;

                    // Check if we got a response (state would change)
                    if self.state() == DecayState::WaitingForResponse {
                        if self.handle_timeout() {
                            return Err(TyphoonError::MaxRetriesExceeded(TYPHOON_MAX_RETRIES));
                        }
                    }
                }
                DecayState::Failed => {
                    return Err(TyphoonError::MaxRetriesExceeded(
                        self.retry_count.load(Ordering::Acquire),
                    ));
                }
                DecayState::Terminated => {
                    return Ok(());
                }
            }
        }
    }

    /// Generate a packet number with current timestamp.
    fn generate_packet_number(&self) -> u64 {
        use std::time::{SystemTime, UNIX_EPOCH};

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as u32)
            .unwrap_or(0);

        let incremental = self.expected_pn.load(Ordering::Acquire) as u32 + 1;
        ((timestamp as u64) << 32) | (incremental as u64)
    }
}

#[cfg(test)]
#[path = "../../../tests/session/health/decay.rs"]
mod tests;
