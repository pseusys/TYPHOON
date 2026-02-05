use std::time::Duration;

use log::{debug, warn};
use rand::Rng;

use crate::constants::{keys, Settings};
use crate::session::common::{SessionCommand, SessionHandle, SessionOutput, SessionReturn};
use crate::utils::random::get_rng;
use crate::utils::sync::sleep;
use crate::utils::time::unix_timestamp_ms;

/// Trait for health check modes.
/// Implementations run their own event loop and communicate with the session controller via channels.
pub trait HealthCheckMode: Sized + Send + 'static {
    /// Create a new health check mode instance.
    /// - `handle`: The session handle for communicating with the session controller.
    fn new(handle: SessionHandle) -> Self;

    /// Run the health check event loop. This should be spawned as a separate task.
    fn run(self) -> impl std::future::Future<Output = ()> + Send;
}

/// Mutable state for the decay cycle, owned entirely by the event loop.
struct DecayCycleState {
    prev_packet_number: Option<u64>,
    prev_next_in: u32,
    prev_sent: u128,
    srtt: Option<f64>,
    rttvar: Option<f64>,
    incremental: u32,
}

/// Decay cycle implementation of HealthCheckMode.
/// Implements the TYPHOON health check protocol with RTT estimation and shadowride optimization.
pub struct DecayCycle {
    handle: SessionHandle,
    settings: Settings,
    state: DecayCycleState,
}

impl DecayCycle {
    fn generate_next_in(&self, multiplier: f32) -> u32 {
        let min_val = self.settings.get(&keys::HEALTH_CHECK_NEXT_IN_MIN) as f32;
        let max_val = self.settings.get(&keys::HEALTH_CHECK_NEXT_IN_MAX) as f32;
        (get_rng().gen_range(min_val..=max_val) * multiplier) as u32
    }

    fn rtt(&self) -> u32 {
        let rtt_min = self.settings.get(&keys::RTT_MIN) as f64;
        let rtt_max = self.settings.get(&keys::RTT_MAX) as f64;
        let rtt_default = self.settings.get(&keys::RTT_DEFAULT) as f64;
        self.state.srtt.unwrap_or(rtt_default).clamp(rtt_min, rtt_max) as u32
    }

    fn timeout(&self) -> u32 {
        let timeout_min = self.settings.get(&keys::TIMEOUT_MIN) as f64;
        let timeout_max = self.settings.get(&keys::TIMEOUT_MAX) as f64;
        let timeout_default = self.settings.get(&keys::TIMEOUT_DEFAULT) as f64;
        let timeout_rtt_factor = self.settings.get(&keys::TIMEOUT_RTT_FACTOR);
        let raw = match self.state.srtt {
            Some(srtt) => srtt + timeout_rtt_factor * self.state.rttvar.unwrap_or(0.0),
            None => timeout_default,
        };
        raw.clamp(timeout_min, timeout_max) as u32
    }

    fn update_rtt(&mut self) {
        let now = unix_timestamp_ms();
        let packet_rtt = (now.saturating_sub(self.state.prev_sent).saturating_sub(self.state.prev_next_in as u128)) as f64;
        let alpha = self.settings.get(&keys::RTT_ALPHA);
        let beta = self.settings.get(&keys::RTT_BETA);
        match self.state.srtt {
            None => {
                self.state.srtt = Some(packet_rtt);
                self.state.rttvar = Some(packet_rtt / 2.0);
            }
            Some(old_srtt) => {
                let old_rttvar = self.state.rttvar.unwrap_or(0.0);
                self.state.rttvar = Some((1.0 - beta) * old_rttvar + beta * (old_srtt - packet_rtt).abs());
                self.state.srtt = Some((1.0 - alpha) * old_srtt + alpha * packet_rtt);
            }
        }
    }

    fn make_packet_number(&mut self) -> u64 {
        self.state.incremental += 1;
        let timestamp = (unix_timestamp_ms() / 1000) as u32;
        ((timestamp as u64) << 32) | (self.state.incremental as u64)
    }
}

impl HealthCheckMode for DecayCycle {
    fn new(handle: SessionHandle) -> Self {
        let settings = Settings::default();
        let initial_next_in = {
            let min_val = settings.get(&keys::HEALTH_CHECK_NEXT_IN_MIN) as f32;
            let max_val = settings.get(&keys::HEALTH_CHECK_NEXT_IN_MAX) as f32;
            get_rng().gen_range(min_val..=max_val) as u32
        };

        DecayCycle {
            handle,
            settings,
            state: DecayCycleState {
                prev_packet_number: None,
                prev_next_in: initial_next_in,
                prev_sent: unix_timestamp_ms(),
                srtt: None,
                rttvar: None,
                incremental: 0,
            },
        }
    }

    async fn run(mut self) {
        let max_retries = self.settings.get(&keys::MAX_RETRIES);
        let mut retries: u64 = 0;

        loop {
            // 1. Sleep phase: wait for max(prev_next_in - rtt, 0) ms.
            let sleep_duration = self.state.prev_next_in.saturating_sub(self.rtt());
            debug!("decay: sleeping for {} ms before shadowride window", sleep_duration);
            sleep(Duration::from_millis(sleep_duration as u64)).await;

            // 2. Prepare health check parameters.
            let packet_number = self.make_packet_number();
            let next_in = self.generate_next_in(1.0);
            self.state.prev_packet_number = Some(packet_number);
            self.state.prev_next_in = next_in;
            self.state.prev_sent = unix_timestamp_ms();

            // 3. Begin shadowride window (fire-and-forget).
            let cmd = SessionCommand::BeginShadowride { packet_number, next_in };
            if !self.handle.send_nowait(cmd) {
                debug!("decay: session channel closed, exiting");
                break;
            }

            let shadowride_window = (self.rtt() * 2) as u64;
            debug!("decay: shadowride window open for {} ms", shadowride_window);
            sleep(Duration::from_millis(shadowride_window)).await;

            // 4. Check if shadowride happened; if not, send standalone health check.
            let shadowrided = match self.handle.send(SessionCommand::EndShadowride).await {
                Some(SessionReturn::EndShadowrideResult(consumed)) => consumed,
                _ => {
                    debug!("decay: session channel closed, exiting");
                    break;
                }
            };

            if shadowrided {
                debug!("decay: shadowride was consumed by a data packet");
            } else {
                debug!("decay: shadowride not consumed, sending standalone health check");
                let cmd = SessionCommand::SendHealthCheck { packet_number, next_in };
                match self.handle.send(cmd).await {
                    Some(SessionReturn::SendHealthCheckResult(true)) => {}
                    _ => {
                        debug!("decay: failed to send health check, session may be closed");
                        break;
                    }
                }
            }

            // 5. Wait for response: prev_next_in + timeout ms.
            let wait_duration = self.state.prev_next_in as u64 + self.timeout() as u64;
            debug!("decay: waiting {} ms for health check response", wait_duration);

            // Use a timeout on the event receiver
            let response = tokio::time::timeout(
                Duration::from_millis(wait_duration),
                self.handle.recv(),
            ).await;

            match response {
                Ok(Some(SessionOutput::HealthResponse { packet_number: resp_pn, next_in: resp_next_in })) => {
                    // Validate packet number matches what we sent.
                    if self.state.prev_packet_number != Some(resp_pn) {
                        debug!("decay: received response with unexpected packet number, discarding");
                        continue;
                    }
                    // 6. Update RTT and use server's next_in.
                    self.update_rtt();
                    self.state.prev_next_in = resp_next_in;
                    self.state.prev_packet_number = None;
                    retries = 0;
                    debug!("decay: valid response received, next_in = {} ms", resp_next_in);
                }
                Ok(Some(SessionOutput::Terminated)) | Ok(None) => {
                    debug!("decay: session terminated, exiting");
                    break;
                }
                Ok(Some(SessionOutput::Data(_))) => {
                    // Ignore user data on health channel (shouldn't happen)
                    debug!("decay: unexpected data on health channel, ignoring");
                }
                Err(_) => {
                    // Timeout
                    retries += 1;
                    warn!("decay: timeout, retry {}/{}", retries, max_retries);
                    if retries >= max_retries {
                        // All retries exhausted - session is considered decayed.
                        // The session controller will handle cleanup when it detects
                        // that the health check task has exited.
                        warn!("decay: max retries exceeded, session decayed");
                        break;
                    }
                }
            }
        }
    }
}
