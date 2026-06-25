//! EWMA round-trip-time estimator shared by the client- and server-side health check providers.

#[cfg(test)]
#[path = "../../tests/session/rtt.rs"]
mod tests;

use crate::settings::Settings;
use crate::settings::keys::{RTT_ALPHA, RTT_BETA, RTT_DEFAULT, RTT_MAX, RTT_MIN, TIMEOUT_DEFAULT, TIMEOUT_MAX, TIMEOUT_MIN, TIMEOUT_RTT_FACTOR};
use crate::utils::sync::AsyncExecutor;

/// Smoothed round-trip-time estimate, used to size the health-check timeout and the shadowride window.
pub(crate) struct RttEstimator {
    smooth_rtt: Option<f64>,
    rtt_variance: Option<f64>,
}

impl RttEstimator {
    /// Create an estimator with no measurement yet.
    pub(crate) fn new() -> Self {
        Self {
            smooth_rtt: None,
            rtt_variance: None,
        }
    }

    /// Update the estimate from a freshly observed round trip: `receive_time` minus `sent_time` minus the intentional `sent_next_in` delay the other side was asked to wait.
    pub(crate) fn update<AE: AsyncExecutor>(&mut self, settings: &Settings<AE>, receive_time: u128, sent_time: u128, sent_next_in: u32) {
        let packet_rtt = (receive_time as f64) - (sent_time as f64) - (sent_next_in as f64);
        let rtt_min = settings.get(&RTT_MIN) as f64;
        let rtt_max = settings.get(&RTT_MAX) as f64;
        let packet_rtt = packet_rtt.clamp(rtt_min, rtt_max);

        match self.smooth_rtt {
            None => {
                self.smooth_rtt = Some(packet_rtt);
                self.rtt_variance = Some(packet_rtt / 2.0);
            }
            Some(srtt) => {
                let alpha = settings.get(&RTT_ALPHA);
                let beta = settings.get(&RTT_BETA);
                let new_srtt = (1.0 - alpha) * srtt + alpha * packet_rtt;
                let new_rttvar = (1.0 - beta) * self.rtt_variance.unwrap() + beta * (new_srtt - packet_rtt).abs();
                self.smooth_rtt = Some(new_srtt.clamp(rtt_min, rtt_max));
                self.rtt_variance = Some(new_rttvar);
            }
        }
    }

    /// Smoothed RTT, or `TYPHOON_RTT_DEFAULT` if no measurement exists yet.
    pub(crate) fn smooth_or_default<AE: AsyncExecutor>(&self, settings: &Settings<AE>) -> f64 {
        self.smooth_rtt.unwrap_or(settings.get(&RTT_DEFAULT) as f64)
    }

    /// Timeout derived from the current RTT estimate, or `TYPHOON_TIMEOUT_DEFAULT` if no measurement exists yet, clamped to `[TYPHOON_TIMEOUT_MIN, TYPHOON_TIMEOUT_MAX]`.
    pub(crate) fn compute_timeout<AE: AsyncExecutor>(&self, settings: &Settings<AE>) -> u64 {
        let timeout_min = settings.get(&TIMEOUT_MIN);
        let timeout_max = settings.get(&TIMEOUT_MAX);

        match (self.smooth_rtt, self.rtt_variance) {
            (Some(srtt), Some(rttvar)) => {
                let factor = settings.get(&TIMEOUT_RTT_FACTOR);
                ((srtt + rttvar) * factor) as u64
            }
            _ => settings.get(&TIMEOUT_DEFAULT),
        }
        .clamp(timeout_min, timeout_max)
    }
}
