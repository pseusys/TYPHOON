use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use crate::constants::timing::{
    TYPHOON_RTT_ALPHA, TYPHOON_RTT_BETA, TYPHOON_RTT_DEFAULT, TYPHOON_RTT_MAX, TYPHOON_RTT_MIN,
    TYPHOON_TIMEOUT_DEFAULT, TYPHOON_TIMEOUT_MAX, TYPHOON_TIMEOUT_MIN, TYPHOON_TIMEOUT_RTT_FACTOR,
};

/// EWMA-based RTT tracker for adaptive timeout calculation.
///
/// Uses the algorithm described in RFC 6298 (Karn/Partridge algorithm)
/// with configurable alpha and beta parameters.
///
/// Thread-safe through atomic operations.
#[derive(Debug)]
pub struct RttTracker {
    /// Smoothed RTT in milliseconds.
    smooth_rtt: AtomicU32,
    /// RTT variance in milliseconds.
    rtt_variance: AtomicU32,
    /// Whether RTT has been initialized with at least one sample.
    initialized: AtomicBool,
}

impl RttTracker {
    /// Create a new uninitialized RTT tracker.
    pub fn new() -> Self {
        Self {
            smooth_rtt: AtomicU32::new(0),
            rtt_variance: AtomicU32::new(0),
            initialized: AtomicBool::new(false),
        }
    }

    /// Check if the tracker has been initialized with at least one sample.
    #[inline]
    pub fn is_initialized(&self) -> bool {
        self.initialized.load(Ordering::Acquire)
    }

    /// Update RTT with a new sample.
    ///
    /// The sample should be the measured round-trip time in milliseconds,
    /// with the next_in delay already subtracted:
    /// `packet_RTT = receive_time - send_time - next_in`
    pub fn update(&self, packet_rtt: u32) {
        // Clamp input to valid range
        let packet_rtt = packet_rtt.clamp(TYPHOON_RTT_MIN, TYPHOON_RTT_MAX);

        if !self.initialized.swap(true, Ordering::AcqRel) {
            // First measurement: initialize directly
            self.smooth_rtt.store(packet_rtt, Ordering::Release);
            self.rtt_variance.store(packet_rtt / 2, Ordering::Release);
        } else {
            // Subsequent measurements: apply EWMA
            let srtt = self.smooth_rtt.load(Ordering::Acquire);
            let rttvar = self.rtt_variance.load(Ordering::Acquire);

            // RTT_variance = (1 - beta) * RTT_variance + beta * |smooth_RTT - packet_RTT|
            let diff = if srtt > packet_rtt {
                srtt - packet_rtt
            } else {
                packet_rtt - srtt
            };
            let new_rttvar =
                ((1.0 - TYPHOON_RTT_BETA) * (rttvar as f64) + TYPHOON_RTT_BETA * (diff as f64))
                    as u32;

            // smooth_RTT = (1 - alpha) * smooth_RTT + alpha * packet_RTT
            let new_srtt =
                ((1.0 - TYPHOON_RTT_ALPHA) * (srtt as f64) + TYPHOON_RTT_ALPHA * (packet_rtt as f64))
                    as u32;

            // Clamp to valid ranges (variance can be smaller than RTT_MIN)
            self.rtt_variance.store(
                new_rttvar.min(TYPHOON_RTT_MAX),
                Ordering::Release,
            );
            self.smooth_rtt.store(
                new_srtt.clamp(TYPHOON_RTT_MIN, TYPHOON_RTT_MAX),
                Ordering::Release,
            );
        }
    }

    /// Get the current smoothed RTT estimate in milliseconds.
    ///
    /// Returns the default RTT if not initialized.
    pub fn get_rtt(&self) -> u32 {
        if self.initialized.load(Ordering::Acquire) {
            self.smooth_rtt.load(Ordering::Acquire)
        } else {
            TYPHOON_RTT_DEFAULT
        }
    }

    /// Get the current RTT variance in milliseconds.
    ///
    /// Returns half the default RTT if not initialized.
    pub fn get_variance(&self) -> u32 {
        if self.initialized.load(Ordering::Acquire) {
            self.rtt_variance.load(Ordering::Acquire)
        } else {
            TYPHOON_RTT_DEFAULT / 2
        }
    }

    /// Calculate the timeout value based on current RTT estimates.
    ///
    /// Timeout = (smooth_RTT + RTT_variance) * TYPHOON_TIMEOUT_RTT_FACTOR
    ///
    /// Returns the default timeout if not initialized.
    pub fn get_timeout(&self) -> u32 {
        if self.initialized.load(Ordering::Acquire) {
            let srtt = self.smooth_rtt.load(Ordering::Acquire);
            let rttvar = self.rtt_variance.load(Ordering::Acquire);
            let timeout = ((srtt as f64 + rttvar as f64) * TYPHOON_TIMEOUT_RTT_FACTOR) as u32;
            timeout.clamp(TYPHOON_TIMEOUT_MIN, TYPHOON_TIMEOUT_MAX)
        } else {
            TYPHOON_TIMEOUT_DEFAULT
        }
    }

    /// Reset the tracker to uninitialized state.
    pub fn reset(&self) {
        self.initialized.store(false, Ordering::Release);
        self.smooth_rtt.store(0, Ordering::Release);
        self.rtt_variance.store(0, Ordering::Release);
    }
}

impl Default for RttTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl Clone for RttTracker {
    fn clone(&self) -> Self {
        Self {
            smooth_rtt: AtomicU32::new(self.smooth_rtt.load(Ordering::Acquire)),
            rtt_variance: AtomicU32::new(self.rtt_variance.load(Ordering::Acquire)),
            initialized: AtomicBool::new(self.initialized.load(Ordering::Acquire)),
        }
    }
}

#[cfg(test)]
#[path = "../../../tests/session/health/rtt.rs"]
mod tests;
