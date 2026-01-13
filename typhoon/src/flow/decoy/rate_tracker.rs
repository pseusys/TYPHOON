use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use parking_lot::RwLock;

use crate::constants::decoy::{
    TYPHOON_DECOY_CURRENT_ALPHA, TYPHOON_DECOY_CURRENT_BYTE_RATE_DEFAULT,
    TYPHOON_DECOY_CURRENT_PACKET_RATE_DEFAULT, TYPHOON_DECOY_REFERENCE_ALPHA,
    TYPHOON_DECOY_REFERENCE_BURST_FACTOR, TYPHOON_DECOY_REFERENCE_PACKET_RATE_DEFAULT,
};

/// EWMA-based rate tracker for packet and byte rates.
///
/// Tracks both:
/// - Current rate (fast-adapting, alpha = 0.05)
/// - Reference rate (slow-adapting, alpha = 0.001)
///
/// Used for detecting bursts and calculating decoy timing.
#[derive(Debug)]
pub struct RateTracker {
    /// Current packet rate (ms between packets).
    current_packet_rate: AtomicU64,
    /// Reference packet rate (ms between packets).
    reference_packet_rate: AtomicU64,
    /// Current byte rate (bytes per second).
    current_byte_rate: AtomicU64,
    /// Last packet timestamp.
    last_packet_time: RwLock<Option<Instant>>,
    /// Total bytes sent in current window.
    window_bytes: AtomicU64,
    /// Window start time.
    window_start: RwLock<Instant>,
}

impl RateTracker {
    /// Create a new rate tracker with default values.
    pub fn new() -> Self {
        Self {
            current_packet_rate: AtomicU64::new(
                (TYPHOON_DECOY_CURRENT_PACKET_RATE_DEFAULT * 1000.0) as u64,
            ),
            reference_packet_rate: AtomicU64::new(
                (TYPHOON_DECOY_REFERENCE_PACKET_RATE_DEFAULT * 1000.0) as u64,
            ),
            current_byte_rate: AtomicU64::new(TYPHOON_DECOY_CURRENT_BYTE_RATE_DEFAULT as u64),
            last_packet_time: RwLock::new(None),
            window_bytes: AtomicU64::new(0),
            window_start: RwLock::new(Instant::now()),
        }
    }

    /// Record a packet being sent.
    pub fn record_packet(&self, bytes: usize) {
        let now = Instant::now();

        // Update packet rate
        let mut last_time = self.last_packet_time.write();
        if let Some(last) = *last_time {
            let elapsed_us = now.duration_since(last).as_micros() as u64;

            // Update current rate (fast)
            let current = self.current_packet_rate.load(Ordering::Relaxed);
            let new_current = ((1.0 - TYPHOON_DECOY_CURRENT_ALPHA) * (current as f64)
                + TYPHOON_DECOY_CURRENT_ALPHA * (elapsed_us as f64))
                as u64;
            self.current_packet_rate
                .store(new_current, Ordering::Relaxed);

            // Update reference rate (slow)
            let reference = self.reference_packet_rate.load(Ordering::Relaxed);
            let new_reference = ((1.0 - TYPHOON_DECOY_REFERENCE_ALPHA) * (reference as f64)
                + TYPHOON_DECOY_REFERENCE_ALPHA * (elapsed_us as f64))
                as u64;
            self.reference_packet_rate
                .store(new_reference, Ordering::Relaxed);
        }
        *last_time = Some(now);

        // Update byte rate
        self.window_bytes
            .fetch_add(bytes as u64, Ordering::Relaxed);

        // Check if window should be reset (every second)
        let window_start = *self.window_start.read();
        if now.duration_since(window_start) >= Duration::from_secs(1) {
            let bytes_in_window = self.window_bytes.swap(0, Ordering::Relaxed);
            let current_byte_rate = self.current_byte_rate.load(Ordering::Relaxed);
            let new_byte_rate = ((1.0 - TYPHOON_DECOY_CURRENT_ALPHA) * (current_byte_rate as f64)
                + TYPHOON_DECOY_CURRENT_ALPHA * (bytes_in_window as f64))
                as u64;
            self.current_byte_rate
                .store(new_byte_rate, Ordering::Relaxed);
            *self.window_start.write() = now;
        }
    }

    /// Get the current packet rate in microseconds.
    pub fn current_packet_rate_us(&self) -> u64 {
        self.current_packet_rate.load(Ordering::Relaxed)
    }

    /// Get the reference packet rate in microseconds.
    pub fn reference_packet_rate_us(&self) -> u64 {
        self.reference_packet_rate.load(Ordering::Relaxed)
    }

    /// Get the current packet rate in milliseconds.
    pub fn current_packet_rate_ms(&self) -> f64 {
        self.current_packet_rate.load(Ordering::Relaxed) as f64 / 1000.0
    }

    /// Get the reference packet rate in milliseconds.
    pub fn reference_packet_rate_ms(&self) -> f64 {
        self.reference_packet_rate.load(Ordering::Relaxed) as f64 / 1000.0
    }

    /// Get the current byte rate (bytes per second).
    pub fn current_byte_rate(&self) -> u64 {
        self.current_byte_rate.load(Ordering::Relaxed)
    }

    /// Check if currently in a burst (current rate significantly faster than reference).
    pub fn is_burst(&self) -> bool {
        let current = self.current_packet_rate.load(Ordering::Relaxed);
        let reference = self.reference_packet_rate.load(Ordering::Relaxed);

        // Burst = current rate is much faster (smaller interval) than reference
        (current as f64) < (reference as f64) / TYPHOON_DECOY_REFERENCE_BURST_FACTOR
    }

    /// Get time since last packet in milliseconds.
    pub fn time_since_last_packet_ms(&self) -> Option<u64> {
        let last_time = self.last_packet_time.read();
        last_time.map(|t| Instant::now().duration_since(t).as_millis() as u64)
    }

    /// Reset the tracker to initial state.
    pub fn reset(&self) {
        self.current_packet_rate.store(
            (TYPHOON_DECOY_CURRENT_PACKET_RATE_DEFAULT * 1000.0) as u64,
            Ordering::Relaxed,
        );
        self.reference_packet_rate.store(
            (TYPHOON_DECOY_REFERENCE_PACKET_RATE_DEFAULT * 1000.0) as u64,
            Ordering::Relaxed,
        );
        self.current_byte_rate
            .store(TYPHOON_DECOY_CURRENT_BYTE_RATE_DEFAULT as u64, Ordering::Relaxed);
        *self.last_packet_time.write() = None;
        self.window_bytes.store(0, Ordering::Relaxed);
        *self.window_start.write() = Instant::now();
    }
}

impl Default for RateTracker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
#[path = "../../../tests/flow/decoy/rate_tracker.rs"]
mod tests;
