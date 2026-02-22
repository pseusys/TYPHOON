#[cfg(test)]
#[path = "../../../tests/flow/decoy.rs"]
mod tests;

/// Shared state and utilities for decoy traffic communication modes.
use std::marker::PhantomData;
use std::sync::{Arc, Weak};

use rand::Rng;
use rand_distr::{Distribution, Exp, Normal};

use crate::bytes::{ByteBuffer, ByteBufferMut, DynamicByteBuffer};
use crate::flow::common::FlowManager;
use crate::settings::Settings;
use crate::settings::consts::TAILOR_LENGTH;
use crate::settings::keys::*;
use crate::tailor::{IdentityType, Tailor};
use crate::utils::random::get_rng;
use crate::utils::sync::AsyncExecutor;
use crate::utils::time::unix_timestamp_ms;

/// Trait for implementing decoy traffic communication modes.
pub trait DecoyCommunicationMode<AE: AsyncExecutor>: Sized + Send + Sync {
    type FlowManagerT: FlowManager;

    /// Create a new decoy provider with the given manager, settings, and tailor size.
    fn new(manager: Weak<Self::FlowManagerT>, settings: Arc<Settings<AE>>) -> Self;

    /// Start the background decoy generation timer.
    fn start(&mut self) -> impl Future<Output = ()> + Send;

    /// Process an incoming packet through the decoy provider, updating internal rate tracking.
    fn feed_input(&mut self, packet: DynamicByteBuffer) -> impl Future<Output = Option<DynamicByteBuffer>> + Send;

    /// Process an outgoing packet through the decoy provider, updating internal rate tracking.
    fn feed_output(&mut self, packet: DynamicByteBuffer, generated: bool) -> impl Future<Output = Option<DynamicByteBuffer>> + Send;
}

/// Internal state for tracking packet rates and byte budgets.
/// This state is shared by all communication modes.
pub(super) struct DecoyState<T: IdentityType, AE: AsyncExecutor> {
    pub(super) settings: Arc<Settings<AE>>,
    /// Long-term reference transmission rate in packets (milliseconds between packets).
    pub(super) reference_rate: f64,
    /// Current transmission rate in packets (milliseconds between packets).
    pub(super) packet_rate: f64,
    /// Current transmission rate in bytes.
    pub(super) byte_rate: f64,
    /// Number of decoy packet bytes allowed to send now.
    pub(super) byte_budget: f64,
    /// Timestamp of the previous packet.
    previous_packet_time: Option<u128>,
    /// Maximum allowed length of decoy packets.
    pub(super) packet_length_cap: usize,
    /// Incremental packet number counter.
    packet_number: u64,
    /// Identity bytes for decoy packets (16 bytes of zeros).
    identity: Vec<u8>,
    /// Next scheduled decoy time (milliseconds since epoch).
    pub(super) next_decoy_time: u128,
    /// Pre-computed length for next decoy.
    pub(super) pending_length: usize,
    _phantom: PhantomData<T>,
}

impl<T: IdentityType, AE: AsyncExecutor> DecoyState<T, AE> {
    pub(super) fn new(settings: Arc<Settings<AE>>) -> Self {
        let byte_rate_cap = settings.get(&DECOY_BYTE_RATE_CAP);
        let byte_rate_factor = settings.get(&DECOY_BYTE_RATE_FACTOR);
        let length_max = settings.get(&DECOY_LENGTH_MAX) as usize;
        let length_min = settings.get(&DECOY_LENGTH_MIN) as usize;

        let now = unix_timestamp_ms();

        Self {
            settings: settings.clone(),
            reference_rate: settings.get(&DECOY_REFERENCE_PACKET_RATE_DEFAULT),
            packet_rate: settings.get(&DECOY_CURRENT_PACKET_RATE_DEFAULT),
            byte_rate: settings.get(&DECOY_CURRENT_BYTE_RATE_DEFAULT),
            byte_budget: byte_rate_cap * byte_rate_factor / 2.0,
            previous_packet_time: None,
            packet_length_cap: length_max.max(length_min),
            packet_number: 0,
            identity: vec![0u8; 16],
            next_decoy_time: now,
            pending_length: length_min,
            _phantom: PhantomData,
        }
    }

    /// Update internal state when a packet passes through.
    pub(super) fn update(&mut self, packet_length: usize) {
        let current_time = unix_timestamp_ms();

        if let Some(prev_time) = self.previous_packet_time {
            let time_delta = (current_time - prev_time) as f64;

            let reference_alpha = self.settings.get(&DECOY_REFERENCE_ALPHA);
            let current_alpha = self.settings.get(&DECOY_CURRENT_ALPHA);
            let byte_rate_cap = self.settings.get(&DECOY_BYTE_RATE_CAP);
            let byte_rate_factor = self.settings.get(&DECOY_BYTE_RATE_FACTOR);

            self.reference_rate = (1.0 - reference_alpha) * self.reference_rate + reference_alpha * time_delta;
            self.packet_rate = (1.0 - current_alpha) * self.packet_rate + current_alpha * time_delta;
            self.byte_rate = (1.0 - current_alpha) * self.byte_rate + current_alpha * (packet_length as f64);
            self.byte_budget = (self.byte_budget + time_delta * byte_rate_cap / 1000.0).min(byte_rate_cap * byte_rate_factor);
        }

        self.previous_packet_time = Some(current_time);
    }

    /// Get quietness index: how quiet the traffic is (0 = busy, 1 = quiet).
    pub(super) fn quietness_index(&self) -> f64 {
        ((self.reference_rate - self.packet_rate) / self.reference_rate).clamp(0.0, 1.0)
    }

    /// Get next packet number and increment counter.
    fn next_packet_number(&mut self) -> u64 {
        self.packet_number += 1;
        let timestamp = (unix_timestamp_ms() / 1000) as u32;
        ((timestamp as u64) << 32) | (self.packet_number as u64)
    }

    /// Create a decoy packet with the given body length.
    pub(super) fn create_decoy_packet(&mut self, body_length: usize) -> DynamicByteBuffer {
        let total_length = body_length + TAILOR_LENGTH + T::length();
        let packet = self.settings.pool().allocate(Some(total_length));

        get_rng().fill(packet.slice_end_mut(body_length));

        let identity_buffer = self.settings.pool().allocate_precise_from_slice_with_capacity(&self.identity, 0, 0);
        let tailor = Tailor::decoy(T::from_bytes(identity_buffer.slice()), self.next_packet_number());
        let tailor_buffer = self.settings.pool().allocate(Some(T::length() + TAILOR_LENGTH));
        let tailor_data = tailor.to_buffer(tailor_buffer);
        packet.slice_start_mut(body_length).copy_from_slice(tailor_data.slice());

        packet
    }

    /// Schedule the next decoy packet.
    pub(super) fn schedule_next(&mut self, delay: u64, length: usize) {
        self.next_decoy_time = unix_timestamp_ms() + delay as u128;
        self.pending_length = length;
    }
}

/// Random uniform distribution between min and max.
#[inline]
pub(super) fn random_uniform(min: f64, max: f64) -> f64 {
    get_rng().gen_range(min..=max)
}

/// Gaussian random with mean and standard deviation.
#[inline]
pub(super) fn random_gauss(mean: f64, sigma: f64) -> f64 {
    if sigma <= 0.0 {
        return mean;
    }
    let normal = Normal::new(mean, sigma).unwrap_or_else(|_| Normal::new(mean, 1.0).unwrap());
    normal.sample(&mut get_rng())
}

/// Exponential random with rate (mean = 1/rate).
#[inline]
pub(super) fn exponential_variance(rate: f64) -> f64 {
    if rate <= 0.0 {
        return f64::MAX;
    }
    let exp = Exp::new(rate).unwrap_or_else(|_| Exp::new(1.0).unwrap());
    exp.sample(&mut get_rng())
}
