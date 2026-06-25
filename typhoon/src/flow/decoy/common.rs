//! Core engine shared by every decoy communication mode: the object-safe traits each provider
//! implements, and [`DecoyState`] which tracks packet/byte rates, the byte budget, and packet
//! construction. Maintenance, replication, and subheader feature configuration — randomized
//! once per `DecoyState` and driven by independent background tasks — lives in
//! [`super::features`].

#[cfg(test)]
#[path = "../../../tests/flow/decoy/common.rs"]
mod tests;

use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Weak};

use async_trait::async_trait;
use rand::Rng;
use rand_distr::{Distribution, Exp, Normal};

use super::features::{DecoyFeatureConfig, MaintenanceMode, ReplicationMode, SubheaderMode, maintenance_delay_for, maintenance_length_for};
use crate::bytes::{ByteBuffer, ByteBufferMut, DynamicByteBuffer};
use crate::cache::DerivedValue;
use crate::flow::config::FakeHeaderConfig;
use crate::flow::error::FlowControllerError;
use crate::settings::Settings;
use crate::settings::keys::*;
use crate::tailer::{IdentityType, Tailer};
use crate::utils::random::get_rng;
use crate::utils::sync::AsyncExecutor;
use crate::utils::unix_timestamp_ms;

// ── Trait ────────────────────────────────────────────────────────────────────

/// Object-safe interface used by decoy providers to dispatch generated packets.
/// Implemented explicitly by each flow manager — `ClientFlowManager` forwards to its `FlowManager::send_packet`, `ServerFlowManager` forwards to its inherent `send_packet`.
pub trait DecoyFlowSender: Send + Sync {
    /// Send a generated decoy packet through the flow manager. `fallthrough` skips the tailer step (see `FlowManager::send_packet`).
    fn send_decoy_packet<'a>(&'a self, packet: DynamicByteBuffer, fallthrough: bool, is_maintenance: bool) -> Pin<Box<dyn Future<Output = Result<(), FlowControllerError>> + Send + 'a>>;
}

/// Object-safe runtime interface for decoy traffic. Used as `Arc<dyn DecoyProvider>` in
/// flow managers — no external lock wraps it, so implementations must manage their own
/// mutable state via interior mutability (e.g. `Arc<RwLock<_>>`, as every built-in provider
/// does). All async methods are boxed automatically by `async_trait`.
#[async_trait]
pub trait DecoyProvider: Send + Sync {
    /// Short display name of this provider (e.g. "`SparseDecoyProvider`").
    fn name(&self) -> &'static str;

    /// Start the background decoy generation timer.
    async fn start(&self);

    /// Process an incoming packet, updating internal rate tracking.
    /// `tailer_buf` is the deobfuscated tailer for the packet (flags, packet number, etc.).
    async fn feed_input(&self, packet: DynamicByteBuffer, tailer_buf: DynamicByteBuffer) -> Option<DynamicByteBuffer>;

    /// Process an outgoing packet body and its plaintext tailer, updating internal rate tracking.
    /// Returns the (possibly modified) body, or `None` to suppress the packet entirely.
    async fn feed_output(&self, body: DynamicByteBuffer, tailer_buf: DynamicByteBuffer) -> Option<DynamicByteBuffer>;
}

/// Construction contract for decoy providers. Extends `DecoyProvider` so that any
/// `DecoyCommunicationMode` can be stored as `Box<dyn DecoyProvider>`.
pub trait DecoyCommunicationMode<T: IdentityType + Clone, AE: AsyncExecutor>: DecoyProvider + Sized {
    /// Short name of this provider, derived from the type name (no path, no generics).
    fn name() -> &'static str {
        let full = std::any::type_name::<Self>();
        let without_generics = full.split('<').next().unwrap_or(full);
        without_generics.split("::").last().unwrap_or(without_generics)
    }

    /// Create a new decoy provider; `counter` is the per-session monotonic packet-number
    /// counter shared with the session manager and the health-check provider; every emitted
    /// decoy packet advances it. `fallthrough_probability` pins the per-flow fallthrough rate,
    /// `None` samples from the settings keys.
    fn new(manager: Weak<dyn DecoyFlowSender>, settings: Arc<Settings<AE>>, identity: DerivedValue<T>, counter: Arc<AtomicU32>, fallthrough_probability: Option<f64>) -> Self;
}

// ── DecoyState ──────────────────────────────────────────────────────────────

/// Internal state for tracking packet rates and byte budgets.
/// This state is shared by all communication modes.
pub(crate) struct DecoyState<T: IdentityType + Clone, AE: AsyncExecutor> {
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
    /// Per-session monotonic packet-number counter, shared with the session manager and the
    /// health-check provider. Every emitted decoy advances it.
    counter: Arc<AtomicU32>,
    /// Live source of the current session identity for decoy tailers; re-read on every emitted
    /// decoy so the identity follows session-identity rotation rather than freezing at construction.
    identity: DerivedValue<T>,
    /// Next scheduled decoy time (milliseconds since epoch).
    pub(super) next_decoy_time: u128,
    /// Pre-computed length for next decoy.
    pub(super) pending_length: usize,
    /// Maintenance, replication, and subheader configuration.
    pub(super) features: DecoyFeatureConfig,
    /// Next scheduled maintenance time (milliseconds since epoch).
    pub(super) next_maintenance_time: u128,
    /// Pre-computed length for next maintenance packet.
    pub(super) pending_maintenance_length: usize,
    /// Per-flow probability that a generated decoy packet bypasses the tailer step.
    fallthrough_probability: f64,
}

impl<T: IdentityType + Clone, AE: AsyncExecutor> DecoyState<T, AE> {
    /// Build a fresh decoy state. `counter` is the per-session monotonic PN counter shared
    /// with the session manager and the health-check provider; `fallthrough_probability`
    /// pins the per-flow probability, `None` samples from `DECOY_FALLTHROUGH_PACKETS_{MIN,MAX}`.
    pub(super) fn new(settings: Arc<Settings<AE>>, identity: DerivedValue<T>, counter: Arc<AtomicU32>, fallthrough_probability: Option<f64>) -> Self {
        let byte_rate_cap = settings.get(&DECOY_BYTE_RATE_CAP);
        let byte_rate_factor = settings.get(&DECOY_BYTE_RATE_FACTOR);
        let length_max = settings.get(&DECOY_LENGTH_MAX) as usize;
        let length_min = settings.get(&DECOY_LENGTH_MIN) as usize;

        let now = unix_timestamp_ms();
        let features = DecoyFeatureConfig::random(&settings);

        // Initial maintenance scheduling.
        let (maint_time, maint_len) = if features.maintenance_mode == MaintenanceMode::None {
            (u128::MAX, 0)
        } else {
            let delay = maintenance_delay_for(&features.maintenance_mode, &settings);
            let length = maintenance_length_for(&features.maintenance_mode, &settings);
            (now + delay as u128, length)
        };

        let fallthrough_probability = fallthrough_probability.unwrap_or_else(|| {
            let lo = settings.get(&DECOY_FALLTHROUGH_PACKETS_MIN);
            let hi = settings.get(&DECOY_FALLTHROUGH_PACKETS_MAX);
            if lo >= hi {
                lo
            } else {
                get_rng().gen_range(lo..=hi)
            }
        });

        Self {
            settings: settings.clone(),
            reference_rate: settings.get(&DECOY_REFERENCE_PACKET_RATE_DEFAULT),
            packet_rate: settings.get(&DECOY_CURRENT_PACKET_RATE_DEFAULT),
            byte_rate: settings.get(&DECOY_CURRENT_BYTE_RATE_DEFAULT),
            byte_budget: byte_rate_cap * byte_rate_factor / 2.0,
            previous_packet_time: None,
            packet_length_cap: length_max.max(length_min),
            counter,
            identity,
            next_decoy_time: now,
            pending_length: length_min,
            features,
            next_maintenance_time: maint_time,
            pending_maintenance_length: maint_len,
            fallthrough_probability,
        }
    }

    /// Roll a coin against `fallthrough_probability`; `true` ⇒ next decoy bypasses the tailer.
    #[inline]
    pub(super) fn should_fallthrough(&self) -> bool {
        if self.fallthrough_probability <= 0.0 {
            false
        } else if self.fallthrough_probability >= 1.0 {
            true
        } else {
            get_rng().r#gen::<f64>() < self.fallthrough_probability
        }
    }

    /// Update rate-tracking state when a packet passes through.
    pub(super) fn update(&mut self, packet_length: usize, outgoing_real: bool) {
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
            let refill = time_delta * byte_rate_cap / 1000.0;
            let deduct = if outgoing_real {
                packet_length as f64
            } else {
                0.0
            };
            self.byte_budget = (self.byte_budget + refill - deduct).clamp(0.0, byte_rate_cap * byte_rate_factor);
        }

        self.previous_packet_time = Some(current_time);
    }

    /// Get quietness index: how quiet the traffic is (0 = busy, 1 = quiet).
    pub(super) fn quietness_index(&self) -> f64 {
        ((self.reference_rate - self.packet_rate) / self.reference_rate).clamp(0.0, 1.0)
    }

    /// Bump the per-session counter and return the next packet number
    /// (`counter << 32 | timestamp_seconds`). Decoy emissions share this counter with the
    /// session manager and the health-check provider, so the resulting PN stream is monotonic
    /// across every packet type the session produces. The counter is kept in the dominant half
    /// so raw `PN` ordering is immune to clock adjustments.
    fn next_packet_number(&self) -> u64 {
        let counter = self.counter.fetch_add(1, Ordering::Relaxed).wrapping_add(1);
        let timestamp = (unix_timestamp_ms() / 1000) as u32;
        ((counter as u64) << 32) | timestamp as u64
    }

    /// Create a decoy packet with the given body length.
    /// If `is_maintenance` is true and the subheader mode applies, a subheader is prepended.
    pub(super) fn create_decoy_packet(&mut self, body_length: usize, is_maintenance: bool) -> DynamicByteBuffer {
        let subheader_len = self.subheader_length(is_maintenance);
        let total_length = body_length + Tailer::<T>::len();
        let packet = self.settings.pool().allocate(Some(total_length));

        get_rng().fill(packet.slice_end_mut(body_length));

        let pn = self.next_packet_number();
        Tailer::decoy(packet.rebuffer_start(body_length), &self.identity.get(), pn);

        if subheader_len > 0 {
            let expanded = packet.expand_start(subheader_len);
            if let Some(ref mut config) = self.features.subheader_config {
                config.fill(expanded.rebuffer_end(expanded.len() - subheader_len));
            }
            return expanded;
        }

        packet
    }

    /// Create a replica of the given decoy body (same body bytes, new tailer).
    pub(super) fn create_replica_packet(&mut self, original_body: &[u8], is_maintenance: bool) -> DynamicByteBuffer {
        let subheader_len = self.subheader_length(is_maintenance);
        let body_length = original_body.len();
        let total_length = body_length + Tailer::<T>::len();
        let packet = self.settings.pool().allocate(Some(total_length));

        packet.slice_end_mut(body_length).copy_from_slice(original_body);

        let pn = self.next_packet_number();
        Tailer::decoy(packet.rebuffer_start(body_length), &self.identity.get(), pn);

        if subheader_len > 0 {
            let expanded = packet.expand_start(subheader_len);
            if let Some(ref mut config) = self.features.subheader_config {
                config.fill(expanded.rebuffer_end(expanded.len() - subheader_len));
            }
            return expanded;
        }

        packet
    }

    /// Try to spend byte budget for a decoy packet.
    /// Returns true if budget was sufficient and has been deducted.
    pub(super) fn try_spend_budget(&mut self, bytes: usize) -> bool {
        if self.byte_budget >= bytes as f64 {
            self.byte_budget -= bytes as f64;
            true
        } else {
            false
        }
    }

    /// Schedule the next decoy packet.
    pub(super) fn schedule_next(&mut self, delay: u64, length: usize) {
        self.next_decoy_time = unix_timestamp_ms() + delay as u128;
        self.pending_length = length;
    }

    /// Schedule the next maintenance packet.
    pub(super) fn schedule_next_maintenance(&mut self) {
        let delay = maintenance_delay_for(&self.features.maintenance_mode, &self.settings);
        let length = maintenance_length_for(&self.features.maintenance_mode, &self.settings);
        self.next_maintenance_time = unix_timestamp_ms() + delay as u128;
        self.pending_maintenance_length = length;
    }

    /// Returns the subheader byte length for a packet, or 0 if no subheader applies.
    fn subheader_length(&self, is_maintenance: bool) -> usize {
        let should_apply = match self.features.subheader_mode {
            SubheaderMode::None => false,
            SubheaderMode::Maintenance => is_maintenance,
            SubheaderMode::All => true,
        };
        if should_apply {
            self.features.subheader_config.as_ref().map_or(0, FakeHeaderConfig::len)
        } else {
            0
        }
    }

    /// Check if a packet should be replicated.
    pub(super) fn should_replicate(&self, is_maintenance: bool) -> bool {
        match self.features.replication_mode {
            ReplicationMode::None => false,
            ReplicationMode::Maintenance => is_maintenance,
            ReplicationMode::All => true,
        }
    }
}

// ── Random utility functions ────────────────────────────────────────────────

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
