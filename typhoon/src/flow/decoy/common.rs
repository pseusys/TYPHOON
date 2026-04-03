#[cfg(test)]
#[path = "../../../tests/flow/decoy.rs"]
mod tests;

/// Shared state and utilities for decoy traffic communication modes.
use std::sync::{Arc, Weak};
use std::time::Duration;

use log::debug;
use rand::Rng;
use rand::seq::SliceRandom;
use rand_distr::{Distribution, Exp, Normal};

use crate::bytes::{ByteBuffer, ByteBufferMut, DynamicByteBuffer};
use crate::flow::common::FlowManager;
use crate::flow::config::{FakeHeaderConfig, FieldType, FieldTypeHolder};
use crate::settings::Settings;
use crate::settings::consts::TAILOR_LENGTH;
use crate::settings::keys::*;
use crate::tailor::{IdentityType, Tailor};
use crate::utils::random::get_rng;
use crate::utils::sync::{AsyncExecutor, RwLock, sleep};
use crate::utils::time::unix_timestamp_ms;

// ── Mode enums ──────────────────────────────────────────────────────────────

/// Maintenance mode for decoy packets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum MaintenanceMode {
    None,
    Random,
    Timed { delay_ms: u64 },
    Sized { length: usize },
    Both { delay_ms: u64, length: usize },
}

/// Replication mode for decoy packets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ReplicationMode {
    None,
    Maintenance,
    All,
}

/// Subheader mode for decoy packets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum SubheaderMode {
    None,
    Maintenance,
    All,
}

// ── DecoyFeatureConfig ──────────────────────────────────────────────────────

/// Per-provider configuration for maintenance, replication, and subheader features.
/// Randomly selected at init.
pub(super) struct DecoyFeatureConfig {
    pub(super) maintenance_mode: MaintenanceMode,
    pub(super) replication_mode: ReplicationMode,
    pub(super) replication_probability: f64,
    pub(super) subheader_mode: SubheaderMode,
    pub(super) subheader_config: Option<FakeHeaderConfig>,
}

impl DecoyFeatureConfig {
    pub(super) fn random<AE: AsyncExecutor>(settings: &Settings<AE>) -> Self {
        let mut rng = get_rng();

        // Maintenance mode: None is weighted heavier.
        let none_weight = settings.get(&DECOY_MAINTENANCE_MODE_NONE_PROBABILITY);
        let total = none_weight + 4.0; // 4 other modes
        let roll: f64 = rng.gen_range(0.0..total);
        let maintenance_mode = if roll < none_weight {
            MaintenanceMode::None
        } else {
            let delay_min = settings.get(&DECOY_MAINTENANCE_DELAY_MIN);
            let delay_max = settings.get(&DECOY_MAINTENANCE_DELAY_MAX);
            let length_min = settings.get(&DECOY_MAINTENANCE_LENGTH_MIN) as usize;
            let length_max = settings.get(&DECOY_MAINTENANCE_LENGTH_MAX) as usize;
            let fixed_delay = rng.gen_range(delay_min..=delay_max);
            let fixed_length = rng.gen_range(length_min..=length_max);
            let idx = ((roll - none_weight) * 4.0 / 4.0) as usize;
            match idx.min(3) {
                0 => MaintenanceMode::Random,
                1 => MaintenanceMode::Timed { delay_ms: fixed_delay },
                2 => MaintenanceMode::Sized { length: fixed_length },
                _ => MaintenanceMode::Both { delay_ms: fixed_delay, length: fixed_length },
            }
        };

        // Replication mode: None is weighted heavier.
        let none_weight = settings.get(&DECOY_REPLICATION_MODE_NONE_PROBABILITY);
        let total = none_weight + 2.0;
        let roll: f64 = rng.gen_range(0.0..total);
        let replication_mode = if roll < none_weight {
            ReplicationMode::None
        } else if roll < none_weight + 1.0 {
            ReplicationMode::Maintenance
        } else {
            ReplicationMode::All
        };

        let prob_min = settings.get(&DECOY_REPLICATION_PROBABILITY_MIN);
        let prob_max = settings.get(&DECOY_REPLICATION_PROBABILITY_MAX);
        let replication_probability = rng.gen_range(prob_min..=prob_max);

        // Subheader mode: equal probability.
        let subheader_mode = match rng.gen_range(0u8..3) {
            0 => SubheaderMode::None,
            1 => SubheaderMode::Maintenance,
            _ => SubheaderMode::All,
        };

        let subheader_config = if subheader_mode != SubheaderMode::None {
            let min_len = settings.get(&DECOY_SUBHEADER_LENGTH_MIN) as usize;
            let max_len = settings.get(&DECOY_SUBHEADER_LENGTH_MAX) as usize;
            Some(generate_random_fake_header(min_len, max_len))
        } else {
            None
        };

        Self {
            maintenance_mode,
            replication_mode,
            replication_probability,
            subheader_mode,
            subheader_config,
        }
    }
}

/// Generate a random `FakeHeaderConfig` with total byte length in [min_len, max_len].
fn generate_random_fake_header(min_len: usize, max_len: usize) -> FakeHeaderConfig {
    let mut rng = get_rng();
    let target_len = rng.gen_range(min_len..=max_len);
    let mut fields = Vec::new();
    let mut current_len = 0usize;

    while current_len < target_len {
        let remaining = target_len - current_len;
        // Pick the largest field size that still fits.
        let size = if remaining >= 8 {
            *[1usize, 2, 4, 8].choose(&mut rng).unwrap()
        } else if remaining >= 4 {
            *[1usize, 2, 4].choose(&mut rng).unwrap()
        } else if remaining >= 2 {
            *[1usize, 2].choose(&mut rng).unwrap()
        } else {
            1
        };

        let field = match size {
            1 => FieldTypeHolder::U8(random_field_type(&mut rng)),
            2 => FieldTypeHolder::U16(random_field_type(&mut rng)),
            4 => FieldTypeHolder::U32(random_field_type(&mut rng)),
            8 => FieldTypeHolder::U64(random_field_type(&mut rng)),
            _ => unreachable!(),
        };
        fields.push(field);
        current_len += size;
    }

    FakeHeaderConfig::new(fields)
}

/// Generate a random FieldType variant for a given size.
fn random_field_type<L: Copy + From<u8>>(rng: &mut impl Rng) -> FieldType<L>
where
    rand::distributions::Standard: Distribution<L>,
{
    match rng.gen_range(0u8..5) {
        0 => FieldType::Random,
        1 => FieldType::Constant { value: rng.r#gen::<L>() },
        2 => FieldType::Volatile {
            value: rng.r#gen::<L>(),
            change_probability: rng.gen_range(0.01..0.5),
        },
        3 => FieldType::Switching {
            value: rng.r#gen::<L>(),
            next_switch: unix_timestamp_ms() + rng.gen_range(1000..10000) as u128,
            switch_timeout: rng.gen_range(1000..10000),
        },
        _ => FieldType::Incremental { value: rng.r#gen::<L>() },
    }
}

// ── Trait ────────────────────────────────────────────────────────────────────

/// Trait for implementing decoy traffic communication modes.
pub trait DecoyCommunicationMode<T: IdentityType + Clone, AE: AsyncExecutor, FM: Send + Sync + 'static>: Sized + Send + Sync {
    /// Create a new decoy provider with the given manager, settings, and identity.
    fn new(manager: Weak<FM>, settings: Arc<Settings<AE>>, identity: T) -> Self;

    /// Start the background decoy generation timer.
    fn start(&mut self) -> impl Future<Output = ()> + Send;

    /// Process an incoming packet through the decoy provider, updating internal rate tracking.
    fn feed_input(&mut self, packet: DynamicByteBuffer) -> impl Future<Output = Option<DynamicByteBuffer>> + Send;

    /// Process an outgoing packet through the decoy provider, updating internal rate tracking.
    fn feed_output(&mut self, packet: DynamicByteBuffer, generated: bool) -> impl Future<Output = Option<DynamicByteBuffer>> + Send;
}

// ── DecoyState ──────────────────────────────────────────────────────────────

/// Internal state for tracking packet rates and byte budgets.
/// This state is shared by all communication modes.
pub(super) struct DecoyState<T: IdentityType + Clone, AE: AsyncExecutor> {
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
    /// Identity for decoy packets.
    identity: T,
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
}

impl<T: IdentityType + Clone, AE: AsyncExecutor> DecoyState<T, AE> {
    pub(super) fn new(settings: Arc<Settings<AE>>, identity: T) -> Self {
        let byte_rate_cap = settings.get(&DECOY_BYTE_RATE_CAP);
        let byte_rate_factor = settings.get(&DECOY_BYTE_RATE_FACTOR);
        let length_max = settings.get(&DECOY_LENGTH_MAX) as usize;
        let length_min = settings.get(&DECOY_LENGTH_MIN) as usize;

        let now = unix_timestamp_ms();
        let features = DecoyFeatureConfig::random(&settings);

        // Initial maintenance scheduling.
        let (maint_time, maint_len) = if features.maintenance_mode != MaintenanceMode::None {
            let delay = maintenance_delay_for(&features.maintenance_mode, &settings);
            let length = maintenance_length_for(&features.maintenance_mode, &settings);
            (now + delay as u128, length)
        } else {
            (u128::MAX, 0)
        };

        Self {
            settings: settings.clone(),
            reference_rate: settings.get(&DECOY_REFERENCE_PACKET_RATE_DEFAULT),
            packet_rate: settings.get(&DECOY_CURRENT_PACKET_RATE_DEFAULT),
            byte_rate: settings.get(&DECOY_CURRENT_BYTE_RATE_DEFAULT),
            byte_budget: byte_rate_cap * byte_rate_factor / 2.0,
            previous_packet_time: None,
            packet_length_cap: length_max.max(length_min),
            packet_number: 0,
            identity,
            next_decoy_time: now,
            pending_length: length_min,
            features,
            next_maintenance_time: maint_time,
            pending_maintenance_length: maint_len,
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
    /// If `is_maintenance` is true and the subheader mode applies, a subheader is prepended.
    pub(super) fn create_decoy_packet(&mut self, body_length: usize, is_maintenance: bool) -> DynamicByteBuffer {
        let subheader_len = self.subheader_length(is_maintenance);
        let total_length = body_length + TAILOR_LENGTH + T::length();
        let packet = self.settings.pool().allocate_precise(total_length, subheader_len, 0);

        get_rng().fill(packet.slice_end_mut(body_length));

        let pn = self.next_packet_number();
        let tailor_buffer = self.settings.pool().allocate(Some(T::length() + TAILOR_LENGTH));
        let tailor = Tailor::decoy(tailor_buffer, &self.identity, pn);
        packet.slice_start_mut(body_length).copy_from_slice(tailor.buffer().slice());

        if subheader_len > 0 {
            let expanded = packet.expand_start(subheader_len);
            if let Some(ref mut config) = self.features.subheader_config {
                config.fill(expanded.rebuffer_end(expanded.len() - subheader_len));
            }
            return expanded;
        }

        packet
    }

    /// Create a replica of the given decoy body (same body bytes, new tailor).
    pub(super) fn create_replica_packet(&mut self, original_body: &[u8], is_maintenance: bool) -> DynamicByteBuffer {
        let subheader_len = self.subheader_length(is_maintenance);
        let body_length = original_body.len();
        let total_length = body_length + TAILOR_LENGTH + T::length();
        let packet = self.settings.pool().allocate_precise(total_length, subheader_len, 0);

        packet.slice_end_mut(body_length).copy_from_slice(original_body);

        let pn = self.next_packet_number();
        let tailor_buffer = self.settings.pool().allocate(Some(T::length() + TAILOR_LENGTH));
        let tailor = Tailor::decoy(tailor_buffer, &self.identity, pn);
        packet.slice_start_mut(body_length).copy_from_slice(tailor.buffer().slice());

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
            self.features.subheader_config.as_ref().map_or(0, |c| c.len())
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

// ── Maintenance / Replication helpers ───────────────────────────────────────

/// Get maintenance delay for the given mode.
fn maintenance_delay_for<AE: AsyncExecutor>(mode: &MaintenanceMode, settings: &Settings<AE>) -> u64 {
    match *mode {
        MaintenanceMode::Timed { delay_ms } | MaintenanceMode::Both { delay_ms, .. } => delay_ms,
        _ => {
            let min = settings.get(&DECOY_MAINTENANCE_DELAY_MIN);
            let max = settings.get(&DECOY_MAINTENANCE_DELAY_MAX);
            random_uniform(min as f64, max as f64) as u64
        }
    }
}

/// Get maintenance packet length for the given mode.
fn maintenance_length_for<AE: AsyncExecutor>(mode: &MaintenanceMode, settings: &Settings<AE>) -> usize {
    match *mode {
        MaintenanceMode::Sized { length } | MaintenanceMode::Both { length, .. } => length,
        _ => {
            let min = settings.get(&DECOY_MAINTENANCE_LENGTH_MIN) as usize;
            let max = settings.get(&DECOY_MAINTENANCE_LENGTH_MAX) as usize;
            random_uniform(min as f64, max as f64) as usize
        }
    }
}

/// Background maintenance timer task. Runs independently of the communication mode timer.
/// Returns immediately if maintenance mode is `None`.
pub(super) async fn maintenance_timer_task<T, AE, FM>(
    manager: Weak<FM>,
    state: Arc<RwLock<DecoyState<T, AE>>>,
) where
    T: IdentityType + Clone + 'static,
    AE: AsyncExecutor + 'static,
    FM: FlowManager + Send + Sync + 'static,
{
    {
        let guard = state.read().await;
        if guard.features.maintenance_mode == MaintenanceMode::None {
            return;
        }
    }

    loop {
        let delay = {
            let guard = state.read().await;
            let remaining = guard.next_maintenance_time.saturating_sub(unix_timestamp_ms());
            Duration::from_millis(remaining as u64)
        };

        sleep(delay).await;

        let Some(manager_arc) = manager.upgrade() else {
            debug!("Maintenance timer: manager dropped, stopping");
            break;
        };

        let (packet, body_length, body_bytes) = {
            let mut guard = state.write().await;
            let length = guard.pending_maintenance_length;

            if !guard.try_spend_budget(length) {
                guard.schedule_next_maintenance();
                debug!("Maintenance: insufficient budget for {} bytes, skipping", length);
                continue;
            }

            let packet = guard.create_decoy_packet(length, true);
            // Save body bytes for potential replication (before tailor).
            let body = packet.slice_end(length).to_vec();
            (packet, length, body)
        };

        debug!("Maintenance: generated packet (len={})", body_length);

        if let Err(err) = manager_arc.send_packet(packet, true).await {
            debug!("Maintenance: failed to send: {:?}", err);
        } else {
            try_replicate(&state, &manager, true, &body_bytes).await;
        }

        {
            let mut guard = state.write().await;
            guard.schedule_next_maintenance();
        }
    }
}

/// Attempt replication of a decoy packet. If replication mode applies, spawns a cascading
/// task that re-sends the packet body with diminishing probability.
pub(super) async fn try_replicate<T, AE, FM>(
    state: &Arc<RwLock<DecoyState<T, AE>>>,
    manager: &Weak<FM>,
    is_maintenance: bool,
    body_bytes: &[u8],
) where
    T: IdentityType + Clone + 'static,
    AE: AsyncExecutor + 'static,
    FM: FlowManager + Send + Sync + 'static,
{
    let (probability, delay_min, delay_max, reduce, executor) = {
        let guard = state.read().await;
        if !guard.should_replicate(is_maintenance) {
            return;
        }
        (
            guard.features.replication_probability,
            guard.settings.get(&DECOY_REPLICATION_DELAY_MIN),
            guard.settings.get(&DECOY_REPLICATION_DELAY_MAX),
            guard.settings.get(&DECOY_REPLICATION_PROBABILITY_REDUCE),
            guard.settings.executor().clone(),
        )
    };

    let state_clone = Arc::clone(state);
    let manager_clone = manager.clone();
    let body_owned = body_bytes.to_vec();

    executor.spawn(async move {
        let mut current_probability = probability;
        loop {
            if get_rng().r#gen::<f64>() >= current_probability {
                break;
            }

            let delay = random_uniform(delay_min as f64, delay_max as f64) as u64;
            sleep(Duration::from_millis(delay)).await;

            let Some(manager_arc) = manager_clone.upgrade() else { break; };

            let packet = {
                let mut guard = state_clone.write().await;
                if !guard.try_spend_budget(body_owned.len()) {
                    debug!("Replication: insufficient budget, stopping cascade");
                    break;
                }
                guard.create_replica_packet(&body_owned, is_maintenance)
            };

            debug!("Replication: sending replica (len={})", body_owned.len());
            if manager_arc.send_packet(packet, true).await.is_err() {
                break;
            }

            current_probability /= reduce;
        }
    });
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
