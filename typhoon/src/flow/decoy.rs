use std::sync::{Arc, Weak};
use std::time::Duration;

use log::debug;
use rand::Rng;
use rand_distr::{Distribution, Exp, Normal};

use crate::bytes::{ByteBuffer, ByteBufferMut, DynamicByteBuffer};
use crate::settings::keys::*;
use crate::settings::{Settings, SettingValue};
use crate::flow::common::FlowManager;
use crate::tailor::Tailor;
use crate::utils::random::get_rng;
use crate::utils::sync::{spawn, sleep, RwLock};
use crate::utils::time::unix_timestamp_ms;

/// Trait for implementing decoy traffic communication modes.
pub trait DecoyCommunicationMode: Sized + Send + Sync {
    type FlowManagerT: FlowManager;

    /// Create a new decoy provider with the given manager, settings, and tailor size.
    fn new(manager: Weak<Self::FlowManagerT>, settings: Arc<Settings>, tailor: usize) -> Self;

    /// Start the background decoy generation timer.
    fn start(&mut self) -> impl Future<Output = ()> + Send;

    /// Process a packet through the decoy provider, updating internal rate tracking.
    fn feed_input(&mut self, packet: DynamicByteBuffer) -> impl Future<Output = Option<DynamicByteBuffer>> + Send;

    /// Process a packet through the decoy provider, updating internal rate tracking.
    fn feed_output(&mut self, packet: DynamicByteBuffer, generated: bool) -> impl Future<Output = Option<DynamicByteBuffer>> + Send;
}

/// Internal state for tracking packet rates and byte budgets.
/// This state is shared by all communication modes.
struct DecoyState {
    settings: Arc<Settings>,
    /// Long-term reference transmission rate in packets (milliseconds between packets).
    reference_rate: f64,
    /// Current transmission rate in packets (milliseconds between packets).
    packet_rate: f64,
    /// Current transmission rate in bytes.
    byte_rate: f64,
    /// Number of decoy packet bytes allowed to send now.
    byte_budget: f64,
    /// Timestamp of the previous packet.
    previous_packet_time: Option<u128>,
    /// Maximum allowed length of decoy packets.
    packet_length_cap: usize,
    /// Incremental packet number counter.
    packet_number: u64,
    /// Tailor size in bytes.
    tailor_size: usize,
    /// Identity bytes for decoy packets (16 bytes of zeros).
    identity: Vec<u8>,
    /// Next scheduled decoy time (milliseconds since epoch).
    next_decoy_time: u128,
    /// Pre-computed length for next decoy.
    pending_length: usize,
}

impl DecoyState {
    fn new(settings: Arc<Settings>, tailor_size: usize) -> Self {
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
            tailor_size,
            identity: vec![0u8; 16], // 16 bytes of zeros for decoy identity
            next_decoy_time: now,
            pending_length: length_min,
        }
    }

    /// Update internal state when a packet passes through.
    fn update(&mut self, packet_length: usize, settings: &Settings) {
        let current_time = unix_timestamp_ms();

        if let Some(prev_time) = self.previous_packet_time {
            let time_delta = (current_time - prev_time) as f64;

            let reference_alpha = settings.get(&DECOY_REFERENCE_ALPHA);
            let current_alpha = settings.get(&DECOY_CURRENT_ALPHA);
            let byte_rate_cap = settings.get(&DECOY_BYTE_RATE_CAP);
            let byte_rate_factor = settings.get(&DECOY_BYTE_RATE_FACTOR);

            self.reference_rate = (1.0 - reference_alpha) * self.reference_rate + reference_alpha * time_delta;
            self.packet_rate = (1.0 - current_alpha) * self.packet_rate + current_alpha * time_delta;
            self.byte_rate = (1.0 - current_alpha) * self.byte_rate + current_alpha * (packet_length as f64);
            self.byte_budget = (self.byte_budget + time_delta * byte_rate_cap / 1000.0)
                .min(byte_rate_cap * byte_rate_factor);
        }

        self.previous_packet_time = Some(current_time);
    }

    /// Get quietness index: how quiet the traffic is (0 = busy, 1 = quiet).
    fn quietness_index(&self) -> f64 {
        ((self.reference_rate - self.packet_rate) / self.reference_rate).clamp(0.0, 1.0)
    }

    /// Get next packet number and increment counter.
    fn next_packet_number(&mut self) -> u64 {
        self.packet_number += 1;
        let timestamp = (unix_timestamp_ms() / 1000) as u32;
        ((timestamp as u64) << 32) | (self.packet_number as u64)
    }

    /// Create a decoy packet with the given body length.
    fn create_decoy_packet(&mut self, body_length: usize) -> DynamicByteBuffer {
        let total_length = body_length + self.tailor_size;
        let packet = self.settings.pool().allocate(Some(total_length));

        // Fill the body with random bytes
        get_rng().fill(packet.slice_end_mut(body_length));

        // Create and write the tailor
        let identity_buffer = self.settings.pool().allocate_precise_from_slice_with_capacity(&self.identity, 0, 0);
        let tailor = Tailor::decoy(identity_buffer, self.next_packet_number());
        let tailor_buffer = self.settings.pool().allocate(Some(self.tailor_size));
        let tailor_data = tailor.to_buffer(tailor_buffer);
        packet.slice_start_mut(body_length).copy_from_slice(tailor_data.slice());

        packet
    }

    /// Check if it's time to generate a decoy packet.
    fn should_generate_decoy(&self) -> bool {
        unix_timestamp_ms() >= self.next_decoy_time
    }

    /// Schedule the next decoy packet.
    fn schedule_next(&mut self, delay: u64, length: usize) {
        self.next_decoy_time = unix_timestamp_ms() + delay as u128;
        self.pending_length = length;
    }
}

/// Random uniform distribution between min and max.
#[inline]
fn random_uniform(min: f64, max: f64) -> f64 {
    get_rng().gen_range(min..=max)
}

/// Gaussian random with mean and standard deviation.
#[inline]
fn random_gauss(mean: f64, sigma: f64) -> f64 {
    if sigma <= 0.0 {
        return mean;
    }
    let normal = Normal::new(mean, sigma).unwrap_or_else(|_| Normal::new(mean, 1.0).unwrap());
    normal.sample(&mut get_rng())
}

/// Exponential random with rate (mean = 1/rate).
#[inline]
fn exponential_variance(rate: f64) -> f64 {
    if rate <= 0.0 {
        return f64::MAX;
    }
    let exp = Exp::new(rate).unwrap_or_else(|_| Exp::new(1.0).unwrap());
    exp.sample(&mut get_rng())
}

// ============================================================================
// Heavy Mode Implementation
// ============================================================================

/// Heavy mode implements sending big decoy packets occasionally.
/// It resembles file transferring or bulk update delivery.
///
/// The `start` method spawns a background timer task that generates and sends
/// decoy packets at calculated intervals. The task terminates when the
/// FlowManager weak reference becomes invalid.
pub struct HeavyDecoyProvider<FM: FlowManager> {
    manager: Weak<FM>,
    settings: Arc<Settings>,
    state: Arc<RwLock<DecoyState>>,
}

impl<FM: FlowManager> HeavyDecoyProvider<FM> {
    fn calculate_delay(state: &DecoyState, settings: &Settings) -> u64 {
        let base_rate_rnd = settings.get(&DECOY_BASE_RATE_RND);
        let heavy_base_rate = settings.get(&DECOY_HEAVY_BASE_RATE);
        let quietness_factor = settings.get(&DECOY_HEAVY_QUIETNESS_FACTOR);
        let delay_min = settings.get(&DECOY_HEAVY_DELAY_MIN);
        let delay_max = settings.get(&DECOY_HEAVY_DELAY_MAX);
        let delay_default = settings.get(&DECOY_HEAVY_DELAY_DEFAULT);

        let base_rate = heavy_base_rate * random_uniform(1.0 - base_rate_rnd, 1.0 + base_rate_rnd);
        let quietness = state.quietness_index();
        let rate = base_rate * quietness.powf(quietness_factor) * (-state.packet_rate / state.reference_rate).exp();

        let delay = if rate > 0.0 {
            exponential_variance(rate)
        } else {
            delay_default as f64
        };

        (delay as u64).clamp(delay_min, delay_max)
    }

    fn calculate_length(state: &DecoyState, settings: &Settings) -> usize {
        let base_length_factor = settings.get(&DECOY_HEAVY_BASE_LENGTH);
        let quietness_length = settings.get(&DECOY_HEAVY_QUIETNESS_LENGTH);
        let decoy_length_factor = settings.get(&DECOY_HEAVY_DECOY_LENGTH_FACTOR);

        let quietness = state.quietness_index();
        let base_length = (state.packet_length_cap as f64) * (base_length_factor + quietness_length * quietness);
        let decoy_length = random_uniform(decoy_length_factor * base_length, base_length);

        (decoy_length as usize).clamp(state.packet_length_cap / 2, state.packet_length_cap)
    }

    /// Background timer task that generates and sends decoy packets.
    async fn timer_task(manager: Weak<FM>, settings: Arc<Settings>, state: Arc<RwLock<DecoyState>>) {
        loop {
            // Get current delay from state
            let delay = {
                let state_guard = state.read().await;
                let remaining = state_guard.next_decoy_time.saturating_sub(unix_timestamp_ms());
                Duration::from_millis(remaining as u64)
            };

            // Sleep for the calculated delay
            sleep(delay).await;

            // Try to upgrade the weak reference to the manager
            let Some(manager_arc) = manager.upgrade() else {
                debug!("HeavyDecoyProvider: manager dropped, stopping timer");
                break;
            };

            // Generate and send decoy packet
            let decoy_packet = {
                let mut state_guard = state.write().await;
                let decoy_length = state_guard.pending_length;
                let decoy_packet = state_guard.create_decoy_packet(decoy_length);

                // Schedule next decoy
                let delay = Self::calculate_delay(&state_guard, &settings);
                let length = Self::calculate_length(&state_guard, &settings);
                state_guard.schedule_next(delay, length);

                debug!("HeavyDecoyProvider: generated decoy packet (len={}), next in {}ms", decoy_length, delay);
                decoy_packet
            };

            // Send the decoy packet
            if let Err(err) = manager_arc.send_packet(decoy_packet, true).await {
                debug!("HeavyDecoyProvider: failed to send decoy packet: {:?}", err);
            }
        }
    }
}

impl<FM: FlowManager + Send + Sync + 'static> DecoyCommunicationMode for HeavyDecoyProvider<FM> {
    type FlowManagerT = FM;

    fn new(manager: Weak<Self::FlowManagerT>, settings: Arc<Settings>, tailor: usize) -> Self {
        let state = DecoyState::new(settings.clone(), tailor);
        let delay = Self::calculate_delay(&state, &settings);
        let length = Self::calculate_length(&state, &settings);
        let mut state = state;
        state.schedule_next(delay, length);

        debug!("HeavyDecoyProvider initialized with delay={}ms, length={}", delay, length);

        Self {
            manager,
            settings,
            state: Arc::new(RwLock::new(state)),
        }
    }

    async fn start(&mut self) {
        // Spawn the background timer task
        let manager = self.manager.clone();
        let settings = self.settings.clone();
        let state = self.state.clone();
        spawn(Self::timer_task(manager, settings, state));
        debug!("HeavyDecoyProvider: background timer started");
    }
    
    async fn feed_input(&mut self, packet: DynamicByteBuffer) -> Option<DynamicByteBuffer> {
        todo!()
    }

    async fn feed_output(&mut self, packet: DynamicByteBuffer, generated: bool) -> Option<DynamicByteBuffer> {
        // Update state with incoming packet (for rate tracking)
        if !generated {
            let mut state = self.state.write().await;
            state.update(packet.len(), &self.settings);
        }

        // Always pass through the packet - decoy generation is handled by the timer task
        Some(packet)
    }
}


/*

// ============================================================================
// Noisy Mode Implementation
// ============================================================================

/// Noisy mode implements sending smaller decoy packets in bursts often.
/// It resembles usual web or socket traffic.
pub struct NoisyDecoyProvider<FM: FlowManager> {
    #[allow(dead_code)]
    manager: Weak<FM>,
    settings: Arc<Settings>,
    state: std::cell::RefCell<DecoyState>,
}

impl<FM: FlowManager> NoisyDecoyProvider<FM> {
    fn calculate_delay(state: &DecoyState, settings: &Settings) -> u64 {
        let base_rate_rnd = settings.get(&DECOY_BASE_RATE_RND] {
            SettingValue::Float(v) => v,
            _ => 0.25,
        };
        let noisy_base_rate = settings.get(&DECOY_NOISY_BASE_RATE] {
            SettingValue::Float(v) => v,
            _ => 3.0,
        };
        let delay_min = settings.get(&DECOY_NOISY_DELAY_MIN] {
            SettingValue::Unsigned(v) => v,
            _ => 10,
        };
        let delay_max = settings.get(&DECOY_NOISY_DELAY_MAX] {
            SettingValue::Unsigned(v) => v,
            _ => 1000,
        };
        let delay_default = settings.get(&DECOY_NOISY_DELAY_DEFAULT] {
            SettingValue::Unsigned(v) => v,
            _ => 500,
        };

        let base_rate = noisy_base_rate * random_uniform(1.0 - base_rate_rnd, 1.0 + base_rate_rnd);
        let quietness = state.quietness_index();
        let rate = base_rate * quietness * (-state.packet_rate / state.reference_rate).exp();

        let delay = if rate > 0.0 {
            exponential_variance(rate * (1.0 + state.packet_rate / state.reference_rate))
        } else {
            delay_default as f64
        };

        (delay as u64).clamp(delay_min, delay_max)
    }

    fn calculate_length(state: &DecoyState, settings: &Settings) -> usize {
        let length_min = settings.get(&DECOY_NOISY_DECOY_LENGTH_MIN] {
            SettingValue::Unsigned(v) => v as usize,
            _ => 128,
        };
        let length_jitter = settings.get(&DECOY_NOISY_DECOY_LENGTH_JITTER] {
            SettingValue::Float(v) => v,
            _ => 0.3,
        };

        let quietness = state.quietness_index();
        let mean_length = (length_min as f64) + quietness * (-state.packet_rate / state.reference_rate).exp()
            * ((state.packet_length_cap - length_min) as f64);
        let decoy_length = random_gauss(mean_length, length_jitter * mean_length);

        (decoy_length as usize).clamp(length_min, state.packet_length_cap)
    }
}

impl<FM: FlowManager> DecoyCommunicationMode for NoisyDecoyProvider<FM> {
    type FlowManagerT = FM;

    fn new(manager: Weak<Self::FlowManagerT>, settings: Arc<Settings>, tailor: usize) -> Self {
        let state = DecoyState::new(&settings, tailor);
        let delay = Self::calculate_delay(&state, &settings);
        let length = Self::calculate_length(&state, &settings);
        let mut state = state;
        state.schedule_next(delay, length);

        debug!("NoisyDecoyProvider initialized with delay={}ms, length={}", delay, length);

        Self {
            manager,
            settings,
            state: std::cell::RefCell::new(state),
        }
    }

    fn feed(&self, packet: ByteBuffer, generated: bool) -> Option<ByteBuffer> {
        let mut state = self.state.borrow_mut();

        if !generated {
            state.update(packet.len(), &self.settings);
        }

        if state.should_generate_decoy() {
            let decoy_length = state.pending_length;
            let decoy_packet = state.create_decoy_packet(decoy_length);

            let delay = Self::calculate_delay(&state, &self.settings);
            let length = Self::calculate_length(&state, &self.settings);
            state.schedule_next(delay, length);

            debug!("NoisyDecoyProvider generated decoy packet, next in {}ms", delay);

            return Some(decoy_packet);
        }

        Some(packet)
    }
}

// ============================================================================
// Sparse Mode Implementation
// ============================================================================

/// Sparse mode implements sending average decoy packets sparsely distributed in time.
/// It resembles VoIP traffic or downloading.
pub struct SparseDecoyProvider<FM: FlowManager> {
    #[allow(dead_code)]
    manager: Weak<FM>,
    settings: Arc<Settings>,
    state: std::cell::RefCell<DecoyState>,
}

impl<FM: FlowManager> SparseDecoyProvider<FM> {
    fn calculate_delay(state: &DecoyState, settings: &Settings) -> u64 {
        let base_rate_rnd = settings.get(&DECOY_BASE_RATE_RND] {
            SettingValue::Float(v) => v,
            _ => 0.25,
        };
        let sparse_base_rate = settings.get(&DECOY_SPARSE_BASE_RATE] {
            SettingValue::Float(v) => v,
            _ => 20.0,
        };
        let rate_factor = settings.get(&DECOY_SPARSE_RATE_FACTOR] {
            SettingValue::Float(v) => v,
            _ => 3.0,
        };
        let jitter = settings.get(&DECOY_SPARSE_JITTER] {
            SettingValue::Float(v) => v,
            _ => 0.15,
        };
        let delay_factor = settings.get(&DECOY_SPARSE_DELAY_FACTOR] {
            SettingValue::Float(v) => v,
            _ => 3.0,
        };
        let delay_min = settings.get(&DECOY_SPARSE_DELAY_MIN] {
            SettingValue::Unsigned(v) => v,
            _ => 20,
        };
        let delay_max = settings.get(&DECOY_SPARSE_DELAY_MAX] {
            SettingValue::Unsigned(v) => v,
            _ => 150,
        };
        let delay_default = settings.get(&DECOY_SPARSE_DELAY_DEFAULT] {
            SettingValue::Unsigned(v) => v,
            _ => 100,
        };

        let base_rate = sparse_base_rate * random_uniform(1.0 - base_rate_rnd, 1.0 + base_rate_rnd);
        let quietness = state.quietness_index();
        let rate = base_rate * quietness * (-rate_factor * state.packet_rate / state.reference_rate).exp();

        let delay = if rate > 0.0 {
            random_uniform(1.0 - jitter, 1.0 + jitter)
                * (1.0 + delay_factor * (state.packet_rate / state.reference_rate))
                / rate
        } else {
            delay_default as f64
        };

        (delay as u64).clamp(delay_min, delay_max)
    }

    fn calculate_length(state: &DecoyState, settings: &Settings) -> usize {
        let length_factor = settings.get(&DECOY_SPARSE_LENGTH_FACTOR] {
            SettingValue::Float(v) => v,
            _ => 120.0,
        };
        let length_sigma = settings.get(&DECOY_SPARSE_LENGTH_SIGMA] {
            SettingValue::Float(v) => v,
            _ => 20.0,
        };
        let length_min = settings.get(&DECOY_SPARSE_LENGTH_MIN] {
            SettingValue::Unsigned(v) => v as usize,
            _ => 75,
        };
        let length_max = settings.get(&DECOY_SPARSE_LENGTH_MAX] {
            SettingValue::Unsigned(v) => v as usize,
            _ => 250,
        };

        let mean = length_factor * (-state.packet_rate / state.reference_rate).exp();
        let decoy_length = random_gauss(mean, length_sigma);

        (decoy_length as usize).clamp(length_min, length_max)
    }
}

impl<FM: FlowManager> DecoyCommunicationMode for SparseDecoyProvider<FM> {
    type FlowManagerT = FM;

    fn new(manager: Weak<Self::FlowManagerT>, settings: Arc<Settings>, tailor: usize) -> Self {
        let state = DecoyState::new(&settings, tailor);
        let delay = Self::calculate_delay(&state, &settings);
        let length = Self::calculate_length(&state, &settings);
        let mut state = state;
        state.schedule_next(delay, length);

        debug!("SparseDecoyProvider initialized with delay={}ms, length={}", delay, length);

        Self {
            manager,
            settings,
            state: std::cell::RefCell::new(state),
        }
    }

    fn feed(&self, packet: ByteBuffer, generated: bool) -> Option<ByteBuffer> {
        let mut state = self.state.borrow_mut();

        if !generated {
            state.update(packet.len(), &self.settings);
        }

        if state.should_generate_decoy() {
            let decoy_length = state.pending_length;
            let decoy_packet = state.create_decoy_packet(decoy_length);

            let delay = Self::calculate_delay(&state, &self.settings);
            let length = Self::calculate_length(&state, &self.settings);
            state.schedule_next(delay, length);

            debug!("SparseDecoyProvider generated decoy packet, next in {}ms", delay);

            return Some(decoy_packet);
        }

        Some(packet)
    }
}

// ============================================================================
// Smooth Mode Implementation
// ============================================================================

/// Smooth mode implements sending few average decoy packets during quiet periods.
/// It fills gaps between data packets and prevents the connection from going silent.
pub struct SmoothDecoyProvider<FM: FlowManager> {
    #[allow(dead_code)]
    manager: Weak<FM>,
    settings: Arc<Settings>,
    state: std::cell::RefCell<DecoyState>,
}

impl<FM: FlowManager> SmoothDecoyProvider<FM> {
    fn calculate_delay(state: &DecoyState, settings: &Settings) -> u64 {
        let base_rate_rnd = settings.get(&DECOY_BASE_RATE_RND] {
            SettingValue::Float(v) => v,
            _ => 0.25,
        };
        let smooth_base_rate = settings.get(&DECOY_SMOOTH_BASE_RATE] {
            SettingValue::Float(v) => v,
            _ => 0.3,
        };
        let quietness_factor = settings.get(&DECOY_SMOOTH_QUIETNESS_FACTOR] {
            SettingValue::Float(v) => v,
            _ => 2.0,
        };
        let rate_factor = settings.get(&DECOY_SMOOTH_RATE_FACTOR] {
            SettingValue::Float(v) => v,
            _ => 3.0,
        };
        let jitter = settings.get(&DECOY_SMOOTH_JITTER] {
            SettingValue::Float(v) => v,
            _ => 0.2,
        };
        let delay_factor = settings.get(&DECOY_SMOOTH_DELAY_FACTOR] {
            SettingValue::Float(v) => v,
            _ => 2.0,
        };
        let delay_min = settings.get(&DECOY_SMOOTH_DELAY_MIN] {
            SettingValue::Unsigned(v) => v,
            _ => 300,
        };
        let delay_max = settings.get(&DECOY_SMOOTH_DELAY_MAX] {
            SettingValue::Unsigned(v) => v,
            _ => 10000,
        };
        let delay_default = settings.get(&DECOY_SMOOTH_DELAY_DEFAULT] {
            SettingValue::Unsigned(v) => v,
            _ => 5000,
        };

        let base_rate = smooth_base_rate * random_uniform(1.0 - base_rate_rnd, 1.0 + base_rate_rnd);
        let quietness = state.quietness_index();
        let rate = base_rate * quietness.powf(quietness_factor)
            * (-rate_factor * state.packet_rate / state.reference_rate).exp();

        let delay = if rate > 0.0 {
            random_uniform(1.0 - jitter, 1.0 + jitter)
                * (1.0 + delay_factor * (state.packet_rate / state.reference_rate))
                / rate
        } else {
            delay_default as f64
        };

        (delay as u64).clamp(delay_min, delay_max)
    }

    fn calculate_length(state: &DecoyState, settings: &Settings) -> usize {
        let length_min = settings.get(&DECOY_SMOOTH_LENGTH_MIN] {
            SettingValue::Unsigned(v) => v as usize,
            _ => 48,
        };
        let length_max = settings.get(&DECOY_SMOOTH_LENGTH_MAX] {
            SettingValue::Unsigned(v) => v as usize,
            _ => 512,
        };

        let quietness = state.quietness_index();
        let mean_length = (length_min as f64) + quietness * (-state.packet_rate / state.reference_rate).exp()
            * ((length_max - length_min) as f64);
        let decoy_length = random_uniform(length_min as f64, mean_length);

        (decoy_length as usize).clamp(length_min, length_max)
    }
}

impl<FM: FlowManager> DecoyCommunicationMode for SmoothDecoyProvider<FM> {
    type FlowManagerT = FM;

    fn new(manager: Weak<Self::FlowManagerT>, settings: Arc<Settings>, tailor: usize) -> Self {
        let state = DecoyState::new(&settings, tailor);
        let delay = Self::calculate_delay(&state, &settings);
        let length = Self::calculate_length(&state, &settings);
        let mut state = state;
        state.schedule_next(delay, length);

        debug!("SmoothDecoyProvider initialized with delay={}ms, length={}", delay, length);

        Self {
            manager,
            settings,
            state: std::cell::RefCell::new(state),
        }
    }

    fn feed(&self, packet: ByteBuffer, generated: bool) -> Option<ByteBuffer> {
        let mut state = self.state.borrow_mut();

        if !generated {
            state.update(packet.len(), &self.settings);
        }

        if state.should_generate_decoy() {
            let decoy_length = state.pending_length;
            let decoy_packet = state.create_decoy_packet(decoy_length);

            let delay = Self::calculate_delay(&state, &self.settings);
            let length = Self::calculate_length(&state, &self.settings);
            state.schedule_next(delay, length);

            debug!("SmoothDecoyProvider generated decoy packet, next in {}ms", delay);

            return Some(decoy_packet);
        }

        Some(packet)
    }
}


*/
