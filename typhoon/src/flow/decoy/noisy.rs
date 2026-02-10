/// Noisy mode: sends smaller decoy packets in bursts often, resembling web or socket traffic.
use std::sync::{Arc, Weak};
use std::time::Duration;

use log::debug;

use crate::flow::decoy::common::{DecoyCommunicationMode, DecoyState, exponential_variance, random_gauss, random_uniform};
use crate::bytes::{ByteBuffer, DynamicByteBuffer};
use crate::flow::common::FlowManager;
use crate::settings::Settings;
use crate::settings::keys::*;
use crate::utils::sync::{RwLock, sleep, spawn};
use crate::utils::time::unix_timestamp_ms;

/// Noisy mode implements sending smaller decoy packets in bursts often.
pub struct NoisyDecoyProvider<FM: FlowManager> {
    manager: Weak<FM>,
    settings: Arc<Settings>,
    state: Arc<RwLock<DecoyState>>,
}

impl<FM: FlowManager> NoisyDecoyProvider<FM> {
    fn calculate_delay(state: &DecoyState, settings: &Settings) -> u64 {
        let base_rate_rnd = settings.get(&DECOY_BASE_RATE_RND);
        let noisy_base_rate = settings.get(&DECOY_NOISY_BASE_RATE);
        let delay_min = settings.get(&DECOY_NOISY_DELAY_MIN);
        let delay_max = settings.get(&DECOY_NOISY_DELAY_MAX);
        let delay_default = settings.get(&DECOY_NOISY_DELAY_DEFAULT);

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
        let length_min = settings.get(&DECOY_NOISY_DECOY_LENGTH_MIN) as usize;
        let length_jitter = settings.get(&DECOY_NOISY_DECOY_LENGTH_JITTER);

        let quietness = state.quietness_index();
        let mean_length = (length_min as f64) + quietness * (-state.packet_rate / state.reference_rate).exp() * ((state.packet_length_cap - length_min) as f64);
        let decoy_length = random_gauss(mean_length, length_jitter * mean_length);

        (decoy_length as usize).clamp(length_min, state.packet_length_cap)
    }

    async fn timer_task(manager: Weak<FM>, settings: Arc<Settings>, state: Arc<RwLock<DecoyState>>) {
        loop {
            let delay = {
                let state_guard = state.read().await;
                let remaining = state_guard.next_decoy_time.saturating_sub(unix_timestamp_ms());
                Duration::from_millis(remaining as u64)
            };

            sleep(delay).await;

            let Some(manager_arc) = manager.upgrade() else {
                debug!("NoisyDecoyProvider: manager dropped, stopping timer");
                break;
            };

            let decoy_packet = {
                let mut state_guard = state.write().await;
                let decoy_length = state_guard.pending_length;
                let decoy_packet = state_guard.create_decoy_packet(decoy_length);

                let delay = Self::calculate_delay(&state_guard, &settings);
                let length = Self::calculate_length(&state_guard, &settings);
                state_guard.schedule_next(delay, length);

                debug!("NoisyDecoyProvider: generated decoy packet (len={}), next in {}ms", decoy_length, delay);
                decoy_packet
            };

            if let Err(err) = manager_arc.send_packet(decoy_packet, true).await {
                debug!("NoisyDecoyProvider: failed to send decoy packet: {:?}", err);
            }
        }
    }
}

impl<FM: FlowManager + Send + Sync + 'static> DecoyCommunicationMode for NoisyDecoyProvider<FM> {
    type FlowManagerT = FM;

    fn new(manager: Weak<Self::FlowManagerT>, settings: Arc<Settings>, tailor: usize) -> Self {
        let state = DecoyState::new(settings.clone(), tailor);
        let delay = Self::calculate_delay(&state, &settings);
        let length = Self::calculate_length(&state, &settings);
        let mut state = state;
        state.schedule_next(delay, length);

        debug!("NoisyDecoyProvider initialized with delay={}ms, length={}", delay, length);

        Self {
            manager,
            settings,
            state: Arc::new(RwLock::new(state)),
        }
    }

    async fn start(&mut self) {
        let manager = self.manager.clone();
        let settings = self.settings.clone();
        let state = self.state.clone();
        spawn(Self::timer_task(manager, settings, state));
        debug!("NoisyDecoyProvider: background timer started");
    }

    async fn feed_input(&mut self, packet: DynamicByteBuffer) -> Option<DynamicByteBuffer> {
        let mut state = self.state.write().await;
        state.update(packet.len(), &self.settings);
        Some(packet)
    }

    async fn feed_output(&mut self, packet: DynamicByteBuffer, generated: bool) -> Option<DynamicByteBuffer> {
        if !generated {
            let mut state = self.state.write().await;
            state.update(packet.len(), &self.settings);
        }
        Some(packet)
    }
}
