/// Noisy mode: sends smaller decoy packets in bursts often, resembling web or socket traffic.
use std::sync::{Arc, Weak};
use std::time::Duration;

use log::debug;

use crate::bytes::{ByteBuffer, DynamicByteBuffer};
use crate::flow::common::FlowManager;
use crate::flow::decoy::common::{DecoyCommunicationMode, DecoyState, exponential_variance, random_gauss, random_uniform};
use crate::settings::Settings;
use crate::settings::keys::*;
use crate::tailor::IdentityType;
use crate::utils::sync::{AsyncExecutor, RwLock, sleep};
use crate::utils::time::unix_timestamp_ms;

/// Noisy mode implements sending smaller decoy packets in bursts often.
pub struct NoisyDecoyProvider<T: IdentityType + 'static, AE: AsyncExecutor + 'static, FM: FlowManager + 'static> {
    manager: Weak<FM>,
    state: Arc<RwLock<DecoyState<T, AE>>>,
}

impl<T: IdentityType, AE: AsyncExecutor, FM: FlowManager> NoisyDecoyProvider<T, AE, FM> {
    fn calculate_delay(state: &DecoyState<T, AE>) -> u64 {
        let base_rate_rnd = state.settings.get(&DECOY_BASE_RATE_RND);
        let noisy_base_rate = state.settings.get(&DECOY_NOISY_BASE_RATE);
        let delay_min = state.settings.get(&DECOY_NOISY_DELAY_MIN);
        let delay_max = state.settings.get(&DECOY_NOISY_DELAY_MAX);
        let delay_default = state.settings.get(&DECOY_NOISY_DELAY_DEFAULT);

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

    fn calculate_length(state: &DecoyState<T, AE>) -> usize {
        let length_min = state.settings.get(&DECOY_NOISY_DECOY_LENGTH_MIN) as usize;
        let length_jitter = state.settings.get(&DECOY_NOISY_DECOY_LENGTH_JITTER);

        let quietness = state.quietness_index();
        let mean_length = (length_min as f64) + quietness * (-state.packet_rate / state.reference_rate).exp() * ((state.packet_length_cap - length_min) as f64);
        let decoy_length = random_gauss(mean_length, length_jitter * mean_length);

        (decoy_length as usize).clamp(length_min, state.packet_length_cap)
    }

    async fn timer_task(manager: Weak<FM>, state: Arc<RwLock<DecoyState<T, AE>>>) {
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

                let delay = Self::calculate_delay(&state_guard);
                let length = Self::calculate_length(&state_guard);
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

impl<T: IdentityType, AE: AsyncExecutor, FM: FlowManager + Send + Sync + 'static> DecoyCommunicationMode<AE, FM> for NoisyDecoyProvider<T, AE, FM> {
    fn new(manager: Weak<FM>, settings: Arc<Settings<AE>>) -> Self {
        let state = DecoyState::new(settings.clone());
        let delay = Self::calculate_delay(&state);
        let length = Self::calculate_length(&state);
        let mut state = state;
        state.schedule_next(delay, length);

        debug!("NoisyDecoyProvider initialized with delay ({delay} ms), length ({length} bytes)");

        Self {
            manager,
            state: Arc::new(RwLock::new(state)),
        }
    }

    async fn start(&mut self) {
        let executor = {
            let lock = self.state.read().await;
            lock.settings.executor().clone()
        };

        let manager = self.manager.clone();
        let state = self.state.clone();
        executor.spawn(Self::timer_task(manager, state));
        debug!("NoisyDecoyProvider: background timer started");
    }

    async fn feed_input(&mut self, packet: DynamicByteBuffer) -> Option<DynamicByteBuffer> {
        let mut state = self.state.write().await;
        state.update(packet.len());
        Some(packet)
    }

    async fn feed_output(&mut self, packet: DynamicByteBuffer, generated: bool) -> Option<DynamicByteBuffer> {
        if !generated {
            let mut state = self.state.write().await;
            state.update(packet.len());
        }
        Some(packet)
    }
}
