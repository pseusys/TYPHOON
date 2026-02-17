/// Sparse mode: sends average decoy packets sparsely distributed in time, resembling VoIP or downloading.
use std::sync::{Arc, Weak};
use std::time::Duration;

use log::debug;

use crate::bytes::{ByteBuffer, DynamicByteBuffer};
use crate::flow::common::FlowManager;
use crate::flow::decoy::common::{DecoyCommunicationMode, DecoyState, random_gauss, random_uniform};
use crate::settings::Settings;
use crate::settings::keys::*;
use crate::tailor::IdentityType;
use crate::utils::sync::{AsyncExecutor, RwLock, sleep};
use crate::utils::time::unix_timestamp_ms;

/// Sparse mode implements sending average decoy packets sparsely distributed in time.
pub struct SparseDecoyProvider<T: IdentityType + 'static, AE: AsyncExecutor + 'static, FM: FlowManager + 'static> {
    manager: Weak<FM>,
    state: Arc<RwLock<DecoyState<T, AE>>>,
}

impl<T: IdentityType, AE: AsyncExecutor, FM: FlowManager> SparseDecoyProvider<T, AE, FM> {
    fn calculate_delay(state: &DecoyState<T, AE>) -> u64 {
        let base_rate_rnd = state.settings.get(&DECOY_BASE_RATE_RND);
        let sparse_base_rate = state.settings.get(&DECOY_SPARSE_BASE_RATE);
        let rate_factor = state.settings.get(&DECOY_SPARSE_RATE_FACTOR);
        let jitter = state.settings.get(&DECOY_SPARSE_JITTER);
        let delay_factor = state.settings.get(&DECOY_SPARSE_DELAY_FACTOR);
        let delay_min = state.settings.get(&DECOY_SPARSE_DELAY_MIN);
        let delay_max = state.settings.get(&DECOY_SPARSE_DELAY_MAX);
        let delay_default = state.settings.get(&DECOY_SPARSE_DELAY_DEFAULT);

        let base_rate = sparse_base_rate * random_uniform(1.0 - base_rate_rnd, 1.0 + base_rate_rnd);
        let quietness = state.quietness_index();
        let rate = base_rate * quietness * (-rate_factor * state.packet_rate / state.reference_rate).exp();

        let delay = if rate > 0.0 {
            random_uniform(1.0 - jitter, 1.0 + jitter) * (1.0 + delay_factor * (state.packet_rate / state.reference_rate)) / rate
        } else {
            delay_default as f64
        };

        (delay as u64).clamp(delay_min, delay_max)
    }

    fn calculate_length(state: &DecoyState<T, AE>) -> usize {
        let length_factor = state.settings.get(&DECOY_SPARSE_LENGTH_FACTOR);
        let length_sigma = state.settings.get(&DECOY_SPARSE_LENGTH_SIGMA);
        let length_min = state.settings.get(&DECOY_SPARSE_LENGTH_MIN) as usize;
        let length_max = state.settings.get(&DECOY_SPARSE_LENGTH_MAX) as usize;

        let mean = length_factor * (-state.packet_rate / state.reference_rate).exp();
        let decoy_length = random_gauss(mean, length_sigma);

        (decoy_length as usize).clamp(length_min, length_max)
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
                debug!("SparseDecoyProvider: manager dropped, stopping timer");
                break;
            };

            let decoy_packet = {
                let mut state_guard = state.write().await;
                let decoy_length = state_guard.pending_length;
                let decoy_packet = state_guard.create_decoy_packet(decoy_length);

                let delay = Self::calculate_delay(&state_guard);
                let length = Self::calculate_length(&state_guard);
                state_guard.schedule_next(delay, length);

                debug!("SparseDecoyProvider: generated decoy packet (len={}), next in {}ms", decoy_length, delay);
                decoy_packet
            };

            if let Err(err) = manager_arc.send_packet(decoy_packet, true).await {
                debug!("SparseDecoyProvider: failed to send decoy packet: {:?}", err);
            }
        }
    }
}

impl<T: IdentityType, AE: AsyncExecutor, FM: FlowManager + Send + Sync> DecoyCommunicationMode<AE> for SparseDecoyProvider<T, AE, FM> {
    type FlowManagerT = FM;

    fn new(manager: Weak<Self::FlowManagerT>, settings: Arc<Settings<AE>>) -> Self {
        let state = DecoyState::new(settings.clone());
        let delay = Self::calculate_delay(&state);
        let length = Self::calculate_length(&state);
        let mut state = state;
        state.schedule_next(delay, length);

        debug!("SparseDecoyProvider initialized with delay ({delay} ms), length ({length} bytes)");

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
        debug!("SparseDecoyProvider: background timer started");
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
