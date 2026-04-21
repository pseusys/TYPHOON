/// Sparse mode: sends average decoy packets sparsely distributed in time, resembling VoIP or downloading.
use std::sync::{Arc, Weak};
use std::time::Duration;

use log::warn;

use crate::bytes::{ByteBuffer, DynamicByteBuffer};
use crate::flow::decoy::common::{DecoyCommunicationMode, DecoyFlowSender, DecoyState, maintenance_timer_task, random_gauss, random_uniform, try_replicate};
use crate::settings::Settings;
use crate::settings::keys::*;
use crate::tailor::IdentityType;
use crate::utils::sync::{AsyncExecutor, RwLock, sleep};
use crate::utils::unix_timestamp_ms;

/// Sparse mode implements sending average decoy packets sparsely distributed in time.
pub struct SparseDecoyProvider<T: IdentityType + Clone + 'static, AE: AsyncExecutor + 'static> {
    manager: Weak<dyn DecoyFlowSender>,
    state: Arc<RwLock<DecoyState<T, AE>>>,
}

impl<T: IdentityType + Clone, AE: AsyncExecutor> SparseDecoyProvider<T, AE> {
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

    async fn timer_task(manager: Weak<dyn DecoyFlowSender>, state: Arc<RwLock<DecoyState<T, AE>>>) {
        loop {
            let delay = {
                let state_guard = state.read().await;
                let remaining = state_guard.next_decoy_time.saturating_sub(unix_timestamp_ms());
                Duration::from_millis(remaining as u64)
            };

            sleep(delay).await;

            let Some(manager_arc) = manager.upgrade() else {
                warn!("SparseDecoyProvider: manager dropped, stopping timer");
                break;
            };

            {
                let mut state_guard = state.write().await;
                let decoy_length = state_guard.pending_length;

                if state_guard.try_spend_budget(decoy_length) {
                    let decoy_packet = state_guard.create_decoy_packet(decoy_length, false);
                    let should_rep = state_guard.should_replicate(false);
                    drop(state_guard);

                    // Allocate body bytes for replication only when actually needed (outside write lock).
                    let body_bytes = should_rep.then(|| decoy_packet.slice_end(decoy_length).to_vec());
                    if let Err(err) = manager_arc.send_decoy_packet(decoy_packet).await {
                        warn!("SparseDecoyProvider: failed to send decoy packet: {err:?}");
                    } else if let Some(bytes) = body_bytes {
                        try_replicate(&state, &manager, false, bytes).await;
                    }
                }
            }

            {
                let mut state_guard = state.write().await;
                let delay = Self::calculate_delay(&state_guard);
                let length = Self::calculate_length(&state_guard);
                state_guard.schedule_next(delay, length);
            }
        }
    }
}

impl<T: IdentityType + Clone, AE: AsyncExecutor> DecoyCommunicationMode<T, AE> for SparseDecoyProvider<T, AE> {
    fn new(manager: Weak<dyn DecoyFlowSender>, settings: Arc<Settings<AE>>, identity: T) -> Self {
        let state = DecoyState::new(settings.clone(), identity);
        let delay = Self::calculate_delay(&state);
        let length = Self::calculate_length(&state);
        let mut state = state;
        state.schedule_next(delay, length);

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
        executor.spawn(Self::timer_task(manager.clone(), state.clone()));
        executor.spawn(maintenance_timer_task(manager, state));
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
