/// Smooth mode: sends few average decoy packets during quiet periods, filling gaps between data packets.
use std::sync::{Arc, Weak};
use std::time::Duration;

use log::debug;

use crate::bytes::{ByteBuffer, DynamicByteBuffer};
use crate::flow::common::FlowManager;
use crate::flow::decoy::common::{DecoyCommunicationMode, DecoyState, maintenance_timer_task, random_uniform, try_replicate};
use crate::settings::Settings;
use crate::settings::keys::*;
use crate::tailor::IdentityType;
use crate::utils::sync::{AsyncExecutor, RwLock, sleep};
use crate::utils::time::unix_timestamp_ms;

/// Smooth mode implements sending few average decoy packets during quiet periods.
pub struct SmoothDecoyProvider<T: IdentityType + Clone + 'static, AE: AsyncExecutor + 'static, FM: FlowManager + 'static> {
    manager: Weak<FM>,
    state: Arc<RwLock<DecoyState<T, AE>>>,
}

impl<T: IdentityType + Clone, AE: AsyncExecutor, FM: FlowManager + Send + Sync + 'static> SmoothDecoyProvider<T, AE, FM> {
    fn calculate_delay(state: &DecoyState<T, AE>) -> u64 {
        let base_rate_rnd = state.settings.get(&DECOY_BASE_RATE_RND);
        let smooth_base_rate = state.settings.get(&DECOY_SMOOTH_BASE_RATE);
        let quietness_factor = state.settings.get(&DECOY_SMOOTH_QUIETNESS_FACTOR);
        let rate_factor = state.settings.get(&DECOY_SMOOTH_RATE_FACTOR);
        let jitter = state.settings.get(&DECOY_SMOOTH_JITTER);
        let delay_factor = state.settings.get(&DECOY_SMOOTH_DELAY_FACTOR);
        let delay_min = state.settings.get(&DECOY_SMOOTH_DELAY_MIN);
        let delay_max = state.settings.get(&DECOY_SMOOTH_DELAY_MAX);
        let delay_default = state.settings.get(&DECOY_SMOOTH_DELAY_DEFAULT);

        let base_rate = smooth_base_rate * random_uniform(1.0 - base_rate_rnd, 1.0 + base_rate_rnd);
        let quietness = state.quietness_index();
        let rate = base_rate * quietness.powf(quietness_factor) * (-rate_factor * state.packet_rate / state.reference_rate).exp();

        let delay = if rate > 0.0 {
            random_uniform(1.0 - jitter, 1.0 + jitter) * (1.0 + delay_factor * (state.packet_rate / state.reference_rate)) / rate
        } else {
            delay_default as f64
        };

        (delay as u64).clamp(delay_min, delay_max)
    }

    fn calculate_length(state: &DecoyState<T, AE>) -> usize {
        let length_min = state.settings.get(&DECOY_SMOOTH_LENGTH_MIN) as usize;
        let length_max = state.settings.get(&DECOY_SMOOTH_LENGTH_MAX) as usize;

        let quietness = state.quietness_index();
        let mean_length = (length_min as f64) + quietness * (-state.packet_rate / state.reference_rate).exp() * ((length_max - length_min) as f64);
        let decoy_length = random_uniform(length_min as f64, mean_length);

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
                debug!("SmoothDecoyProvider: manager dropped, stopping timer");
                break;
            };

            {
                let mut state_guard = state.write().await;
                let decoy_length = state_guard.pending_length;

                if state_guard.try_spend_budget(decoy_length) {
                    let decoy_packet = state_guard.create_decoy_packet(decoy_length, false);
                    let body_bytes: Vec<u8> = decoy_packet.slice_end(decoy_length).to_vec();
                    debug!("SmoothDecoyProvider: generated decoy packet (len={})", decoy_length);
                    drop(state_guard);

                    if let Err(err) = manager_arc.send_packet(decoy_packet, true).await {
                        debug!("SmoothDecoyProvider: failed to send decoy packet: {:?}", err);
                    } else {
                        try_replicate(&state, &manager, false, &body_bytes).await;
                    }
                } else {
                    debug!("SmoothDecoyProvider: insufficient byte budget for {} bytes, skipping", decoy_length);
                }
            }

            {
                let mut state_guard = state.write().await;
                let delay = Self::calculate_delay(&state_guard);
                let length = Self::calculate_length(&state_guard);
                state_guard.schedule_next(delay, length);
                debug!("SmoothDecoyProvider: next in {}ms", delay);
            }
        }
    }
}

impl<T: IdentityType + Clone, AE: AsyncExecutor, FM: FlowManager + Send + Sync + 'static> DecoyCommunicationMode<T, AE, FM> for SmoothDecoyProvider<T, AE, FM> {
    fn new(manager: Weak<FM>, settings: Arc<Settings<AE>>, identity: T) -> Self {
        let state = DecoyState::new(settings.clone(), identity);
        let delay = Self::calculate_delay(&state);
        let length = Self::calculate_length(&state);
        let mut state = state;
        state.schedule_next(delay, length);

        debug!("SmoothDecoyProvider initialized with delay ({delay} ms), length ({length} bytes)");

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
        debug!("SmoothDecoyProvider: background timers started");
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
