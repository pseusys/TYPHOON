/// Heavy mode: sends big decoy packets occasionally, resembling file transfers or bulk updates.
use std::sync::{Arc, Weak};
use std::time::Duration;

use log::debug;

use crate::flow::decoy::common::{DecoyCommunicationMode, DecoyState, exponential_variance, random_uniform};
use crate::bytes::{ByteBuffer, DynamicByteBuffer};
use crate::flow::common::FlowManager;
use crate::settings::Settings;
use crate::settings::keys::*;
use crate::tailor::IdentityType;
use crate::utils::sync::{RwLock, sleep};
use crate::utils::time::unix_timestamp_ms;

/// Heavy mode implements sending big decoy packets occasionally.
pub struct HeavyDecoyProvider<'a, 'b, T: IdentityType + 'b, FM: FlowManager + 'b> {
    manager: Weak<FM>,
    state: Arc<RwLock<DecoyState<'a, 'b, T>>>,
}

impl<'a, 'b, T: IdentityType, FM: FlowManager> HeavyDecoyProvider<'a, 'b, T, FM> {
    fn calculate_delay(state: &DecoyState<'a, 'b, T>) -> u64 {
        let base_rate_rnd = state.settings.get(&DECOY_BASE_RATE_RND);
        let heavy_base_rate = state.settings.get(&DECOY_HEAVY_BASE_RATE);
        let quietness_factor = state.settings.get(&DECOY_HEAVY_QUIETNESS_FACTOR);
        let delay_min = state.settings.get(&DECOY_HEAVY_DELAY_MIN);
        let delay_max = state.settings.get(&DECOY_HEAVY_DELAY_MAX);
        let delay_default = state.settings.get(&DECOY_HEAVY_DELAY_DEFAULT);

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

    fn calculate_length(state: &DecoyState<'a, 'b, T>) -> usize {
        let base_length_factor = state.settings.get(&DECOY_HEAVY_BASE_LENGTH);
        let quietness_length = state.settings.get(&DECOY_HEAVY_QUIETNESS_LENGTH);
        let decoy_length_factor = state.settings.get(&DECOY_HEAVY_DECOY_LENGTH_FACTOR);

        let quietness = state.quietness_index();
        let base_length = (state.packet_length_cap as f64) * (base_length_factor + quietness_length * quietness);
        let decoy_length = random_uniform(decoy_length_factor * base_length, base_length);

        (decoy_length as usize).clamp(state.packet_length_cap / 2, state.packet_length_cap)
    }

    async fn timer_task(manager: Weak<FM>, state: Arc<RwLock<DecoyState<'a, 'b, T>>>) {
        loop {
            let delay = {
                let state_guard = state.read().await;
                let remaining = state_guard.next_decoy_time.saturating_sub(unix_timestamp_ms());
                Duration::from_millis(remaining as u64)
            };

            sleep(delay).await;

            let Some(manager_arc) = manager.upgrade() else {
                debug!("HeavyDecoyProvider: manager dropped, stopping timer");
                break;
            };

            let decoy_packet = {
                let mut state_guard = state.write().await;
                let decoy_length = state_guard.pending_length;
                let decoy_packet = state_guard.create_decoy_packet(decoy_length);

                let delay = Self::calculate_delay(&state_guard);
                let length = Self::calculate_length(&state_guard);
                state_guard.schedule_next(delay, length);

                debug!("HeavyDecoyProvider: generated decoy packet (len={}), next in {}ms", decoy_length, delay);
                decoy_packet
            };

            if let Err(err) = manager_arc.send_packet(decoy_packet, true).await {
                debug!("HeavyDecoyProvider: failed to send decoy packet: {:?}", err);
            }
        }
    }
}

impl<'a, 'b, T: IdentityType, FM: FlowManager + Send + Sync> DecoyCommunicationMode<'a, 'b> for HeavyDecoyProvider<'a, 'b, T, FM> {
    type FlowManagerT = FM;

    fn new(manager: Weak<Self::FlowManagerT>, settings: Arc<Settings<'a, 'b>>) -> Self {
        let state = DecoyState::new(settings.clone());
        let delay = Self::calculate_delay(&state);
        let length = Self::calculate_length(&state);
        let mut state = state;
        state.schedule_next(delay, length);

        debug!("HeavyDecoyProvider initialized with delay ({delay} ms), length ({length} bytes)");

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
        debug!("HeavyDecoyProvider: background timer started");
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
