/// Heavy mode: sends large decoy packets at a low cadence (~0.1 pkt/s base, capped at 0.2 pkt/s), resembling background heartbeat / metric-push / software-update-poll traffic.
use std::sync::atomic::AtomicU32;
use std::sync::{Arc, Weak};
use std::time::Duration;

use async_trait::async_trait;
use log::warn;

use crate::bytes::{ByteBuffer, DynamicByteBuffer};
use crate::cache::DerivedValue;
use crate::flow::decoy::common::{DecoyCommunicationMode, DecoyFlowSender, DecoyProvider, DecoyState, exponential_variance, maintenance_timer_task, random_uniform, try_replicate};
use crate::settings::Settings;
use crate::settings::consts::FG_OFFSET;
use crate::settings::keys::*;
use crate::tailor::{IdentityType, PacketFlags};
use crate::utils::sync::{AsyncExecutor, RwLock, sleep};
use crate::utils::unix_timestamp_ms;

/// Heavy mode implements sending large decoy packets at a low cadence (background-heartbeat shape).
pub struct HeavyDecoyProvider<T: IdentityType + Clone + 'static, AE: AsyncExecutor + 'static> {
    manager: Weak<dyn DecoyFlowSender>,
    state: Arc<RwLock<DecoyState<T, AE>>>,
}

impl<T: IdentityType + Clone, AE: AsyncExecutor> HeavyDecoyProvider<T, AE> {
    fn calculate_delay(state: &DecoyState<T, AE>) -> u64 {
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
            exponential_variance(rate) * 1000.0
        } else {
            delay_default as f64
        };

        (delay as u64).clamp(delay_min, delay_max)
    }

    pub(crate) fn calculate_length(state: &DecoyState<T, AE>) -> usize {
        let base_length_factor = state.settings.get(&DECOY_HEAVY_BASE_LENGTH);
        let quietness_length = state.settings.get(&DECOY_HEAVY_QUIETNESS_LENGTH);
        let decoy_length_factor = state.settings.get(&DECOY_HEAVY_DECOY_LENGTH_FACTOR);
        let length_min = state.settings.get(&DECOY_HEAVY_LENGTH_MIN) as usize;

        let quietness = state.quietness_index();
        let base_length = (state.packet_length_cap as f64) * (base_length_factor + quietness_length * quietness);
        let decoy_length = random_uniform(decoy_length_factor * base_length, base_length);

        (decoy_length as usize).clamp(length_min, state.packet_length_cap)
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
                warn!("HeavyDecoyProvider: manager dropped, stopping timer");
                break;
            };

            {
                let mut state_guard = state.write().await;
                let decoy_length = state_guard.pending_length;

                if state_guard.try_spend_budget(decoy_length) {
                    let decoy_packet = state_guard.create_decoy_packet(decoy_length, false);
                    let should_rep = state_guard.should_replicate(false);
                    let fallthrough = state_guard.should_fallthrough();
                    let settings = Arc::clone(&state_guard.settings);
                    drop(state_guard);

                    let body_buf = should_rep.then(|| settings.pool().allocate_precise_from_slice_with_capacity(decoy_packet.slice_end(decoy_length), 0, 0));
                    if let Err(err) = manager_arc.send_decoy_packet(decoy_packet, fallthrough, false).await {
                        warn!("HeavyDecoyProvider: failed to send decoy packet: {err:?}");
                    } else if let Some(body) = body_buf {
                        try_replicate(&state, &manager, false, body).await;
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

#[async_trait]
impl<T: IdentityType + Clone + 'static, AE: AsyncExecutor + 'static> DecoyProvider for HeavyDecoyProvider<T, AE> {
    #[inline]
    fn name(&self) -> &'static str {
        "HeavyDecoyProvider"
    }

    async fn start(&self) {
        let executor = {
            let lock = self.state.read().await;
            lock.settings.executor().clone()
        };

        let manager = self.manager.clone();
        let state = self.state.clone();
        executor.spawn(Self::timer_task(manager.clone(), state.clone()));
        executor.spawn(maintenance_timer_task(manager, state));
    }

    async fn feed_input(&self, packet: DynamicByteBuffer, _tailor_buf: DynamicByteBuffer) -> Option<DynamicByteBuffer> {
        let mut state = self.state.write().await;
        state.update(packet.len(), false);
        Some(packet)
    }

    async fn feed_output(&self, body: DynamicByteBuffer, tailor_buf: DynamicByteBuffer) -> Option<DynamicByteBuffer> {
        let flags = PacketFlags::from_bits_truncate(*tailor_buf.get(FG_OFFSET));
        if !flags.is_discardable() {
            let mut state = self.state.write().await;
            state.update(body.len() + tailor_buf.len(), true);
        }
        Some(body)
    }
}

impl<T: IdentityType + Clone, AE: AsyncExecutor> DecoyCommunicationMode<T, AE> for HeavyDecoyProvider<T, AE> {
    fn new(manager: Weak<dyn DecoyFlowSender>, settings: Arc<Settings<AE>>, identity: DerivedValue<T>, counter: Arc<AtomicU32>, fallthrough_probability: Option<f64>) -> Self {
        let state = DecoyState::new(settings.clone(), identity, counter, fallthrough_probability);
        let delay = Self::calculate_delay(&state);
        let length = Self::calculate_length(&state);
        let mut state = state;
        state.schedule_next(delay, length);

        Self {
            manager,
            state: Arc::new(RwLock::new(state)),
        }
    }
}
