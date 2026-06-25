//! Maintenance, replication, and subheader feature configuration for decoy traffic, plus the
//! background tasks that drive them. [`DecoyFeatureConfig`] is randomized once per `DecoyState`
//! at construction; `maintenance_timer_task` and `try_replicate` are spawned independently of the
//! per-mode decoy timer and operate directly on the shared state from [`super::common`].

#[cfg(test)]
#[path = "../../../tests/flow/decoy/features.rs"]
mod tests;

use std::sync::{Arc, Weak};
use std::time::Duration;

use log::{debug, info, warn};
use rand::Rng;
use rand::seq::SliceRandom;
use rand_distr::Distribution;

use super::common::{DecoyFlowSender, DecoyState, random_uniform};
use crate::bytes::{ByteBuffer, DynamicByteBuffer};
use crate::flow::config::{FakeHeaderConfig, FieldType, FieldTypeHolder};
use crate::settings::Settings;
use crate::settings::keys::*;
use crate::tailer::IdentityType;
use crate::utils::random::get_rng;
use crate::utils::sync::{AsyncExecutor, RwLock, sleep};
use crate::utils::unix_timestamp_ms;
use crate::weighted_random;

// ── Mode enums ──────────────────────────────────────────────────────────────

/// Maintenance mode for decoy packets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum MaintenanceMode {
    None,
    Random,
    Timed {
        delay_ms: u64,
    },
    Sized {
        length: usize,
    },
    Both {
        delay_ms: u64,
        length: usize,
    },
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
    /// Randomly select maintenance, replication, and subheader settings, weighted by the
    /// `DECOY_MAINTENANCE_WEIGHT_*` / `DECOY_REPLICATION_WEIGHT_*` / `DECOY_SUBHEADER_WEIGHT_*` keys.
    pub(super) fn random<AE: AsyncExecutor>(settings: &Settings<AE>) -> Self {
        let mut rng = get_rng();

        let delay_min = settings.get(&DECOY_MAINTENANCE_DELAY_MIN);
        let delay_max = settings.get(&DECOY_MAINTENANCE_DELAY_MAX);
        let length_min = settings.get(&DECOY_MAINTENANCE_LENGTH_MIN) as usize;
        let length_max = settings.get(&DECOY_MAINTENANCE_LENGTH_MAX) as usize;
        let fixed_delay = rng.gen_range(delay_min..=delay_max);
        let fixed_length = rng.gen_range(length_min..=length_max);

        // Maintenance mode: weights from settings (None heavier by default).
        let maintenance_mode = weighted_random! {
            settings.get(&DECOY_MAINTENANCE_WEIGHT_NONE) => MaintenanceMode::None,
            settings.get(&DECOY_MAINTENANCE_WEIGHT_RANDOM) => MaintenanceMode::Random,
            settings.get(&DECOY_MAINTENANCE_WEIGHT_TIMED) => MaintenanceMode::Timed {
                delay_ms: fixed_delay,
            },
            settings.get(&DECOY_MAINTENANCE_WEIGHT_SIZED) => MaintenanceMode::Sized {
                length: fixed_length,
            },
            settings.get(&DECOY_MAINTENANCE_WEIGHT_BOTH) => MaintenanceMode::Both {
                delay_ms: fixed_delay,
                length: fixed_length,
            },
        };

        // Replication mode: weights from settings (None heavier by default).
        let replication_mode = weighted_random! {
            settings.get(&DECOY_REPLICATION_WEIGHT_NONE) => ReplicationMode::None,
            settings.get(&DECOY_REPLICATION_WEIGHT_MAINTENANCE) => ReplicationMode::Maintenance,
            settings.get(&DECOY_REPLICATION_WEIGHT_ALL) => ReplicationMode::All,
        };

        let prob_min = settings.get(&DECOY_REPLICATION_PROBABILITY_MIN);
        let prob_max = settings.get(&DECOY_REPLICATION_PROBABILITY_MAX);
        let replication_probability = rng.gen_range(prob_min..=prob_max);

        // Subheader mode: weights from settings.
        let subheader_mode = weighted_random! {
            settings.get(&DECOY_SUBHEADER_WEIGHT_NONE) => SubheaderMode::None,
            settings.get(&DECOY_SUBHEADER_WEIGHT_MAINTENANCE) => SubheaderMode::Maintenance,
            settings.get(&DECOY_SUBHEADER_WEIGHT_ALL) => SubheaderMode::All,
        };

        let subheader_config = if subheader_mode == SubheaderMode::None {
            None
        } else {
            let min_len = settings.get(&DECOY_SUBHEADER_LENGTH_MIN) as usize;
            let max_len = settings.get(&DECOY_SUBHEADER_LENGTH_MAX) as usize;
            Some(generate_random_fake_header(settings, min_len, max_len))
        };

        info!("decoy feature config: maintenance={maintenance_mode:?}, replication={replication_mode:?}, replication_prob={replication_probability:.4}, subheader={subheader_mode:?}");

        Self {
            maintenance_mode,
            replication_mode,
            replication_probability,
            subheader_mode,
            subheader_config,
        }
    }
}

/// Generate a random `FakeHeaderConfig` with total byte length in [`min_len`, `max_len`].
pub(super) fn generate_random_fake_header<AE: AsyncExecutor>(settings: &Settings<AE>, min_len: usize, max_len: usize) -> FakeHeaderConfig {
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
            1 => FieldTypeHolder::U8(random_field_type(settings, &mut rng)),
            2 => FieldTypeHolder::U16(random_field_type(settings, &mut rng)),
            4 => FieldTypeHolder::U32(random_field_type(settings, &mut rng)),
            8 => FieldTypeHolder::U64(random_field_type(settings, &mut rng)),
            _ => unreachable!(),
        };
        fields.push(field);
        current_len += size;
    }

    FakeHeaderConfig::new(fields)
}

/// Generate a random `FieldType` variant weighted by the `FAKE_HEADER_FIELD_WEIGHT_*` settings.
fn random_field_type<AE: AsyncExecutor, L: Copy + From<u8>>(settings: &Settings<AE>, rng: &mut impl Rng) -> FieldType<L>
where
    rand::distributions::Standard: Distribution<L>,
{
    let volatile_prob_min = settings.get(&FAKE_HEADER_VOLATILE_CHANGE_PROB_MIN);
    let volatile_prob_max = settings.get(&FAKE_HEADER_VOLATILE_CHANGE_PROB_MAX);
    let switching_timeout_min = settings.get(&FAKE_HEADER_SWITCHING_TIMEOUT_MIN_MS);
    let switching_timeout_max = settings.get(&FAKE_HEADER_SWITCHING_TIMEOUT_MAX_MS);
    weighted_random! {
        settings.get(&FAKE_HEADER_FIELD_WEIGHT_RANDOM) => FieldType::Random,
        settings.get(&FAKE_HEADER_FIELD_WEIGHT_CONSTANT) => FieldType::Constant {
            value: rng.r#gen::<L>(),
        },
        settings.get(&FAKE_HEADER_FIELD_WEIGHT_VOLATILE) => FieldType::Volatile {
            value: rng.r#gen::<L>(),
            change_probability: rng.gen_range(volatile_prob_min..=volatile_prob_max),
        },
        settings.get(&FAKE_HEADER_FIELD_WEIGHT_SWITCHING) => {
            let switch_timeout = rng.gen_range(switching_timeout_min..=switching_timeout_max);
            FieldType::Switching {
                value: rng.r#gen::<L>(),
                next_switch: unix_timestamp_ms() + switch_timeout as u128,
                switch_timeout,
            }
        },
        settings.get(&FAKE_HEADER_FIELD_WEIGHT_INCREMENTAL) => FieldType::Incremental {
            value: rng.r#gen::<L>(),
        }
    }
}

// ── Maintenance / Replication helpers ───────────────────────────────────────

/// Get maintenance delay for the given mode.
pub(super) fn maintenance_delay_for<AE: AsyncExecutor>(mode: &MaintenanceMode, settings: &Settings<AE>) -> u64 {
    match *mode {
        MaintenanceMode::Timed {
            delay_ms,
        }
        | MaintenanceMode::Both {
            delay_ms,
            ..
        } => delay_ms,
        _ => {
            let min = settings.get(&DECOY_MAINTENANCE_DELAY_MIN);
            let max = settings.get(&DECOY_MAINTENANCE_DELAY_MAX);
            random_uniform(min as f64, max as f64) as u64
        }
    }
}

/// Get maintenance packet length for the given mode.
pub(super) fn maintenance_length_for<AE: AsyncExecutor>(mode: &MaintenanceMode, settings: &Settings<AE>) -> usize {
    match *mode {
        MaintenanceMode::Sized {
            length,
        }
        | MaintenanceMode::Both {
            length,
            ..
        } => length,
        _ => {
            let min = settings.get(&DECOY_MAINTENANCE_LENGTH_MIN) as usize;
            let max = settings.get(&DECOY_MAINTENANCE_LENGTH_MAX) as usize;
            random_uniform(min as f64, max as f64) as usize
        }
    }
}

/// Background maintenance timer task. Runs independently of the communication mode timer.
/// Returns immediately if maintenance mode is `None`.
pub(super) async fn maintenance_timer_task<T, AE>(manager: Weak<dyn DecoyFlowSender>, state: Arc<RwLock<DecoyState<T, AE>>>)
where
    T: IdentityType + Clone + 'static,
    AE: AsyncExecutor + 'static,
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
            warn!("Maintenance timer: manager dropped, stopping");
            break;
        };

        let (packet, body_length, should_rep, fallthrough, settings) = {
            let mut guard = state.write().await;
            let length = guard.pending_maintenance_length;

            if !guard.try_spend_budget(length) {
                guard.schedule_next_maintenance();
                continue;
            }

            let packet = guard.create_decoy_packet(length, true);
            let should_rep = guard.should_replicate(true);
            let fallthrough = guard.should_fallthrough();
            let settings = Arc::clone(&guard.settings);
            (packet, length, should_rep, fallthrough, settings)
        };

        let body_buf = should_rep.then(|| settings.pool().allocate_precise_from_slice_with_capacity(packet.slice_end(body_length), 0, 0));

        debug!("Maintenance: generated packet (len={body_length})");

        if let Err(err) = manager_arc.send_decoy_packet(packet, fallthrough, true).await {
            warn!("Maintenance: failed to send: {err:?}");
        } else if let Some(body) = body_buf {
            try_replicate(&state, &manager, true, body).await;
        }

        {
            let mut guard = state.write().await;
            guard.schedule_next_maintenance();
        }
    }
}

/// Attempt replication of a decoy packet. If replication mode applies, spawns a cascading
/// task that re-sends the packet body with diminishing probability.
pub(super) async fn try_replicate<T, AE>(state: &Arc<RwLock<DecoyState<T, AE>>>, manager: &Weak<dyn DecoyFlowSender>, is_maintenance: bool, body: DynamicByteBuffer)
where
    T: IdentityType + Clone + 'static,
    AE: AsyncExecutor + 'static,
{
    let (probability, delay_min, delay_max, reduce, executor) = {
        let guard = state.read().await;
        if !guard.should_replicate(is_maintenance) {
            return;
        }
        (guard.features.replication_probability, guard.settings.get(&DECOY_REPLICATION_DELAY_MIN), guard.settings.get(&DECOY_REPLICATION_DELAY_MAX), guard.settings.get(&DECOY_REPLICATION_PROBABILITY_REDUCE), guard.settings.executor().clone())
    };

    let state_clone = Arc::clone(state);
    let manager_clone = manager.clone();

    executor.spawn(async move {
        let mut current_probability = probability;
        loop {
            if get_rng().r#gen::<f64>() >= current_probability {
                break;
            }

            let delay = random_uniform(delay_min as f64, delay_max as f64) as u64;
            sleep(Duration::from_millis(delay)).await;

            let Some(manager_arc) = manager_clone.upgrade() else {
                break;
            };

            let (packet, fallthrough) = {
                let mut guard = state_clone.write().await;
                if !guard.try_spend_budget(body.slice().len()) {
                    break;
                }
                let replica = guard.create_replica_packet(body.slice(), is_maintenance);
                (replica, guard.should_fallthrough())
            };

            if manager_arc.send_decoy_packet(packet, fallthrough, is_maintenance).await.is_err() {
                break;
            }

            current_probability /= reduce;
        }
    });
}
