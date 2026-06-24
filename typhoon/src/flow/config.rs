//! Fake body and fake header generation: per-flow length/content modes and the runtime
//! distributions used to randomize them.

#[cfg(test)]
#[path = "../../tests/flow/config.rs"]
mod tests;

use std::cmp::min;

use log::info;
use rand::Rng;
use rand::distributions::Standard;
use rand::prelude::Distribution;

use crate::bytes::{ByteBufferMut, DynamicByteBuffer};
use crate::flow::error::FlowControllerError;
use crate::settings::{Settings, keys};
use crate::utils::random::get_rng;
use crate::utils::sync::AsyncExecutor;
use crate::utils::unix_timestamp_ms;
use crate::weighted_random;

/// Fake body generation mode.
///
/// Each mode defines how fake body content is generated to pad packets.
#[derive(Debug, Clone)]
pub enum FakeBodyMode {
    /// Empty: no fake body added.
    Empty,
    /// Random: random bytes of random length.
    Random {
        /// Lower clamp (bytes) for the sampled body length.
        min_length: usize,
        /// Upper clamp (bytes) for the sampled body length.
        max_length: usize,
        /// If `true`, only padded when the packet is a maintenance-substream decoy.
        service: bool,
    },
    /// Constant: fixed content across all packets.
    Constant {
        /// Total wire packet length (bytes) this mode pads every packet up to.
        packet_length: usize,
    },
}

impl FakeBodyMode {
    /// Human-readable description of this mode for capture log records.
    #[inline]
    pub(crate) fn description(&self) -> String {
        match self {
            FakeBodyMode::Empty => "Empty".to_string(),
            FakeBodyMode::Random {
                min_length,
                max_length,
                service,
            } => format!("Random({min_length}..{max_length},svc={service})"),
            FakeBodyMode::Constant {
                packet_length,
            } => format!("Constant({packet_length})"),
        }
    }

    /// Maximum fake body length this mode can produce — used to bound MTU calculations.
    pub fn max_len(&self) -> usize {
        match self {
            FakeBodyMode::Empty => 0,
            FakeBodyMode::Random {
                max_length,
                ..
            } => *max_length,
            FakeBodyMode::Constant {
                packet_length,
            } => *packet_length,
        }
    }

    /// Compute the fake body length for one packet, given the room left after the real
    /// payload/tailer (`max_packet_size - taken_packet_size`) and whether this packet is a
    /// maintenance-substream decoy (`is_service`).
    pub fn get_length(&self, max_packet_size: usize, taken_packet_size: usize, is_service: bool) -> usize {
        match self {
            FakeBodyMode::Empty => 0,
            FakeBodyMode::Random {
                min_length,
                max_length,
                service,
            } => {
                if !service || (is_service && *service) {
                    let body_space = max_packet_size.saturating_sub(taken_packet_size);
                    let effective_max = min(*max_length, body_space);
                    if effective_max <= *min_length {
                        effective_max
                    } else {
                        get_rng().gen_range(*min_length..effective_max)
                    }
                } else {
                    0
                }
            }
            FakeBodyMode::Constant {
                packet_length,
            } => min(max_packet_size, *packet_length).saturating_sub(taken_packet_size),
        }
    }
}

/// Field type for fake header generation.
///
/// Each field type defines how a portion of the header is generated.
#[derive(Debug, Clone)]
pub enum FieldType<L> {
    /// Random bytes on each packet.
    Random,
    /// Constant bytes across all packets.
    Constant {
        /// The fixed value written into every packet.
        value: L,
    },
    /// Volatile: changes value randomly at random intervals.
    Volatile {
        /// The current value, held until the next change.
        value: L,
        /// Per-packet probability of resampling `value`.
        change_probability: f64,
    },
    /// Switching: toggles between two values.
    Switching {
        /// The current value, held until `next_switch`.
        value: L,
        /// Unix timestamp (milliseconds) at which `value` will next be resampled.
        next_switch: u128,
        /// Interval (milliseconds) between switches, re-applied each time `next_switch` elapses.
        switch_timeout: u64,
    },
    /// Incremental: counter that increases by 1 each packet.
    Incremental {
        /// The current counter value.
        value: L,
    },
}

trait WrappingIncrement: Copy {
    fn wrapping_inc(self) -> Self;
}
macro_rules! impl_wrapping_increment {
    ($($t:ty)*) => { $(
        impl WrappingIncrement for $t {
            #[inline] fn wrapping_inc(self) -> Self { self.wrapping_add(1) }
        }
    )* };
}
impl_wrapping_increment!(u8 u16 u32 u64);

#[allow(private_bounds)]
impl<L: Copy + WrappingIncrement> FieldType<L> {
    /// Advance this field by one packet and return the value to write into the wire header.
    pub fn apply(&mut self) -> L
    where
        Standard: Distribution<L>,
    {
        match self {
            FieldType::Random => get_rng().r#gen::<L>(),
            FieldType::Constant {
                value,
            } => *value,
            FieldType::Volatile {
                value,
                change_probability,
            } => {
                if get_rng().r#gen::<f64>() > *change_probability {
                    *value = get_rng().r#gen::<L>();
                }
                *value
            }
            FieldType::Switching {
                value,
                next_switch,
                switch_timeout,
            } => {
                if unix_timestamp_ms() > *next_switch {
                    *next_switch = unix_timestamp_ms() + *switch_timeout as u128;
                    *value = get_rng().r#gen::<L>();
                }
                *value
            }
            FieldType::Incremental {
                value,
            } => {
                *value = value.wrapping_inc();
                *value
            }
        }
    }
}

/// A [`FieldType`] erased over its primitive integer width, so a [`FakeHeaderConfig`] can mix
/// fields of different sizes in one pattern.
#[derive(Debug, Clone)]
pub enum FieldTypeHolder {
    /// A 1-byte field.
    U8(FieldType<u8>),
    /// A 2-byte field.
    U16(FieldType<u16>),
    /// A 4-byte field.
    U32(FieldType<u32>),
    /// An 8-byte field.
    U64(FieldType<u64>),
}

/// Fake header field layout for one flow: an ordered sequence of fields, each independently
/// evolving per [`FieldType`].
#[derive(Debug, Clone)]
pub struct FakeHeaderConfig {
    pattern: Vec<FieldTypeHolder>,
}

impl FakeHeaderConfig {
    /// Build a fake header config from an explicit field pattern.
    pub fn new(pattern: Vec<FieldTypeHolder>) -> Self {
        Self {
            pattern,
        }
    }

    /// Create a random header configuration drawn from the default probability distributions.
    ///
    /// Includes a header with probability `FAKE_HEADER_PROBABILITY`; if included, a random number
    /// of fields are packed to fill a length sampled from `[FAKE_HEADER_LENGTH_MIN, FAKE_HEADER_LENGTH_MAX]`.
    /// Each field is independently assigned one of the five `FieldType` variants weighted by the
    /// `FAKE_HEADER_FIELD_WEIGHT_*` settings.
    pub fn random<AE: AsyncExecutor>(settings: &Settings<AE>) -> Self {
        let mut rng = get_rng();
        let header_prob = settings.get(&keys::FAKE_HEADER_PROBABILITY);
        if rng.r#gen::<f64>() < header_prob {
            let min_len = settings.get(&keys::FAKE_HEADER_LENGTH_MIN) as usize;
            let max_len = settings.get(&keys::FAKE_HEADER_LENGTH_MAX) as usize;
            let len = if min_len >= max_len {
                max_len
            } else {
                rng.gen_range(min_len..=max_len)
            };
            let volatile_prob_min = settings.get(&keys::FAKE_HEADER_VOLATILE_CHANGE_PROB_MIN);
            let volatile_prob_max = settings.get(&keys::FAKE_HEADER_VOLATILE_CHANGE_PROB_MAX);
            let switching_timeout_min = settings.get(&keys::FAKE_HEADER_SWITCHING_TIMEOUT_MIN_MS);
            let switching_timeout_max = settings.get(&keys::FAKE_HEADER_SWITCHING_TIMEOUT_MAX_MS);
            let fields = (0..len)
                .map(|_| {
                    FieldTypeHolder::U8(weighted_random! {
                        settings.get(&keys::FAKE_HEADER_FIELD_WEIGHT_RANDOM) => FieldType::Random,
                        settings.get(&keys::FAKE_HEADER_FIELD_WEIGHT_CONSTANT) => FieldType::Constant {
                            value: rng.r#gen::<u8>(),
                        },
                        settings.get(&keys::FAKE_HEADER_FIELD_WEIGHT_VOLATILE) => FieldType::Volatile {
                            value: rng.r#gen::<u8>(),
                            change_probability: rng.gen_range(volatile_prob_min..=volatile_prob_max),
                        },
                        settings.get(&keys::FAKE_HEADER_FIELD_WEIGHT_SWITCHING) => {
                            let switch_timeout = rng.gen_range(switching_timeout_min..=switching_timeout_max);
                            FieldType::Switching {
                                value: rng.r#gen::<u8>(),
                                next_switch: unix_timestamp_ms() + switch_timeout as u128,
                                switch_timeout,
                            }
                        }
                        settings.get(&keys::FAKE_HEADER_FIELD_WEIGHT_INCREMENTAL) => FieldType::Incremental {
                            value: rng.r#gen::<u8>(),
                        },
                    })
                })
                .collect();
            Self::new(fields)
        } else {
            Self::new(vec![])
        }
    }

    /// Total wire length (bytes) of this header pattern.
    pub fn len(&self) -> usize {
        self.pattern.iter().fold(0, |a, f| {
            a + match f {
                FieldTypeHolder::U8(_) => size_of::<u8>(),
                FieldTypeHolder::U16(_) => size_of::<u16>(),
                FieldTypeHolder::U32(_) => size_of::<u32>(),
                FieldTypeHolder::U64(_) => size_of::<u64>(),
            }
        })
    }

    /// `true` if this pattern has no fields (no fake header is emitted for this flow).
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Advance every field by one packet and write the resulting bytes into `buffer`.
    pub fn fill(&mut self, buffer: DynamicByteBuffer) {
        self.pattern.iter_mut().fold(0, |a, f| {
            a + match f {
                FieldTypeHolder::U8(holder) => {
                    buffer.set(a, holder.apply());
                    size_of::<u8>()
                }
                FieldTypeHolder::U16(holder) => {
                    let holder_size = size_of::<u16>();
                    let field_slice = buffer.rebuffer_both(a, a + holder_size);
                    field_slice.slice_mut().copy_from_slice(&holder.apply().to_be_bytes());
                    holder_size
                }
                FieldTypeHolder::U32(holder) => {
                    let holder_size = size_of::<u32>();
                    let field_slice = buffer.rebuffer_both(a, a + holder_size);
                    field_slice.slice_mut().copy_from_slice(&holder.apply().to_be_bytes());
                    holder_size
                }
                FieldTypeHolder::U64(holder) => {
                    let holder_size = size_of::<u64>();
                    let field_slice = buffer.rebuffer_both(a, a + holder_size);
                    field_slice.slice_mut().copy_from_slice(&holder.apply().to_be_bytes());
                    holder_size
                }
            }
        });
    }
}

/// Configuration for a flow.
#[derive(Debug, Clone)]
pub struct FlowConfig {
    /// Fake body generation mode for this flow.
    pub(super) fake_body_mode: FakeBodyMode,
    /// Fake header field layout for this flow.
    pub(super) fake_header_mode: FakeHeaderConfig,
}

impl FlowConfig {
    /// Build a flow configuration from explicit fake-body and fake-header settings.
    pub fn new(fake_body_mode: FakeBodyMode, fake_header_mode: FakeHeaderConfig) -> Self {
        Self {
            fake_body_mode,
            fake_header_mode,
        }
    }

    /// Create a random flow configuration drawn from the default probability distributions.
    ///
    /// - Headers: included with probability `FAKE_HEADER_PROBABILITY`; if included, a random number
    ///   of fields are packed to fill a length sampled from
    ///   `[FAKE_HEADER_LENGTH_MIN, FAKE_HEADER_LENGTH_MAX]`.
    /// - Body: chosen by the `FAKE_BODY_WEIGHT_*` settings (Empty / Random / Constant / Random{service}).
    ///   In `Constant` mode `packet_length` is sampled **once at flow init** from
    ///   `[FAKE_BODY_CONSTANT_LENGTH_MIN, FAKE_BODY_CONSTANT_LENGTH_MAX]` (clamped to
    ///   `[FAKE_BODY_LENGTH_MIN, mtu]`) and then held constant for every packet
    ///   in that flow — different flows get different constants, breaking the
    ///   sharp single-mode wire-size spike that a global fixed-length Constant
    ///   would produce.
    pub fn random<AE: AsyncExecutor>(settings: &Settings<AE>) -> Self {
        let fake_header_mode = FakeHeaderConfig::random(settings);

        let min_len = settings.get(&keys::FAKE_BODY_LENGTH_MIN) as usize;
        let max_len = settings.get(&keys::FAKE_BODY_LENGTH_MAX) as usize;

        let constant_min = (settings.get(&keys::FAKE_BODY_CONSTANT_LENGTH_MIN) as usize).clamp(min_len, settings.mtu());
        let constant_max = (settings.get(&keys::FAKE_BODY_CONSTANT_LENGTH_MAX) as usize).clamp(min_len, settings.mtu());
        let constant_length = if constant_min >= constant_max {
            constant_min
        } else {
            get_rng().gen_range(constant_min..=constant_max)
        };

        let fake_body_mode = weighted_random! {
            settings.get(&keys::FAKE_BODY_WEIGHT_EMPTY) => FakeBodyMode::Empty,
            settings.get(&keys::FAKE_BODY_WEIGHT_RANDOM) => FakeBodyMode::Random {
                    min_length: min_len,
                    max_length: max_len,
                    service: false,
            },
            settings.get(&keys::FAKE_BODY_WEIGHT_CONSTANT) => FakeBodyMode::Constant {
                packet_length: constant_length,
            },
            settings.get(&keys::FAKE_BODY_WEIGHT_SERVICE) => FakeBodyMode::Random {
                min_length: min_len,
                max_length: max_len,
                service: true,
            }
        };

        info!("flow_config: fake_body={:?}, fake_header_len={}", fake_body_mode, fake_header_mode.len());
        Self {
            fake_body_mode,
            fake_header_mode,
        }
    }

    /// Maximum bytes this flow config can prepend to a packet (fake header + worst-case fake body).
    /// Used to reserve `before_capacity` in packet buffers. Conservative for Constant mode.
    pub fn max_overhead(&self) -> usize {
        self.fake_header_mode.len() + self.fake_body_mode.max_len()
    }

    /// Maximum user-data bytes per packet given MTU and the per-packet crypto/tailer overhead.
    /// For Constant mode the wire size is fixed to `packet_length`, so the data budget is
    /// `min(packet_length, mtu) - (fake_header + crypto + tailer)`.
    /// For other modes it is `mtu - (fake_header + fake_body_max + crypto + tailer)`.
    pub fn max_user_payload(&self, mtu: usize, crypto_overhead: usize, tailer_len: usize) -> usize {
        let fixed = self.fake_header_mode.len() + crypto_overhead + tailer_len;
        match &self.fake_body_mode {
            FakeBodyMode::Constant {
                packet_length,
            } => packet_length.min(&mtu).saturating_sub(fixed),
            _ => mtu.saturating_sub(self.max_overhead() + crypto_overhead + tailer_len),
        }
    }

    /// Validate that the flow configuration is consistent with the given max packet size.
    ///
    /// # Errors
    ///
    /// Returns [`FlowControllerError::AssertionFailed`] if the fake body or fake header
    /// configuration is internally inconsistent or exceeds `max_packet_size`.
    pub fn assert(&self, max_packet_size: usize) -> Result<(), FlowControllerError> {
        match &self.fake_body_mode {
            FakeBodyMode::Constant {
                packet_length,
            } => {
                if *packet_length > max_packet_size {
                    return Err(FlowControllerError::AssertionFailed {
                        message: format!("constant fake body packet_length ({packet_length}) must not exceed max_packet_size ({max_packet_size})"),
                    });
                }
            }
            FakeBodyMode::Random {
                min_length,
                max_length,
                ..
            } => {
                if min_length > max_length {
                    return Err(FlowControllerError::AssertionFailed {
                        message: format!("random fake body min_length ({min_length}) must be <= max_length ({max_length})"),
                    });
                }
            }
            FakeBodyMode::Empty => {}
        }

        let header_len = self.fake_header_mode.len();
        if header_len > max_packet_size {
            return Err(FlowControllerError::AssertionFailed {
                message: format!("fake header length ({header_len}) must not exceed max_packet_size ({max_packet_size})"),
            });
        }

        Ok(())
    }
}
