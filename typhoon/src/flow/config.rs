#[cfg(test)]
#[path = "../../tests/flow/config.rs"]
mod tests;

use std::cmp::min;
use std::ops::AddAssign;

use rand::Rng;
use rand::distributions::Standard;
use rand::prelude::Distribution;

use crate::bytes::{ByteBufferMut, DynamicByteBuffer};
use crate::flow::error::FlowControllerError;
use crate::utils::random::get_rng;
use crate::utils::time::unix_timestamp_ms;

/// Fake body generation mode.
///
/// Each mode defines how fake body content is generated to pad packets.
/// Uses Vec<u8> internally for Sync compatibility.
#[derive(Debug, Clone)]
pub enum FakeBodyMode {
    /// Empty: no fake body added.
    Empty,
    /// Random: random bytes of random length (optionally service - only applied to service packets).
    Random {
        min_length: usize,
        max_length: usize,
        service: bool,
    },
    /// Constant: fixed content across all packets.
    Constant {
        packet_length: usize,
    },
}

impl FakeBodyMode {
    pub fn get_length(&self, max_packet_size: usize, taken_packet_size: usize, is_service: bool) -> usize {
        match self {
            FakeBodyMode::Empty => 0,
            FakeBodyMode::Random {
                min_length,
                max_length,
                service,
            } => {
                if !service || (is_service && *service) {
                    let body_space = max_packet_size - taken_packet_size;
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
/// Uses Vec<u8> internally for Sync compatibility.
#[derive(Debug, Clone)]
pub enum FieldType<L> {
    /// Random bytes on each packet.
    Random,
    /// Constant bytes across all packets.
    Constant {
        value: L,
    },
    /// Volatile: changes value randomly at random intervals.
    Volatile {
        value: L,
        change_probability: f64,
    },
    /// Switching: toggles between two values.
    Switching {
        value: L,
        next_switch: u128,
        switch_timeout: u64,
    },
    /// Incremental: counter that increases by 1 each packet.
    Incremental {
        value: L,
    },
}

impl<L: Copy + AddAssign<L> + From<u8>> FieldType<L> {
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
                    *next_switch = *switch_timeout as u128;
                    *value = get_rng().r#gen::<L>();
                }
                *value
            }
            FieldType::Incremental {
                value,
            } => {
                *value += L::from(1);
                *value
            }
        }
    }
}

#[derive(Debug, Clone)]
pub enum FieldTypeHolder {
    U8(FieldType<u8>),
    U16(FieldType<u16>),
    U32(FieldType<u32>),
    U64(FieldType<u64>),
}

/// Fake body generation mode.
///
/// Each mode defines how fake body content is generated to pad packets.
/// Uses Vec<u8> internally for Sync compatibility.
#[derive(Debug, Clone)]
pub struct FakeHeaderConfig {
    pattern: Vec<FieldTypeHolder>,
}

impl FakeHeaderConfig {
    pub fn new(pattern: Vec<FieldTypeHolder>) -> Self {
        Self {
            pattern,
        }
    }

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
    /// Whether to use fake bodies.
    pub(super) fake_body_mode: FakeBodyMode,
    /// Whether to use fake headers.
    pub(super) fake_header_mode: FakeHeaderConfig,
}

impl FlowConfig {
    pub fn new(fake_body_mode: FakeBodyMode, fake_header_mode: FakeHeaderConfig) -> Self {
        Self {
            fake_body_mode,
            fake_header_mode,
        }
    }

    /// Validate that the flow configuration is consistent with the given max packet size.
    pub fn assert(&self, max_packet_size: usize) -> Result<(), FlowControllerError> {
        match &self.fake_body_mode {
            FakeBodyMode::Constant {
                packet_length,
            } => {
                if *packet_length > max_packet_size {
                    return Err(FlowControllerError::AssertionFailed {
                        message: format!("constant fake body packet_length ({}) must not exceed max_packet_size ({})", packet_length, max_packet_size),
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
                        message: format!("random fake body min_length ({}) must be <= max_length ({})", min_length, max_length),
                    });
                }
            }
            FakeBodyMode::Empty => {}
        }

        let header_len = self.fake_header_mode.len();
        if header_len > max_packet_size {
            return Err(FlowControllerError::AssertionFailed {
                message: format!("fake header length ({}) must not exceed max_packet_size ({})", header_len, max_packet_size),
            });
        }

        Ok(())
    }
}
