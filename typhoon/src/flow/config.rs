use std::{
    cmp::{max, min},
    net::SocketAddr,
    ops::AddAssign,
};

use rand::distributions::Standard;
use rand::{Fill, Rng, RngCore, prelude::Distribution};

use crate::{
    bytes::ByteBuffer,
    flow::error::FlowControllerError,
    utils::{random::get_rng, socket::Socket, time::unix_timestamp_ms},
};

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
                    get_rng().gen_range(max(*min_length, body_space)..min(*max_length, body_space))
                } else {
                    0
                }
            }
            FakeBodyMode::Constant {
                packet_length,
            } => max(0, min(max_packet_size, *packet_length) - taken_packet_size),
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

    pub fn fill(&mut self, buffer: ByteBuffer) {
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
