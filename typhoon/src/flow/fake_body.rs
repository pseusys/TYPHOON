use rand::Rng;

use crate::bytes::ByteBuffer;
use crate::constants::flow::{
    TYPHOON_FAKE_BODY_LENGTH_MAX, TYPHOON_FAKE_BODY_LENGTH_MIN, TYPHOON_FAKE_BODY_SERVICE_PROBABILITY,
};
use crate::random::get_rng;

/// Fake body generation mode.
///
/// Each mode defines how fake body content is generated to pad packets.
/// Uses Vec<u8> internally for Sync compatibility.
#[derive(Debug, Clone)]
pub enum FakeBodyMode {
    /// Empty: no fake body added.
    Empty,
    /// Random: random bytes of random length.
    Random {
        min_length: usize,
        max_length: usize,
    },
    /// Service: mimics service-like payload (e.g., HTTP headers).
    Service {
        templates: Vec<Vec<u8>>,
    },
    /// Constant: fixed content across all packets.
    Constant {
        value: Vec<u8>,
    },
}

impl FakeBodyMode {
    /// Create an empty mode.
    pub fn empty() -> Self {
        Self::Empty
    }

    /// Create a random mode with given length bounds.
    pub fn random(min_length: usize, max_length: usize) -> Self {
        Self::Random {
            min_length,
            max_length,
        }
    }

    /// Create a service mode with templates.
    pub fn service(templates: Vec<Vec<u8>>) -> Self {
        Self::Service { templates }
    }

    /// Create a constant mode.
    pub fn constant(value: Vec<u8>) -> Self {
        Self::Constant { value }
    }

    /// Create a constant mode from a ByteBuffer.
    pub fn constant_from_buffer(value: &ByteBuffer) -> Self {
        Self::Constant {
            value: value.slice().to_vec(),
        }
    }
}

/// Fake body generator.
///
/// Generates variable-length fake body content to pad packets.
pub struct FakeBodyGenerator {
    /// Current mode for body generation.
    mode: FakeBodyMode,
}

impl FakeBodyGenerator {
    /// Create a new fake body generator with the given mode.
    pub fn new(mode: FakeBodyMode) -> Self {
        Self { mode }
    }

    /// Create a generator with default random mode.
    pub fn default_random() -> Self {
        Self::new(FakeBodyMode::random(
            TYPHOON_FAKE_BODY_LENGTH_MIN,
            TYPHOON_FAKE_BODY_LENGTH_MAX,
        ))
    }

    /// Create a generator with default empty mode.
    pub fn default_empty() -> Self {
        Self::new(FakeBodyMode::Empty)
    }

    /// Get the current mode.
    pub fn mode(&self) -> &FakeBodyMode {
        &self.mode
    }

    /// Set the mode.
    pub fn set_mode(&mut self, mode: FakeBodyMode) {
        self.mode = mode;
    }

    /// Generate fake body content.
    ///
    /// Returns None if the mode is Empty.
    pub fn generate(&self) -> Option<ByteBuffer> {
        let mut rng = get_rng();

        match &self.mode {
            FakeBodyMode::Empty => None,
            FakeBodyMode::Random {
                min_length,
                max_length,
            } => {
                let length = rng.r#gen_range(*min_length..=*max_length);
                if length == 0 {
                    return None;
                }
                let buffer = ByteBuffer::empty(length);
                rng.fill(&mut buffer.slice_mut()[..]);
                Some(buffer)
            }
            FakeBodyMode::Service { templates } => {
                if templates.is_empty() {
                    return None;
                }
                // Higher probability for service-like content
                if rng.r#gen::<f64>() * TYPHOON_FAKE_BODY_SERVICE_PROBABILITY < 1.0 {
                    let idx = rng.r#gen_range(0..templates.len());
                    Some(ByteBuffer::from(templates[idx].clone()))
                } else {
                    None
                }
            }
            FakeBodyMode::Constant { value } => Some(ByteBuffer::from(value.clone())),
        }
    }

    /// Generate fake body and write directly to slice.
    ///
    /// Returns the number of bytes written.
    pub fn generate_into(&self, target: &mut [u8]) -> usize {
        let mut rng = get_rng();

        match &self.mode {
            FakeBodyMode::Empty => 0,
            FakeBodyMode::Random {
                min_length,
                max_length,
            } => {
                let max = (*max_length).min(target.len());
                if max < *min_length {
                    return 0;
                }
                let length = rng.r#gen_range(*min_length..=max);
                rng.fill(&mut target[..length]);
                length
            }
            FakeBodyMode::Service { templates } => {
                if templates.is_empty() {
                    return 0;
                }
                if rng.r#gen::<f64>() * TYPHOON_FAKE_BODY_SERVICE_PROBABILITY < 1.0 {
                    let idx = rng.r#gen_range(0..templates.len());
                    let template = &templates[idx];
                    let len = template.len().min(target.len());
                    target[..len].copy_from_slice(&template[..len]);
                    len
                } else {
                    0
                }
            }
            FakeBodyMode::Constant { value } => {
                let len = value.len().min(target.len());
                target[..len].copy_from_slice(&value[..len]);
                len
            }
        }
    }
}

impl Default for FakeBodyGenerator {
    fn default() -> Self {
        Self::default_random()
    }
}

// Safety: FakeBodyGenerator only contains Vec and primitive types
unsafe impl Send for FakeBodyGenerator {}
unsafe impl Sync for FakeBodyGenerator {}

#[cfg(test)]
#[path = "../../tests/flow/fake_body.rs"]
mod tests;
