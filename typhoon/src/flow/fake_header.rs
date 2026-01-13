use rand::Rng;

use crate::bytes::ByteBuffer;
use crate::constants::flow::{TYPHOON_FAKE_HEADER_LENGTH_MAX, TYPHOON_FAKE_HEADER_LENGTH_MIN};
use crate::random::get_rng;

/// Field type for fake header generation.
///
/// Each field type defines how a portion of the header is generated.
/// Uses Vec<u8> internally for Sync compatibility.
#[derive(Debug, Clone)]
pub enum FieldType {
    /// Random bytes on each packet.
    Random { length: usize },
    /// Constant bytes across all packets.
    Constant { value: Vec<u8> },
    /// Volatile: changes value randomly at random intervals.
    Volatile {
        length: usize,
        current_value: Vec<u8>,
        change_probability: f64,
    },
    /// Switching: toggles between two values.
    Switching {
        value_a: Vec<u8>,
        value_b: Vec<u8>,
        use_a: bool,
        switch_probability: f64,
    },
    /// Incremental: counter that increases by 1 each packet.
    Incremental { length: usize, current_value: u64 },
}

impl FieldType {
    /// Create a new random field.
    pub fn random(length: usize) -> Self {
        Self::Random { length }
    }

    /// Create a new constant field.
    pub fn constant(value: Vec<u8>) -> Self {
        Self::Constant { value }
    }

    /// Create a new constant field from a ByteBuffer.
    pub fn constant_from_buffer(value: &ByteBuffer) -> Self {
        Self::Constant {
            value: value.slice().to_vec(),
        }
    }

    /// Create a new volatile field.
    pub fn volatile(length: usize, change_probability: f64) -> Self {
        let mut rng = get_rng();
        let mut bytes = vec![0u8; length];
        rng.fill(&mut bytes[..]);
        Self::Volatile {
            length,
            current_value: bytes,
            change_probability,
        }
    }

    /// Create a new switching field.
    pub fn switching(value_a: Vec<u8>, value_b: Vec<u8>, switch_probability: f64) -> Self {
        Self::Switching {
            value_a,
            value_b,
            use_a: true,
            switch_probability,
        }
    }

    /// Create a new incremental field.
    pub fn incremental(length: usize, initial_value: u64) -> Self {
        Self::Incremental {
            length,
            current_value: initial_value,
        }
    }

    /// Get the length of this field in bytes.
    pub fn length(&self) -> usize {
        match self {
            Self::Random { length } => *length,
            Self::Constant { value } => value.len(),
            Self::Volatile { length, .. } => *length,
            Self::Switching { value_a, .. } => value_a.len(),
            Self::Incremental { length, .. } => *length,
        }
    }

    /// Generate the next value for this field and write it to the slice.
    pub fn generate_into(&mut self, target: &mut [u8]) {
        let mut rng = get_rng();

        match self {
            Self::Random { length } => {
                rng.fill(&mut target[..*length]);
            }
            Self::Constant { value } => {
                target[..value.len()].copy_from_slice(value);
            }
            Self::Volatile {
                length,
                current_value,
                change_probability,
            } => {
                // Maybe change the value
                if rng.r#gen::<f64>() < *change_probability {
                    let mut new_bytes = vec![0u8; *length];
                    rng.fill(&mut new_bytes[..]);
                    *current_value = new_bytes;
                }
                target[..*length].copy_from_slice(current_value);
            }
            Self::Switching {
                value_a,
                value_b,
                use_a,
                switch_probability,
            } => {
                // Maybe switch
                if rng.r#gen::<f64>() < *switch_probability {
                    *use_a = !*use_a;
                }
                let value = if *use_a { value_a } else { value_b };
                target[..value.len()].copy_from_slice(value);
            }
            Self::Incremental {
                length,
                current_value,
            } => {
                // Write value as big-endian
                let bytes = current_value.to_be_bytes();
                let start = 8 - *length;
                target[..*length].copy_from_slice(&bytes[start..]);
                *current_value = current_value.wrapping_add(1);
            }
        }
    }
}

/// Fake header generator.
///
/// Generates variable-length headers that obfuscate packet structure.
pub struct FakeHeaderGenerator {
    /// Fields that make up the header.
    fields: Vec<FieldType>,
    /// Total header length.
    total_length: usize,
    /// Whether to include a header (probability-based).
    include_probability: f64,
}

impl FakeHeaderGenerator {
    /// Create a new fake header generator with the given fields.
    pub fn new(fields: Vec<FieldType>, include_probability: f64) -> Self {
        let total_length = fields.iter().map(|f| f.length()).sum();
        Self {
            fields,
            total_length,
            include_probability,
        }
    }

    /// Create a generator with default random fields.
    pub fn default_random() -> Self {
        let mut rng = get_rng();
        let length = rng.r#gen_range(TYPHOON_FAKE_HEADER_LENGTH_MIN..=TYPHOON_FAKE_HEADER_LENGTH_MAX);
        Self::new(
            vec![FieldType::random(length)],
            crate::constants::flow::TYPHOON_FAKE_HEADER_PROBABILITY,
        )
    }

    /// Get the total header length.
    pub fn length(&self) -> usize {
        self.total_length
    }

    /// Check if this generator should include a header for the next packet.
    pub fn should_include(&self) -> bool {
        get_rng().r#gen::<f64>() < self.include_probability
    }

    /// Generate the header and write it to the buffer.
    ///
    /// Returns the number of bytes written.
    pub fn generate_into(&mut self, target: &mut [u8]) -> usize {
        if !self.should_include() {
            return 0;
        }

        let mut offset = 0;
        for field in &mut self.fields {
            let len = field.length();
            field.generate_into(&mut target[offset..offset + len]);
            offset += len;
        }
        offset
    }

    /// Generate a new header buffer.
    pub fn generate(&mut self) -> Option<ByteBuffer> {
        if !self.should_include() {
            return None;
        }

        let buffer = ByteBuffer::empty(self.total_length);
        let mut offset = 0;
        for field in &mut self.fields {
            let len = field.length();
            field.generate_into(&mut buffer.slice_mut()[offset..offset + len]);
            offset += len;
        }
        Some(buffer)
    }
}

// Safety: FakeHeaderGenerator only contains Vec and primitive types
unsafe impl Send for FakeHeaderGenerator {}
unsafe impl Sync for FakeHeaderGenerator {}

#[cfg(test)]
#[path = "../../tests/flow/fake_header.rs"]
mod tests;
