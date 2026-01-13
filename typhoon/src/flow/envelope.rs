use crate::bytes::ByteBuffer;
use crate::error::{TyphoonError, TyphoonResult};
use crate::tailor::ENCRYPTED_TAILOR_SIZE;

/// Envelope structure for TYPHOON packets.
///
/// An envelope wraps the encrypted payload with obfuscation layers:
/// - Optional fake header (prepended)
/// - Encrypted payload
/// - Encrypted tailor (appended)
/// - Optional fake body (appended)
///
/// Layout: [fake_header?] || [encrypted_payload] || [encrypted_tailor] || [fake_body?]
#[derive(Debug)]
pub struct Envelope {
    /// Length of the fake header (0 if none).
    pub header_length: usize,
    /// The complete packet data.
    pub data: ByteBuffer,
}

impl Envelope {
    /// Minimum envelope size (just the encrypted tailor).
    pub const MIN_SIZE: usize = ENCRYPTED_TAILOR_SIZE;

    /// Create a new envelope from components.
    ///
    /// # Arguments
    /// * `fake_header` - Optional fake header to prepend
    /// * `encrypted_payload` - Encrypted payload data
    /// * `encrypted_tailor` - Encrypted tailor (must be ENCRYPTED_TAILOR_SIZE bytes)
    /// * `fake_body` - Optional fake body to append
    pub fn new(
        fake_header: Option<ByteBuffer>,
        encrypted_payload: ByteBuffer,
        encrypted_tailor: ByteBuffer,
        fake_body: Option<ByteBuffer>,
    ) -> TyphoonResult<Self> {
        if encrypted_tailor.len() != ENCRYPTED_TAILOR_SIZE {
            return Err(TyphoonError::InvalidPacket(format!(
                "Invalid encrypted tailor size: expected {}, got {}",
                ENCRYPTED_TAILOR_SIZE,
                encrypted_tailor.len()
            )));
        }

        let header_length = fake_header.as_ref().map(|h| h.len()).unwrap_or(0);
        let body_length = fake_body.as_ref().map(|b| b.len()).unwrap_or(0);
        let total_length =
            header_length + encrypted_payload.len() + ENCRYPTED_TAILOR_SIZE + body_length;

        // Allocate buffer with total size
        let data = ByteBuffer::empty(total_length);
        let mut offset = 0;

        // Write fake header if present
        if let Some(header) = &fake_header {
            data.slice_mut()[offset..offset + header.len()].copy_from_slice(header.slice());
            offset += header.len();
        }

        // Write encrypted payload
        data.slice_mut()[offset..offset + encrypted_payload.len()]
            .copy_from_slice(encrypted_payload.slice());
        offset += encrypted_payload.len();

        // Write encrypted tailor
        data.slice_mut()[offset..offset + ENCRYPTED_TAILOR_SIZE]
            .copy_from_slice(encrypted_tailor.slice());
        offset += ENCRYPTED_TAILOR_SIZE;

        // Write fake body if present
        if let Some(body) = &fake_body {
            data.slice_mut()[offset..offset + body.len()].copy_from_slice(body.slice());
        }

        Ok(Self {
            header_length,
            data,
        })
    }

    /// Create an envelope for a payload-only packet (no fake header/body).
    pub fn payload_only(
        encrypted_payload: ByteBuffer,
        encrypted_tailor: ByteBuffer,
    ) -> TyphoonResult<Self> {
        Self::new(None, encrypted_payload, encrypted_tailor, None)
    }

    /// Get the total envelope size.
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Check if the envelope is empty.
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Get the raw packet data.
    pub fn as_bytes(&self) -> &[u8] {
        self.data.slice()
    }

    /// Consume the envelope and return the underlying buffer.
    pub fn into_buffer(self) -> ByteBuffer {
        self.data
    }

    /// Extract components from a received envelope.
    ///
    /// # Arguments
    /// * `data` - The received packet data
    /// * `header_length` - Known header length (0 if unknown/none)
    /// * `payload_length` - Known payload length from decrypted tailor
    ///
    /// Returns: (encrypted_payload, encrypted_tailor)
    pub fn extract(
        data: ByteBuffer,
        header_length: usize,
        payload_length: usize,
    ) -> TyphoonResult<(ByteBuffer, ByteBuffer)> {
        let expected_min = header_length + payload_length + ENCRYPTED_TAILOR_SIZE;
        if data.len() < expected_min {
            return Err(TyphoonError::InvalidPacket(format!(
                "Envelope too small: expected at least {}, got {}",
                expected_min,
                data.len()
            )));
        }

        // Skip header
        let after_header = data.rebuffer_start(header_length);

        // Extract payload
        let (payload, rest) = after_header.split_buf(payload_length);

        // Extract tailor (next ENCRYPTED_TAILOR_SIZE bytes)
        let (tailor, _fake_body) = rest.split_buf(ENCRYPTED_TAILOR_SIZE);

        Ok((payload, tailor))
    }

    /// Extract just the encrypted tailor from the end of a packet.
    ///
    /// This is used for initial tailor decryption before payload length is known.
    /// Note: This assumes no fake body is present after the tailor.
    pub fn extract_tailor_from_end(data: ByteBuffer) -> TyphoonResult<(ByteBuffer, ByteBuffer)> {
        if data.len() < ENCRYPTED_TAILOR_SIZE {
            return Err(TyphoonError::InvalidPacket(format!(
                "Packet too small for tailor: expected at least {}, got {}",
                ENCRYPTED_TAILOR_SIZE,
                data.len()
            )));
        }

        let split_point = data.len() - ENCRYPTED_TAILOR_SIZE;
        Ok(data.split_buf(split_point))
    }
}

#[cfg(test)]
#[path = "../../tests/flow/envelope.rs"]
mod tests;
