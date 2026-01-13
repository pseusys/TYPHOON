use std::time::{SystemTime, UNIX_EPOCH};

use crate::bytes::ByteBuffer;
use crate::constants::tailor::{
    CD_OFFSET, FG_OFFSET, ID_OFFSET, PL_OFFSET, PN_OFFSET, TAILOR_LENGTH, TM_OFFSET,
    TYPHOON_ID_LENGTH,
};
use crate::error::{TyphoonError, TyphoonResult};
use crate::tailor::flags::{PacketFlags, ReturnCode};

/// Tailor structure (32 bytes total).
///
/// The tailor is appended at the end of every TYPHOON packet and contains
/// metadata for packet processing, identification, and health checking.
///
/// Layout:
/// - FG (flags): 1 byte - packet type flags
/// - CD (code): 1 byte - client type or return code
/// - TM (time): 4 bytes - next_in delay in milliseconds
/// - PN (packet number): 8 bytes - timestamp (4) + incremental (4)
/// - PL (payload length): 2 bytes - length of encrypted payload
/// - ID (identity): 16 bytes - client UUID
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tailor {
    /// Packet flags defining packet contents.
    pub flags: PacketFlags,
    /// Code: client type in client handshake, return code otherwise.
    pub code: u8,
    /// Time: next_in delay in milliseconds for health check packets.
    pub time: u32,
    /// Packet number: timestamp (upper 32 bits) + incremental (lower 32 bits).
    pub packet_number: u64,
    /// Payload length in bytes.
    pub payload_length: u16,
    /// Client identity (UUID).
    pub identity: [u8; TYPHOON_ID_LENGTH],
}

impl Tailor {
    /// Total size of tailor in bytes.
    pub const SIZE: usize = TAILOR_LENGTH;

    /// Create a new tailor with default values.
    pub fn new() -> Self {
        Self {
            flags: PacketFlags::empty(),
            code: 0,
            time: 0,
            packet_number: 0,
            payload_length: 0,
            identity: [0u8; TYPHOON_ID_LENGTH],
        }
    }

    /// Create a data packet tailor.
    pub fn data(identity: [u8; TYPHOON_ID_LENGTH], payload_length: u16, packet_number: u64) -> Self {
        Self {
            flags: PacketFlags::DATA,
            code: 0,
            time: 0,
            packet_number,
            payload_length,
            identity,
        }
    }

    /// Create a health check packet tailor.
    pub fn health_check(identity: [u8; TYPHOON_ID_LENGTH], next_in: u32, packet_number: u64) -> Self {
        Self {
            flags: PacketFlags::HEALTH_CHECK,
            code: 0,
            time: next_in,
            packet_number,
            payload_length: 0,
            identity,
        }
    }

    /// Create a shadowride packet tailor (data + health check).
    pub fn shadowride(
        identity: [u8; TYPHOON_ID_LENGTH],
        payload_length: u16,
        next_in: u32,
        packet_number: u64,
    ) -> Self {
        Self {
            flags: PacketFlags::DATA | PacketFlags::HEALTH_CHECK,
            code: 0,
            time: next_in,
            packet_number,
            payload_length,
            identity,
        }
    }

    /// Create a handshake packet tailor.
    pub fn handshake(identity: [u8; TYPHOON_ID_LENGTH], code: u8, next_in: u32, packet_number: u64) -> Self {
        Self {
            flags: PacketFlags::HANDSHAKE,
            code,
            time: next_in,
            packet_number,
            payload_length: 0,
            identity,
        }
    }

    /// Create a decoy packet tailor.
    pub fn decoy(identity: [u8; TYPHOON_ID_LENGTH], packet_number: u64) -> Self {
        Self {
            flags: PacketFlags::DECOY,
            code: 0,
            time: 0,
            packet_number,
            payload_length: 0,
            identity,
        }
    }

    /// Create a termination packet tailor.
    pub fn termination(identity: [u8; TYPHOON_ID_LENGTH], code: ReturnCode, packet_number: u64) -> Self {
        Self {
            flags: PacketFlags::TERMINATION,
            code: code.into(),
            time: 0,
            packet_number,
            payload_length: 0,
            identity,
        }
    }

    /// Extract timestamp from packet number (upper 32 bits).
    #[inline]
    pub fn timestamp(&self) -> u32 {
        (self.packet_number >> 32) as u32
    }

    /// Extract incremental number from packet number (lower 32 bits).
    #[inline]
    pub fn incremental(&self) -> u32 {
        self.packet_number as u32
    }

    /// Set packet number from timestamp and incremental counter.
    #[inline]
    pub fn set_packet_number(&mut self, timestamp: u32, incremental: u32) {
        self.packet_number = ((timestamp as u64) << 32) | (incremental as u64);
    }

    /// Set packet number using current timestamp and given incremental.
    pub fn set_packet_number_now(&mut self, incremental: u32) {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as u32)
            .unwrap_or(0);
        self.set_packet_number(timestamp, incremental);
    }

    /// Get return code from code field.
    #[inline]
    pub fn return_code(&self) -> ReturnCode {
        ReturnCode::from(self.code)
    }

    /// Deserialize tailor from buffer.
    ///
    /// Buffer must be exactly TAILOR_LENGTH bytes.
    pub fn from_buffer(buffer: &ByteBuffer) -> TyphoonResult<Self> {
        if buffer.len() != TAILOR_LENGTH {
            return Err(TyphoonError::InvalidPacket(format!(
                "Invalid tailor length: expected {}, got {}",
                TAILOR_LENGTH,
                buffer.len()
            )));
        }

        let slice = buffer.slice();
        let flags = PacketFlags::from_bits_truncate(slice[FG_OFFSET]);
        let code = slice[CD_OFFSET];

        let time = u32::from_be_bytes([
            slice[TM_OFFSET],
            slice[TM_OFFSET + 1],
            slice[TM_OFFSET + 2],
            slice[TM_OFFSET + 3],
        ]);

        let packet_number = u64::from_be_bytes([
            slice[PN_OFFSET],
            slice[PN_OFFSET + 1],
            slice[PN_OFFSET + 2],
            slice[PN_OFFSET + 3],
            slice[PN_OFFSET + 4],
            slice[PN_OFFSET + 5],
            slice[PN_OFFSET + 6],
            slice[PN_OFFSET + 7],
        ]);

        let payload_length =
            u16::from_be_bytes([slice[PL_OFFSET], slice[PL_OFFSET + 1]]);

        let mut identity = [0u8; TYPHOON_ID_LENGTH];
        identity.copy_from_slice(&slice[ID_OFFSET..ID_OFFSET + TYPHOON_ID_LENGTH]);

        Ok(Self {
            flags,
            code,
            time,
            packet_number,
            payload_length,
            identity,
        })
    }

    /// Serialize tailor to a new buffer.
    pub fn to_buffer(&self) -> ByteBuffer {
        let buffer = ByteBuffer::empty(TAILOR_LENGTH);
        self.write_to_slice(buffer.slice_mut());
        buffer
    }

    /// Serialize tailor to a buffer with extra capacity for prepending and appending.
    pub fn to_buffer_with_capacity(&self, before_cap: usize, after_cap: usize) -> ByteBuffer {
        let buffer = ByteBuffer::empty_with_capacity(TAILOR_LENGTH, before_cap, after_cap);
        self.write_to_slice(buffer.slice_mut());
        buffer
    }

    /// Write tailor to an existing slice.
    ///
    /// Slice must be at least TAILOR_LENGTH bytes.
    pub fn write_to_slice(&self, slice: &mut [u8]) {
        assert!(
            slice.len() >= TAILOR_LENGTH,
            "Slice too small for tailor: {} < {}",
            slice.len(),
            TAILOR_LENGTH
        );

        slice[FG_OFFSET] = self.flags.bits();
        slice[CD_OFFSET] = self.code;

        let time_bytes = self.time.to_be_bytes();
        slice[TM_OFFSET..TM_OFFSET + 4].copy_from_slice(&time_bytes);

        let pn_bytes = self.packet_number.to_be_bytes();
        slice[PN_OFFSET..PN_OFFSET + 8].copy_from_slice(&pn_bytes);

        let pl_bytes = self.payload_length.to_be_bytes();
        slice[PL_OFFSET..PL_OFFSET + 2].copy_from_slice(&pl_bytes);

        slice[ID_OFFSET..ID_OFFSET + TYPHOON_ID_LENGTH].copy_from_slice(&self.identity);
    }
}

impl Default for Tailor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
#[path = "../../tests/tailor/structure.rs"]
mod tests;
