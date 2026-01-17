#[cfg(test)]
#[path = "../../tests/tailor/structure.rs"]
mod tests;

use std::time::{SystemTime, UNIX_EPOCH};

use crate::bytes::ByteBuffer;
use crate::constants::consts::{TAILOR_LENGTH, FG_OFFSET, CD_OFFSET, TM_OFFSET, PN_OFFSET, PL_OFFSET, ID_OFFSET};
use crate::tailor::flags::{PacketFlags, ReturnCode};

/// Tailor structure (16 + TYPHOON_ID_LENGTH bytes total).
/// The tailor is appended at the end of every TYPHOON packet and contains
/// metadata for packet processing, identification, and health checking.
///
/// Layout:
/// - FG (flags): 1 byte - packet type flags
/// - CD (code): 1 byte - client type or return code
/// - TM (time): 4 bytes - next_in delay in milliseconds
/// - PN (packet number): 8 bytes - timestamp (4) + incremental (4)
/// - PL (payload length): 2 bytes - length of encrypted payload
/// - ID (identity): TYPHOON_ID_LENGTH bytes - client UUID
#[derive(Debug, Clone, PartialEq)]
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
    pub identity: ByteBuffer,
}

impl Tailor {
    /// Create a data packet tailor.
    pub fn data(identity: ByteBuffer, payload_length: u16, packet_number: u64) -> Self {
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
    pub fn health_check(identity: ByteBuffer, next_in: u32, packet_number: u64) -> Self {
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
    pub fn shadowride(identity: ByteBuffer, payload_length: u16, next_in: u32, packet_number: u64) -> Self {
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
    pub fn handshake(identity: ByteBuffer, code: u8, next_in: u32, packet_number: u64) -> Self {
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
    pub fn decoy(identity: ByteBuffer, packet_number: u64) -> Self {
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
    pub fn termination(identity: ByteBuffer, code: ReturnCode, packet_number: u64) -> Self {
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
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as u32).unwrap_or(0);
        self.set_packet_number(timestamp, incremental);
    }

    /// Get return code from code field.
    #[inline]
    pub fn return_code(&self) -> ReturnCode {
        ReturnCode::from(self.code)
    }

    /// Deserialize tailor from buffer.
    /// Buffer must be exactly TAILOR_LENGTH bytes.
    pub fn from_buffer(buffer: &ByteBuffer, identity_len: usize) -> Self {
        let correct_buffer = buffer.ensure_size(identity_len + TAILOR_LENGTH);
        let slice = correct_buffer.slice();
        let flags = PacketFlags::from_bits_truncate(slice[FG_OFFSET]);
        let code = slice[CD_OFFSET];
        let time = u32::from_be_bytes([slice[TM_OFFSET], slice[TM_OFFSET + 1], slice[TM_OFFSET + 2], slice[TM_OFFSET + 3]]);
        let packet_number = u64::from_be_bytes([slice[PN_OFFSET], slice[PN_OFFSET + 1], slice[PN_OFFSET + 2], slice[PN_OFFSET + 3], slice[PN_OFFSET + 4], slice[PN_OFFSET + 5], slice[PN_OFFSET + 6], slice[PN_OFFSET + 7]]);
        let payload_length = u16::from_be_bytes([slice[PL_OFFSET], slice[PL_OFFSET + 1]]);
        let identity = correct_buffer.rebuffer_both(ID_OFFSET, ID_OFFSET + identity_len);
        Self {
            flags,
            code,
            time,
            packet_number,
            payload_length,
            identity,
        }
    }

    /// Serialize tailor to a buffer.
    pub fn to_buffer(&self, buffer: ByteBuffer) -> ByteBuffer {
        let correct_buffer = buffer.ensure_size(self.identity.len() + TAILOR_LENGTH);
        let correct_slice = correct_buffer.slice_mut();

        correct_slice[FG_OFFSET] = self.flags.bits();
        correct_slice[CD_OFFSET] = self.code;
        correct_slice[TM_OFFSET..TM_OFFSET + 4].copy_from_slice(&self.time.to_be_bytes());
        correct_slice[PN_OFFSET..PN_OFFSET + 8].copy_from_slice(&self.packet_number.to_be_bytes());
        correct_slice[PL_OFFSET..PL_OFFSET + 2].copy_from_slice(&self.payload_length.to_be_bytes());
        correct_slice[ID_OFFSET..ID_OFFSET + self.identity.len()].copy_from_slice(self.identity.slice());

        correct_buffer
    }
}
