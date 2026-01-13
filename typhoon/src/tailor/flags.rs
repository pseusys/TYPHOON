use bitflags::bitflags;

bitflags! {
    /// Packet type flags for the tailor FG field.
    ///
    /// Normally only one flag should be set, but a health check packet
    /// can be embedded into a data packet (shadowride).
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct PacketFlags: u8 {
        /// Handshake packet (128).
        const HANDSHAKE = 0b1000_0000;
        /// Health check packet (64).
        const HEALTH_CHECK = 0b0100_0000;
        /// Data packet (32).
        const DATA = 0b0010_0000;
        /// Decoy packet (16).
        const DECOY = 0b0001_0000;
        /// Termination packet (8).
        const TERMINATION = 0b0000_1000;
    }
}

impl PacketFlags {
    /// Check if this is a shadowride packet (data + health check).
    #[inline]
    pub fn is_shadowride(&self) -> bool {
        self.contains(Self::DATA | Self::HEALTH_CHECK)
    }

    /// Check if this packet carries payload data.
    #[inline]
    pub fn has_payload(&self) -> bool {
        self.contains(Self::DATA)
    }

    /// Check if this packet requires response (handshake or health check).
    #[inline]
    pub fn requires_response(&self) -> bool {
        self.intersects(Self::HANDSHAKE | Self::HEALTH_CHECK)
    }

    /// Check if this packet should be discarded by flow manager (decoy).
    #[inline]
    pub fn is_discardable(&self) -> bool {
        self.contains(Self::DECOY)
    }

    /// Check if this is a termination packet.
    #[inline]
    pub fn is_termination(&self) -> bool {
        self.contains(Self::TERMINATION)
    }
}

/// Return codes for handshake and termination packets (CD field).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ReturnCode {
    /// No error (successful handshake or graceful termination).
    Success = 0,
    /// Unknown error.
    UnknownError = 101,
}

impl From<u8> for ReturnCode {
    fn from(value: u8) -> Self {
        match value {
            0 => ReturnCode::Success,
            _ => ReturnCode::UnknownError,
        }
    }
}

impl From<ReturnCode> for u8 {
    fn from(code: ReturnCode) -> Self {
        code as u8
    }
}

#[cfg(test)]
#[path = "../../tests/tailor/flags.rs"]
mod tests;
