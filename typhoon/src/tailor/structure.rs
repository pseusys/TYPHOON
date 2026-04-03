#[cfg(test)]
#[path = "../../tests/tailor/structure.rs"]
mod tests;

use std::fmt::Debug;
use std::marker::PhantomData;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::bytes::{ByteBuffer, ByteBufferMut, DynamicByteBuffer};
use crate::settings::consts::{CD_OFFSET, FG_OFFSET, ID_OFFSET, PL_OFFSET, PN_OFFSET, TAILOR_LENGTH, TM_OFFSET};
use crate::tailor::flags::{PacketFlags, ReturnCode};

const TM_LENGTH: usize = 4;
const PN_LENGTH: usize = 8;
const PL_LENGTH: usize = 2;

pub trait IdentityType: Send + Sync {
    fn from_bytes(bytes: &[u8]) -> Self;

    fn to_bytes(&self) -> &[u8];

    fn length() -> usize;
}

/// Server-side connection handler: generates identities, produces server initial data, and checks client version.
pub trait ServerConnectionHandler<T: IdentityType>: Send + Sync {
    /// Derive a client session identity from the client's decrypted initial data bytes.
    fn generate(&self, initial_data: &[u8]) -> T;

    /// Produce initial data to include in the server handshake response for the given identity.
    fn initial_data(&self, identity: &T) -> Vec<u8>;

    /// Check whether the client version (from the handshake tailor ID field) is compatible.
    /// Returns `true` if the handshake should proceed, `false` if it should be rejected.
    /// Implementations are responsible for any logging before returning.
    fn verify_version(&self, version_bytes: &[u8]) -> bool;
}

/// Client-side connection handler: produces client initial data and the version bytes for the handshake.
pub trait ClientConnectionHandler: Send + Sync {
    /// Produce initial data to include in the client handshake.
    fn initial_data(&self) -> Vec<u8>;

    /// Produce the version bytes to place in the handshake tailor ID field, clamped to `length` bytes.
    fn version(&self, length: usize) -> Vec<u8>;
}

/// Tailor view (16 + TYPHOON_ID_LENGTH bytes total).
/// Zero-copy view into a `DynamicByteBuffer` containing tailor metadata.
/// All field access reads directly from the underlying buffer.
///
/// Layout:
/// - FG (flags): 1 byte - packet type flags
/// - CD (code): 1 byte - client type or return code
/// - TM (time): 4 bytes - next_in delay in milliseconds
/// - PN (packet number): 8 bytes - timestamp (4) + incremental (4)
/// - PL (payload length): 2 bytes - length of encrypted payload
/// - ID (identity): TYPHOON_ID_LENGTH bytes - client UUID
pub struct Tailor<T: IdentityType> {
    buffer: DynamicByteBuffer,
    _phantom: PhantomData<T>,
}

impl<T: IdentityType> Tailor<T> {
    /// Wrap an existing buffer as a tailor view. No data is copied.
    /// The buffer must contain at least `TAILOR_LENGTH + T::length()` bytes.
    pub fn new(buffer: DynamicByteBuffer) -> Self {
        let buffer = buffer.ensure_size(T::length() + TAILOR_LENGTH);
        Self { buffer, _phantom: PhantomData }
    }

    /// Write a data packet tailor into the buffer.
    pub fn data(buffer: DynamicByteBuffer, identity: &T, payload_length: u16, packet_number: u64) -> Self {
        let view = Self::new(buffer);
        view.set_flags(PacketFlags::DATA);
        view.set_code(0);
        view.set_time(0);
        view.set_packet_number_raw(packet_number);
        view.set_payload_length(payload_length);
        view.set_identity(identity);
        view
    }

    /// Write a health check packet tailor into the buffer.
    pub fn health_check(buffer: DynamicByteBuffer, identity: &T, next_in: u32, packet_number: u64) -> Self {
        let view = Self::new(buffer);
        view.set_flags(PacketFlags::HEALTH_CHECK);
        view.set_code(0);
        view.set_time(next_in);
        view.set_packet_number_raw(packet_number);
        view.set_payload_length(0);
        view.set_identity(identity);
        view
    }

    /// Write a shadowride packet tailor (data + health check) into the buffer.
    pub fn shadowride(buffer: DynamicByteBuffer, identity: &T, payload_length: u16, next_in: u32, packet_number: u64) -> Self {
        let view = Self::new(buffer);
        view.set_flags(PacketFlags::DATA | PacketFlags::HEALTH_CHECK);
        view.set_code(0);
        view.set_time(next_in);
        view.set_packet_number_raw(packet_number);
        view.set_payload_length(payload_length);
        view.set_identity(identity);
        view
    }

    /// Write a handshake packet tailor into the buffer.
    /// `body_len` is the length of the handshake body (excluding tailor), allowing receivers
    /// to strip any fake header/body prefix before parsing the handshake data.
    pub fn handshake(buffer: DynamicByteBuffer, identity: &T, code: u8, next_in: u32, packet_number: u64, body_len: u16) -> Self {
        let view = Self::new(buffer);
        view.set_flags(PacketFlags::HANDSHAKE);
        view.set_code(code);
        view.set_time(next_in);
        view.set_packet_number_raw(packet_number);
        view.set_payload_length(body_len);
        view.set_identity(identity);
        view
    }

    /// Write a decoy packet tailor into the buffer.
    pub fn decoy(buffer: DynamicByteBuffer, identity: &T, packet_number: u64) -> Self {
        let view = Self::new(buffer);
        view.set_flags(PacketFlags::DECOY);
        view.set_code(0);
        view.set_time(0);
        view.set_packet_number_raw(packet_number);
        view.set_payload_length(0);
        view.set_identity(identity);
        view
    }

    /// Write a debug probe tailor into the buffer.
    ///
    /// Field semantics in debug mode:
    /// - **FG**: `DATA` flag (same as data packets so probes blend in).
    /// - **CD**: `ref_num` — rolling reference number (0–255) uniquely identifying this probe.
    /// - **TM**: `send_time_ms` — lower 32 bits of the Unix send timestamp in milliseconds.
    /// - **PN**: `sequence << 32 | phase` — global sequence number and debug phase identifier.
    /// - **PL**: `payload_len` — length of the probe payload.
    pub fn debug_probe(buffer: DynamicByteBuffer, identity: &T, ref_num: u8, send_time_ms: u32, sequence: u32, phase: u32, payload_len: u16) -> Self {
        let view = Self::new(buffer);
        view.set_flags(PacketFlags::DATA);
        view.set_code(ref_num);
        view.set_time(send_time_ms);
        view.set_packet_number_raw(((sequence as u64) << 32) | (phase as u64));
        view.set_payload_length(payload_len);
        view.set_identity(identity);
        view
    }

    /// Write a termination packet tailor into the buffer.
    pub fn termination(buffer: DynamicByteBuffer, identity: &T, code: ReturnCode, packet_number: u64) -> Self {
        let view = Self::new(buffer);
        view.set_flags(PacketFlags::TERMINATION);
        view.set_code(code.into());
        view.set_time(0);
        view.set_packet_number_raw(packet_number);
        view.set_payload_length(0);
        view.set_identity(identity);
        view
    }

    // --- Getters ---

    #[inline]
    pub fn flags(&self) -> PacketFlags {
        PacketFlags::from_bits_truncate(*self.buffer.get(FG_OFFSET))
    }

    #[inline]
    pub fn code(&self) -> u8 {
        *self.buffer.get(CD_OFFSET)
    }

    #[inline]
    pub fn time(&self) -> u32 {
        u32::from_be_bytes(self.buffer.slice_both(TM_OFFSET, TM_OFFSET + TM_LENGTH).try_into().unwrap())
    }

    #[inline]
    pub fn packet_number(&self) -> u64 {
        u64::from_be_bytes(self.buffer.slice_both(PN_OFFSET, PN_OFFSET + PN_LENGTH).try_into().unwrap())
    }

    #[inline]
    pub fn payload_length(&self) -> u16 {
        u16::from_be_bytes(self.buffer.slice_both(PL_OFFSET, PL_OFFSET + PL_LENGTH).try_into().unwrap())
    }

    #[inline]
    pub fn identity(&self) -> T {
        T::from_bytes(self.buffer.slice_both(ID_OFFSET, ID_OFFSET + T::length()))
    }

    /// Extract timestamp from packet number (upper 32 bits).
    #[inline]
    pub fn timestamp(&self) -> u32 {
        (self.packet_number() >> 32) as u32
    }

    /// Extract incremental number from packet number (lower 32 bits).
    #[inline]
    pub fn incremental(&self) -> u32 {
        self.packet_number() as u32
    }

    /// Get return code from code field.
    #[inline]
    pub fn return_code(&self) -> ReturnCode {
        ReturnCode::from(self.code())
    }

    // --- Debug accessors (reinterpret fields per debug-mode semantics) ---

    /// Debug: rolling reference number from the CD field (0–255).
    #[inline]
    pub fn debug_ref_num(&self) -> u8 {
        self.code()
    }

    /// Debug: send timestamp in milliseconds from the TM field (lower 32 bits of Unix time).
    #[inline]
    pub fn debug_send_time(&self) -> u32 {
        self.time()
    }

    /// Debug: global probe sequence number from the upper 32 bits of the PN field.
    #[inline]
    pub fn debug_sequence(&self) -> u32 {
        (self.packet_number() >> 32) as u32
    }

    /// Debug: phase identifier from the lower 32 bits of the PN field.
    /// `0` = reachability, `1` = return time, `2` = throughput.
    #[inline]
    pub fn debug_phase(&self) -> u32 {
        self.packet_number() as u32
    }

    /// Get the underlying buffer.
    #[inline]
    pub fn buffer(&self) -> &DynamicByteBuffer {
        &self.buffer
    }

    /// Consume the tailor view and return the underlying buffer.
    #[inline]
    pub fn into_buffer(self) -> DynamicByteBuffer {
        self.buffer
    }

    // --- Setters (write through to the buffer) ---

    #[inline]
    pub fn set_flags(&self, flags: PacketFlags) {
        self.buffer.set(FG_OFFSET, flags.bits());
    }

    #[inline]
    pub fn set_code(&self, code: u8) {
        self.buffer.set(CD_OFFSET, code);
    }

    #[inline]
    pub fn set_time(&self, time: u32) {
        self.buffer.slice_both_mut(TM_OFFSET, TM_OFFSET + TM_LENGTH).copy_from_slice(&time.to_be_bytes());
    }

    #[inline]
    pub fn set_packet_number_raw(&self, pn: u64) {
        self.buffer.slice_both_mut(PN_OFFSET, PN_OFFSET + PN_LENGTH).copy_from_slice(&pn.to_be_bytes());
    }

    /// Set packet number from timestamp and incremental counter.
    #[inline]
    pub fn set_packet_number(&self, timestamp: u32, incremental: u32) {
        let pn = ((timestamp as u64) << 32) | (incremental as u64);
        self.set_packet_number_raw(pn);
    }

    /// Set packet number using current timestamp and given incremental.
    pub fn set_packet_number_now(&self, incremental: u32) {
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as u32).unwrap_or(0);
        self.set_packet_number(timestamp, incremental);
    }

    #[inline]
    pub fn set_payload_length(&self, len: u16) {
        self.buffer.slice_both_mut(PL_OFFSET, PL_OFFSET + PL_LENGTH).copy_from_slice(&len.to_be_bytes());
    }

    #[inline]
    pub fn set_identity(&self, identity: &T) {
        self.buffer.slice_both_mut(ID_OFFSET, ID_OFFSET + T::length()).copy_from_slice(identity.to_bytes());
    }

    // --- Static helpers that read from a raw buffer ---

    pub fn get_payload_length(buffer: &DynamicByteBuffer) -> u16 {
        let correct_buffer = buffer.ensure_size(TAILOR_LENGTH);
        u16::from_be_bytes(correct_buffer.slice_both(PL_OFFSET, PL_OFFSET + PL_LENGTH).try_into().unwrap())
    }

    /// Extract identity from a raw tailor buffer.
    pub fn get_identity(buffer: &DynamicByteBuffer) -> T {
        let correct_buffer = buffer.ensure_size(T::length() + TAILOR_LENGTH);
        T::from_bytes(correct_buffer.slice_both(ID_OFFSET, ID_OFFSET + T::length()))
    }
}

impl<T: IdentityType> Clone for Tailor<T> {
    fn clone(&self) -> Self {
        Self { buffer: self.buffer.clone(), _phantom: PhantomData }
    }
}

impl<T: IdentityType + PartialEq> PartialEq for Tailor<T> {
    fn eq(&self, other: &Self) -> bool {
        self.buffer.slice() == other.buffer.slice()
    }
}

impl<T: IdentityType> Debug for Tailor<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Tailor")
            .field("flags", &self.flags())
            .field("code", &self.code())
            .field("time", &self.time())
            .field("packet_number", &self.packet_number())
            .field("payload_length", &self.payload_length())
            .finish()
    }
}
