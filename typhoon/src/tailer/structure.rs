#[cfg(test)]
#[path = "../../tests/tailer/structure.rs"]
mod tests;

use std::fmt::{Debug, Formatter, Result as FmtResult};
use std::marker::PhantomData;

use crate::bytes::{ByteBuffer, ByteBufferMut, DynamicByteBuffer, StaticByteBuffer};
use crate::crypto::{TAILER_C2S_OVERHEAD, TAILER_S2C_OVERHEAD};
use crate::settings::consts::{CD_OFFSET, FG_OFFSET, ID_OFFSET, PL_OFFSET, PN_OFFSET, TAILER_LENGTH, TM_OFFSET};
use crate::tailer::flags::{PacketFlags, ReturnCode};
use crate::utils::unix_timestamp_ms;

const TM_LENGTH: usize = 4;
const PN_LENGTH: usize = 8;
const PL_LENGTH: usize = 2;

/// A client identity that can be read from and written into the tailer's fixed-size `ID` field.
pub trait IdentityType: Send + Sync {
    /// Construct an identity from the raw `ID` field bytes.
    fn from_bytes(bytes: &[u8]) -> Self;

    /// Get the raw bytes to write into the `ID` field.
    fn to_bytes(&self) -> &[u8];

    /// Length (bytes) of the `ID` field this identity type occupies.
    fn length() -> usize;
}

/// Server-side connection handler: generates identities, produces server initial data, checks client version, and is notified of connection and disconnection.
pub trait ServerConnectionHandler<T: IdentityType>: Send + Sync {
    /// Derive a client session identity from the client's decrypted initial data bytes, or `None` to reject the handshake (replied to with a TERMINATION carrying `ReturnCode::IdentityRejected`).
    /// Called on every attempt, including ones that fail validation — keep this pure; use [`on_connect`](Self::on_connect) to learn whether it succeeded and whether the identity was new.
    fn generate(&self, initial_data: &[u8]) -> Option<T>;

    /// Produce initial data to include in the server handshake response for the given identity.
    fn initial_data(&self, identity: &T) -> StaticByteBuffer;

    /// Check whether the client version (from the handshake tailer ID field) is compatible.
    /// Returns `true` if the handshake should proceed, `false` if it should be rejected.
    /// Implementations are responsible for any logging before returning.
    fn verify_version(&self, version_bytes: &[u8]) -> bool;

    /// Called once a handshake succeeds.
    /// `existing` is `true` if `identity` already had a live connection — a re-handshake collision that displaces it silently, without `on_disconnect` — or `false` if it's brand new: the reliable signal for allocating (`false`) or carrying over (`true`) per-identity resources.
    /// Default: no-op.
    fn on_connect(&self, _identity: &T, _existing: bool) {}

    /// Called once a client's connection has ended for any reason (remote termination, health-check decay, or explicit eviction), right before its handle is released.
    /// Not invoked when a re-handshake displaces `identity` to a new connection — see `on_connect`.
    /// Default: no-op.
    fn on_disconnect(&self, _identity: &T) {}
}

/// Client-side connection handler: produces client initial data and the version bytes for the handshake.
pub trait ClientConnectionHandler: Send + Sync {
    /// Produce initial data to include in the client handshake.
    fn initial_data(&self) -> StaticByteBuffer;

    /// Produce the version bytes to place in the handshake tailer ID field, clamped to `length` bytes.
    fn version(&self, length: usize) -> StaticByteBuffer;
}

/// Tailer view (16 + `TYPHOON_ID_LENGTH` bytes total).
/// Zero-copy view into a `DynamicByteBuffer` containing tailer metadata.
/// All field access reads directly from the underlying buffer.
///
/// Layout:
/// - FG (flags): 1 byte - packet type flags
/// - CD (code): 1 byte - client type or return code
/// - TM (time): 4 bytes - `next_in` delay in milliseconds
/// - PN (packet number): 8 bytes - incremental (4) + timestamp (4)
/// - PL (payload length): 2 bytes - length of encrypted payload
/// - ID (identity): `TYPHOON_ID_LENGTH` bytes - client UUID
pub struct Tailer<T: IdentityType> {
    buffer: DynamicByteBuffer,
    _phantom: PhantomData<T>,
}

impl<T: IdentityType> Tailer<T> {
    /// Wrap an existing buffer as a tailer view. No data is copied.
    /// The buffer must contain at least `Self::len()` bytes.
    pub fn new(buffer: DynamicByteBuffer) -> Self {
        let buffer = buffer.ensure_size(Self::len());
        Self {
            buffer,
            _phantom: PhantomData,
        }
    }

    /// Construct a tailer view from a received buffer and validate it against the
    /// accompanying body length. Unlike [`Tailer::new`], this constructor never
    /// expands the buffer via the pool — receive paths must supply a slice whose
    /// length is already at least `Self::len()`.
    pub fn validated(buffer: DynamicByteBuffer, body_len: usize) -> Option<Self> {
        if buffer.len() < Self::len() {
            return None;
        }
        let view = Self {
            buffer,
            _phantom: PhantomData,
        };
        let flags = view.flags();
        if flags.is_empty() {
            return None;
        }
        if flags.bits().count_ones() > 1 && !flags.is_shadowride() {
            return None;
        }
        if (view.payload_length() as usize) > body_len {
            return None;
        }
        Some(view)
    }

    /// Write a data packet tailer into the buffer.
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

    /// Write a health check packet tailer into the buffer.
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

    /// Write a handshake packet tailer into the buffer.
    /// `body_len` is the length of the handshake body (excluding tailer), allowing receivers
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

    /// Write a decoy packet tailer into the buffer.
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

    /// Write a debug probe tailer into the buffer.
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

    /// Write a termination packet tailer into the buffer.
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

    /// Read the `FG` (flags) field.
    #[inline]
    pub fn flags(&self) -> PacketFlags {
        PacketFlags::from_bits_truncate(*self.buffer.get(FG_OFFSET))
    }

    /// Read the `CD` (code) field.
    #[inline]
    pub fn code(&self) -> u8 {
        *self.buffer.get(CD_OFFSET)
    }

    /// Read the `TM` (time) field: the next-in delay in milliseconds.
    ///
    /// # Panics
    ///
    /// Never in practice: both `Tailer` constructors guarantee the backing buffer is at least
    /// `Self::len()` bytes.
    #[inline]
    pub fn time(&self) -> u32 {
        u32::from_be_bytes(self.buffer.slice_both(TM_OFFSET, TM_OFFSET + TM_LENGTH).try_into().unwrap())
    }

    /// Read the raw 64-bit `PN` (packet number) field.
    ///
    /// # Panics
    ///
    /// Never in practice: both `Tailer` constructors guarantee the backing buffer is at least
    /// `Self::len()` bytes.
    #[inline]
    pub fn packet_number(&self) -> u64 {
        u64::from_be_bytes(self.buffer.slice_both(PN_OFFSET, PN_OFFSET + PN_LENGTH).try_into().unwrap())
    }

    /// Read the `PL` (payload length) field.
    ///
    /// # Panics
    ///
    /// Never in practice: both `Tailer` constructors guarantee the backing buffer is at least
    /// `Self::len()` bytes.
    #[inline]
    pub fn payload_length(&self) -> u16 {
        u16::from_be_bytes(self.buffer.slice_both(PL_OFFSET, PL_OFFSET + PL_LENGTH).try_into().unwrap())
    }

    /// Read the `ID` (identity) field.
    #[inline]
    pub fn identity(&self) -> T {
        T::from_bytes(self.buffer.slice_both(ID_OFFSET, ID_OFFSET + T::length()))
    }

    /// Extract timestamp from packet number (lower 32 bits).
    #[inline]
    pub fn timestamp(&self) -> u32 {
        self.packet_number() as u32
    }

    /// Extract incremental number from packet number (upper 32 bits).
    /// Kept in the dominant half so raw `PN` comparisons order strictly by the monotonic counter and are immune to clock adjustments.
    #[inline]
    pub fn incremental(&self) -> u32 {
        (self.packet_number() >> 32) as u32
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

    /// Consume the tailer view and return the underlying buffer.
    #[inline]
    pub fn into_buffer(self) -> DynamicByteBuffer {
        self.buffer
    }

    // --- Setters (write through to the buffer) ---

    /// Write the `FG` (flags) field.
    #[inline]
    pub fn set_flags(&self, flags: PacketFlags) {
        self.buffer.set(FG_OFFSET, flags.bits());
    }

    /// Write the `CD` (code) field.
    #[inline]
    pub fn set_code(&self, code: u8) {
        self.buffer.set(CD_OFFSET, code);
    }

    /// Write the `TM` (time) field.
    #[inline]
    pub fn set_time(&self, time: u32) {
        self.buffer.slice_both_mut(TM_OFFSET, TM_OFFSET + TM_LENGTH).copy_from_slice(&time.to_be_bytes());
    }

    /// Write the raw 64-bit `PN` (packet number) field directly.
    #[inline]
    pub fn set_packet_number_raw(&self, pn: u64) {
        self.buffer.slice_both_mut(PN_OFFSET, PN_OFFSET + PN_LENGTH).copy_from_slice(&pn.to_be_bytes());
    }

    /// Set packet number from timestamp and incremental counter.
    /// The counter occupies the upper (dominant) 32 bits so that raw `PN` comparisons order strictly by it, independent of clock adjustments.
    #[inline]
    pub fn set_packet_number(&self, timestamp: u32, incremental: u32) {
        let pn = ((incremental as u64) << 32) | (timestamp as u64);
        self.set_packet_number_raw(pn);
    }

    /// Set packet number using current timestamp and given incremental.
    pub fn set_packet_number_now(&self, incremental: u32) {
        let timestamp = (unix_timestamp_ms() / 1000) as u32;
        self.set_packet_number(timestamp, incremental);
    }

    /// Write the `PL` (payload length) field.
    #[inline]
    pub fn set_payload_length(&self, len: u16) {
        self.buffer.slice_both_mut(PL_OFFSET, PL_OFFSET + PL_LENGTH).copy_from_slice(&len.to_be_bytes());
    }

    /// Write the `ID` (identity) field.
    #[inline]
    pub fn set_identity(&self, identity: &T) {
        self.buffer.slice_both_mut(ID_OFFSET, ID_OFFSET + T::length()).copy_from_slice(identity.to_bytes());
    }

    // --- Static helpers that read from a raw buffer ---

    /// Read the `PL` (payload length) field directly from a raw tailer buffer, without constructing a `Tailer` view.
    ///
    /// # Panics
    ///
    /// Never in practice: the buffer is expanded to at least `TAILER_LENGTH` bytes before reading.
    #[inline]
    pub fn get_payload_length(buffer: &DynamicByteBuffer) -> u16 {
        let correct_buffer = buffer.ensure_size(TAILER_LENGTH);
        u16::from_be_bytes(correct_buffer.slice_both(PL_OFFSET, PL_OFFSET + PL_LENGTH).try_into().unwrap())
    }

    /// Extract identity from a raw tailer buffer.
    #[inline]
    pub fn get_identity(buffer: &DynamicByteBuffer) -> T {
        let correct_buffer = buffer.ensure_size(Self::len());
        T::from_bytes(correct_buffer.slice_both(ID_OFFSET, ID_OFFSET + T::length()))
    }

    /// Total tailer length (bytes): the fixed-size part plus `T`'s `ID` field length.
    #[inline]
    pub fn len() -> usize {
        T::length() + TAILER_LENGTH
    }

    /// Wire length of the obfuscated client → server tailer (plaintext tailer + c2s obfuscation overhead).
    #[inline]
    pub(crate) fn encrypted_len_c2s() -> usize {
        Self::len() + TAILER_C2S_OVERHEAD
    }

    /// Wire length of the obfuscated server → client tailer (plaintext tailer + s2c obfuscation overhead).
    #[inline]
    pub(crate) fn encrypted_len_s2c() -> usize {
        Self::len() + TAILER_S2C_OVERHEAD
    }
}

impl<T: IdentityType> Clone for Tailer<T> {
    fn clone(&self) -> Self {
        Self {
            buffer: self.buffer.clone(),
            _phantom: PhantomData,
        }
    }
}

impl<T: IdentityType + PartialEq> PartialEq for Tailer<T> {
    fn eq(&self, other: &Self) -> bool {
        self.buffer.slice() == other.buffer.slice()
    }
}

impl<T: IdentityType> Debug for Tailer<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        f.debug_struct("Tailer").field("flags", &self.flags()).field("code", &self.code()).field("time", &self.time()).field("packet_number", &self.packet_number()).field("payload_length", &self.payload_length()).finish()
    }
}
