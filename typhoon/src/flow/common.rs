use std::future::Future;
use std::sync::Arc;

use cfg_if::cfg_if;

use crate::bytes::DynamicByteBuffer;
#[cfg(feature = "client")]
use crate::capture::CaptureContext;
use crate::flow::error::FlowControllerError;
cfg_if! {
    if #[cfg(feature = "client")] {
        use log::warn;
        use rand::Rng;
        use crate::bytes::{ByteBuffer, ByteBufferMut};
        use crate::cache::CachedValue;
        use crate::crypto::{CryptoError, ObfuscationTranscript};
        use crate::flow::config::FlowConfig;
        use crate::settings::consts::TAILOR_LENGTH;
        use crate::tailor::IdentityType;
        use crate::tailor::{PacketFlags, Tailor};
        use crate::utils::random::get_rng;
    }
}

/// Trait for managing packet flow with encryption and decoy traffic.
pub(crate) trait FlowManager {
    /// Send a packet through the flow manager. `fallthrough` is set only by fallthrough decoys and skips the tailor step in `prepare_outgoing`; all other callers pass `false`.
    fn send_packet(&self, packet: DynamicByteBuffer, fallthrough: bool) -> impl Future<Output = Result<(), FlowControllerError>> + Send;

    /// Receive a packet from the flow manager.
    #[cfg(feature = "client")]
    fn receive_packet(&self, packet: DynamicByteBuffer) -> impl Future<Output = Result<DynamicByteBuffer, FlowControllerError>> + Send;
}

impl<T: FlowManager + Send + Sync> FlowManager for Arc<T> {
    fn send_packet(&self, packet: DynamicByteBuffer, fallthrough: bool) -> impl Future<Output = Result<(), FlowControllerError>> + Send {
        (**self).send_packet(packet, fallthrough)
    }

    #[cfg(feature = "client")]
    fn receive_packet(&self, packet: DynamicByteBuffer) -> impl Future<Output = Result<DynamicByteBuffer, FlowControllerError>> + Send {
        (**self).receive_packet(packet)
    }
}

/// Trait for tailor-level cryptographic operations used by flow managers.
#[cfg(feature = "client")]
pub(crate) trait FlowCryptoProvider: Clone + Send + Sync {
    /// The identity type used in tailors.
    type Identity: IdentityType + Clone;

    /// Encrypt tailor bytes for sending.
    fn obfuscate_tailor(&mut self, plaintext: DynamicByteBuffer, pool: &crate::bytes::BytePool) -> Result<DynamicByteBuffer, CryptoError>;

    /// Decrypt received tailor bytes.
    fn deobfuscate_tailor(&mut self, ciphertext: DynamicByteBuffer, pool: &crate::bytes::BytePool) -> Result<(DynamicByteBuffer, ObfuscationTranscript), CryptoError>;

    /// Verify tailor authentication after deobfuscation.
    fn verify_tailor(&mut self, transcript: ObfuscationTranscript) -> Result<(), CryptoError>;

    /// Overhead added by tailor encryption (nonce + auth tags).
    fn tailor_overhead() -> usize;
}

/// Shared send-side state for flow managers.
#[cfg(feature = "client")]
pub(crate) struct FlowSendInternal<CP: FlowCryptoProvider> {
    pub(crate) provider: CachedValue<CP>,
    pub(crate) config: FlowConfig,
    pub(crate) capture: CaptureContext,
}

/// Shared receive-side state for flow managers.
#[cfg(feature = "client")]
pub(crate) struct FlowReceiveInternal<CP: FlowCryptoProvider> {
    pub(crate) provider: CachedValue<CP>,
}

/// Outcome of processing an incoming packet through tailor decryption and verification.
#[cfg(feature = "client")]
pub(crate) enum ProcessIncomingResult {
    /// Tailor verified: packet returned for session-layer processing.
    Valid(DynamicByteBuffer),
    /// Decoy flag set: packet should be silently discarded.
    Decoy,
}

#[cfg(feature = "client")]
impl<CP: FlowCryptoProvider> FlowSendInternal<CP> {
    /// Encrypt tailor, add fake header and body, return assembled packet ready for socket send. When `fallthrough` is set, the trailing plaintext tailor bytes are dropped and the tailor-encryption step is skipped — only fake header / body padding is added on top of the body.
    pub(crate) fn prepare_outgoing(&mut self, packet: DynamicByteBuffer, mtu: usize, pool: &crate::bytes::BytePool, fallthrough: bool) -> Result<DynamicByteBuffer, FlowControllerError> {
        let identity_len = <CP::Identity as IdentityType>::length();
        let full_tailor_len = TAILOR_LENGTH + identity_len;

        let (encrypted_packet, packet_flags, data_len) = if fallthrough {
            // Fallthrough decoy: the input is `[random_body | plaintext_tailor]` (the tailor was written for accounting only) - truncate it to the body and forward as opaque noise.
            let body_only = packet.rebuffer_end(packet.len() - full_tailor_len);
            let body_len = body_only.len();
            (body_only, PacketFlags::DECOY, body_len)
        } else {
            let (packet_data, packet_tailor) = packet.split_buf(packet.len() - full_tailor_len);
            let flags = PacketFlags::from_bits_truncate(*packet_tailor.get(0));
            let data_len = packet_data.len();
            let encrypted = match self.provider.get_mut().map_err(FlowControllerError::MissingCache)?.obfuscate_tailor(packet_tailor, pool) {
                Ok(res) => packet_data.expand_end(res.len()),
                Err(err) => return Err(FlowControllerError::TailorEncryption(err)),
            };
            (encrypted, flags, data_len)
        };

        let fake_header_len = self.config.fake_header_mode.len();
        let full_packet_len = fake_header_len + self.config.fake_body_mode.get_length(mtu, fake_header_len + encrypted_packet.len(), packet_flags.is_service());
        // before_capacity >= max_overhead() >= full_packet_len, so expand_start always succeeds.
        let full_packet = encrypted_packet.expand_start(full_packet_len);

        self.config.fake_header_mode.fill(full_packet.rebuffer_end(fake_header_len));
        get_rng().fill(&mut full_packet.rebuffer_both(fake_header_len, full_packet_len));

        self.capture.record_send(|| {
            let kind = if fallthrough {
                "DecoyFallthrough"
            } else if packet_flags.is_discardable() {
                "Decoy"
            } else if packet_flags.is_service() {
                "Service"
            } else {
                "Data"
            };
            let tailor_overhead = if fallthrough {
                0
            } else {
                CP::tailor_overhead()
            };
            let tailor_len = if fallthrough {
                0
            } else {
                full_tailor_len
            };
            (kind, tailor_len, tailor_overhead, fake_header_len, data_len, full_packet_len - fake_header_len)
        });

        Ok(full_packet)
    }
}

#[cfg(feature = "client")]
impl<CP: FlowCryptoProvider> FlowReceiveInternal<CP> {
    /// Deobfuscate the tailor from a raw wire packet.
    /// Returns `Ok(Some((body, tailor_buf)))` on success, `Ok(None)` on crypto failure
    /// (caller should treat the wire packet as unexpected), or `Err` on a programming error.
    pub(crate) fn deobfuscate_incoming(&mut self, packet: DynamicByteBuffer, pool: &crate::bytes::BytePool) -> Result<Option<(DynamicByteBuffer, DynamicByteBuffer)>, FlowControllerError> {
        let encrypted_tailor_len = <CP::Identity as IdentityType>::length() + CP::tailor_overhead();
        // A wire packet shorter than the encrypted tailor cannot be a valid Typhoon
        // packet — caller treats `None` the same as crypto failure and forwards
        // the buffer to the probe handler, so just bail out without splitting.
        if packet.len() < encrypted_tailor_len {
            warn!("client flow: undersized wire packet ({} < {encrypted_tailor_len})", packet.len());
            return Ok(None);
        }
        let (body, encrypted_tailor) = packet.split_buf(packet.len() - encrypted_tailor_len);
        let cipher = self.provider.get_mut().map_err(FlowControllerError::MissingCache)?;
        match cipher.deobfuscate_tailor(encrypted_tailor, pool) {
            Ok((tailor_buf, transcript)) => match cipher.verify_tailor(transcript) {
                Ok(()) => Ok(Some((body, tailor_buf))),
                Err(err) => {
                    warn!("client flow: tailor verification failed: {err}");
                    Ok(None)
                }
            },
            Err(err) => {
                warn!("client flow: tailor decryption failed: {err}");
                Ok(None)
            }
        }
    }

    /// Classify and extract payload from pre-deobfuscated components.
    #[allow(clippy::unused_self)]
    pub(crate) fn process_with_tailor(&self, body: DynamicByteBuffer, tailor_buf: DynamicByteBuffer) -> ProcessIncomingResult {
        let identity_len = <CP::Identity as IdentityType>::length();
        let full_tailor_len = TAILOR_LENGTH + identity_len;
        let tailor = Tailor::<CP::Identity>::new(tailor_buf);
        if tailor.flags().is_discardable() {
            return ProcessIncomingResult::Decoy;
        }
        let payload_len = tailor.payload_length() as usize;
        ProcessIncomingResult::Valid(body.rebuffer_start(body.len() - payload_len).expand_end(full_tailor_len))
    }
}
