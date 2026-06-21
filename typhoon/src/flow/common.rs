#[cfg(feature = "client")]
use std::future::Future;
#[cfg(feature = "client")]
use std::sync::Arc;

use cfg_if::cfg_if;

#[cfg(feature = "client")]
use crate::bytes::DynamicByteBuffer;
#[cfg(feature = "client")]
use crate::capture::CaptureContext;
#[cfg(feature = "client")]
use crate::flow::error::FlowControllerError;
cfg_if! {
    if #[cfg(feature = "client")] {
        use log::warn;
        use rand::Rng;
        use crate::bytes::{ByteBuffer, ByteBufferMut};
        use crate::cache::CachedValue;
        use crate::crypto::ClientCryptoTool;
        use crate::flow::config::FlowConfig;
        use crate::tailer::IdentityType;
        use crate::tailer::{PacketFlags, Tailer};
        use crate::utils::random::get_rng;
    }
}

/// Trait for managing packet flow with encryption and decoy traffic.
#[cfg(feature = "client")]
pub(crate) trait FlowManager {
    /// Send a packet through the flow manager.
    /// * `fallthrough` is set only by fallthrough decoys and skips the tailer step in `prepare_outgoing`; all other callers pass `false`.
    /// * `is_maintenance` is `true` for maintenance-sub-stream decoy packets and selects the `FakeBodyMode::Random { service: true }` emission at the fake-body stage; all non-decoy callers and non-maintenance decoy callers pass `false`.
    fn send_packet(&self, packet: DynamicByteBuffer, fallthrough: bool, is_maintenance: bool) -> impl Future<Output = Result<(), FlowControllerError>> + Send;

    /// Receive a packet from the flow manager.
    #[cfg(feature = "client")]
    fn receive_packet(&self, packet: DynamicByteBuffer) -> impl Future<Output = Result<DynamicByteBuffer, FlowControllerError>> + Send;
}

#[cfg(feature = "client")]
impl<T: FlowManager + Send + Sync> FlowManager for Arc<T> {
    fn send_packet(&self, packet: DynamicByteBuffer, fallthrough: bool, is_maintenance: bool) -> impl Future<Output = Result<(), FlowControllerError>> + Send {
        (**self).send_packet(packet, fallthrough, is_maintenance)
    }

    #[cfg(feature = "client")]
    fn receive_packet(&self, packet: DynamicByteBuffer) -> impl Future<Output = Result<DynamicByteBuffer, FlowControllerError>> + Send {
        (**self).receive_packet(packet)
    }
}

/// Shared send-side state for flow managers.
#[cfg(feature = "client")]
pub(crate) struct FlowSendInternal<T: IdentityType + Clone> {
    pub(crate) provider: CachedValue<ClientCryptoTool<T>>,
    pub(crate) config: FlowConfig,
    pub(crate) capture: CaptureContext,
}

/// Shared receive-side state for flow managers.
#[cfg(feature = "client")]
pub(crate) struct FlowReceiveInternal<T: IdentityType + Clone> {
    pub(crate) provider: CachedValue<ClientCryptoTool<T>>,
}

/// Outcome of processing an incoming packet through tailer decryption and verification.
#[cfg(feature = "client")]
pub(crate) enum ProcessIncomingResult {
    /// Tailer verified: packet returned for session-layer processing.
    Valid(DynamicByteBuffer),
    /// Decoy flag set: packet should be silently discarded.
    Decoy,
}

#[cfg(feature = "client")]
impl<T: IdentityType + Clone> FlowSendInternal<T> {
    /// Encrypt tailer, add fake header and body, return assembled packet ready for socket send.
    /// * When `fallthrough` is set, the trailing plaintext tailer bytes are dropped and the tailer-encryption step is skipped --- only fake header / body padding is added on top of the body.
    /// * When `is_maintenance` is set, the `FakeBodyMode::Random { service: true }` body is emitted on this packet (and only then); all other callers pass `false`.
    pub(crate) fn prepare_outgoing(&mut self, packet: DynamicByteBuffer, mtu: usize, pool: &crate::bytes::BytePool, fallthrough: bool, is_maintenance: bool) -> Result<DynamicByteBuffer, FlowControllerError> {
        let full_tailer_len = Tailer::<T>::len();

        let (encrypted_packet, packet_flags, data_len) = if fallthrough {
            // Fallthrough decoy: the input is `[random_body | plaintext_tailer]` (the tailer was written for accounting only) - truncate it to the body and forward as opaque noise.
            let body_only = packet.rebuffer_end(packet.len() - full_tailer_len);
            let body_len = body_only.len();
            (body_only, PacketFlags::DECOY, body_len)
        } else {
            let (packet_data, packet_tailer) = packet.split_buf_end(full_tailer_len);
            let flags = PacketFlags::from_bits_truncate(*packet_tailer.get(0));
            let data_len = packet_data.len();
            let encrypted = match self.provider.get_mut().map_err(FlowControllerError::MissingCache)?.obfuscate_tailer(packet_tailer, pool) {
                Ok(res) => packet_data.expand_end(res.len()),
                Err(err) => return Err(FlowControllerError::TailerEncryption(err)),
            };
            (encrypted, flags, data_len)
        };

        let fake_header_len = self.config.fake_header_mode.len();
        let full_packet_len = fake_header_len + self.config.fake_body_mode.get_length(mtu, fake_header_len + encrypted_packet.len(), is_maintenance);
        // before_capacity >= max_overhead() >= full_packet_len, so expand_start always succeeds.
        let full_packet = encrypted_packet.expand_start(full_packet_len);

        self.config.fake_header_mode.fill(full_packet.rebuffer_end(fake_header_len));
        get_rng().fill(&mut full_packet.rebuffer_both(fake_header_len, full_packet_len));

        self.capture.record_send(|| {
            let kind = if fallthrough {
                "DecoyFallthrough"
            } else if is_maintenance {
                "DecoyMaintenance"
            } else if packet_flags.is_discardable() {
                "Decoy"
            } else {
                "Data"
            };
            let tailer_overhead = if fallthrough {
                0
            } else {
                crate::crypto::TAILER_C2S_OVERHEAD
            };
            let tailer_len = if fallthrough {
                0
            } else {
                full_tailer_len
            };
            (kind, tailer_len, tailer_overhead, fake_header_len, data_len, full_packet_len - fake_header_len)
        });

        Ok(full_packet)
    }
}

#[cfg(feature = "client")]
impl<T: IdentityType + Clone> FlowReceiveInternal<T> {
    /// Deobfuscate the tailer from a raw wire packet.
    /// Returns `Ok(Some((body, tailer_buf)))` on success, `Ok(None)` on crypto failure
    /// (caller should treat the wire packet as unexpected), or `Err` on a programming error.
    pub(crate) fn deobfuscate_incoming(&mut self, packet: DynamicByteBuffer, pool: &crate::bytes::BytePool) -> Result<Option<(DynamicByteBuffer, DynamicByteBuffer)>, FlowControllerError> {
        let encrypted_tailer_len = Tailer::<T>::encrypted_len_s2c();
        // A wire packet shorter than the encrypted tailer cannot be a valid Typhoon
        // packet — caller treats `None` the same as crypto failure and forwards
        // the buffer to the probe handler, so just bail out without splitting.
        if packet.len() < encrypted_tailer_len {
            warn!("client flow: undersized wire packet ({} < {encrypted_tailer_len})", packet.len());
            return Ok(None);
        }
        let (body, encrypted_tailer) = packet.split_buf_end(encrypted_tailer_len);
        let cipher = self.provider.get_mut().map_err(FlowControllerError::MissingCache)?;
        match cipher.deobfuscate_tailer(encrypted_tailer, pool) {
            Ok((tailer_buf, transcript)) => match cipher.verify_tailer(transcript) {
                Ok(()) => Ok(Some((body, tailer_buf))),
                Err(err) => {
                    warn!("client flow: tailer verification failed: {err}");
                    Ok(None)
                }
            },
            Err(err) => {
                warn!("client flow: tailer decryption failed: {err}");
                Ok(None)
            }
        }
    }

    /// Classify and extract payload from pre-deobfuscated components.
    #[allow(clippy::unused_self)]
    pub(crate) fn process_with_tailer(&self, body: DynamicByteBuffer, tailer_buf: DynamicByteBuffer) -> ProcessIncomingResult {
        let full_tailer_len = Tailer::<T>::len();
        let Some(tailer) = Tailer::<T>::validated(tailer_buf, body.len()) else {
            warn!("client flow: malformed tailer (size, flags or payload_length out of range), dropping packet");
            return ProcessIncomingResult::Decoy;
        };
        if tailer.flags().is_discardable() {
            return ProcessIncomingResult::Decoy;
        }
        let payload_len = tailer.payload_length() as usize;
        ProcessIncomingResult::Valid(body.rebuffer_start(body.len() - payload_len).expand_end(full_tailer_len))
    }
}
