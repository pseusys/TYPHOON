use std::sync::Arc;

use log::{debug, info};
use rand::Rng;

use crate::bytes::ByteBuffer;
use crate::cache::CachedValue;
use crate::crypto::CryptoTool;
use crate::flow::common::FlowManager;
use crate::flow::config::FlowConfig;
use crate::flow::decoy::DecoyCommunicationMode;
use crate::flow::error::FlowControllerError;
use crate::tailor::{PacketFlags, Tailor};
use crate::utils::random::get_rng;
use crate::utils::socket::Socket;
use crate::utils::sync::RwLock;

struct ClientFlowManagerInternalMutable<T: CryptoTool + Clone + Send, FMT: FlowManager, DP: DecoyCommunicationMode<FlowManagerT = FMT>> {
    provider: CachedValue<T>,
    config: FlowConfig,
    sock: Socket,
    decoy: DP,
    mtu: usize,
}

pub struct ClientFlowManager<T: CryptoTool + Clone + Send, DP: DecoyCommunicationMode<FlowManagerT = Self>> {
    internal: RwLock<ClientFlowManagerInternalMutable<T, Self, DP>>,
}

impl<T: CryptoTool + Clone + Send, DP: DecoyCommunicationMode<FlowManagerT = Self>> ClientFlowManager<T, DP> {
    async fn new_with_socket(config: FlowConfig, cipher: CachedValue<T>, mtu: usize, sock: Socket) -> Arc<Self> {
        Arc::new_cyclic(|m| ClientFlowManager {
            internal: RwLock::new(ClientFlowManagerInternalMutable {
                provider: cipher,
                config: config,
                sock: sock,
                decoy: DP::new(m.clone()),
                mtu,
            }),
        })
    }
}

impl<T: CryptoTool + Clone + Send, DP: DecoyCommunicationMode<FlowManagerT = Self>> FlowManager for ClientFlowManager<T, DP> {
    /// Packet should consist of: encrypted payload || valid plaintext tailor.
    /// NB! DecoyCommunicationMode implementations *should not* send non-decoy packets via this method, but they can, if they want.
    async fn send_packet(&self, packet: ByteBuffer, tailor_len: usize) -> Result<(), FlowControllerError> {
        let mut writer = self.internal.write().await;

        let notified_packet = writer.decoy.feed(packet, tailor_len);
        if let None = notified_packet {
            return Ok(());
        }

        let (packet_data, tailor_len) = notified_packet.unwrap();
        let (packet_data, packet_tailor) = packet_data.split_buf(packet_data.len() - tailor_len);
        let packet_flags = PacketFlags::from_bits_truncate(packet_tailor.get(0).clone());
        let encrypted_packet = match writer.provider.get_mut().await {
            Ok(cipher) => match cipher.obfuscate_tailor(packet_tailor) {
                Ok(res) => packet_data.expand_end(res.len()),
                Err(err) => return Err(FlowControllerError::TailorEncryption(err)),
            },
            Err(err) => return Err(FlowControllerError::MissingCache(err)),
        };

        let fake_header_len = writer.config.fake_header_mode.len();
        let full_packet_len = fake_header_len + writer.config.fake_body_mode.get_length(writer.mtu, fake_header_len + encrypted_packet.len(), packet_flags.is_service());
        let full_packet = encrypted_packet.expand_start(full_packet_len);

        writer.config.fake_header_mode.fill(full_packet.rebuffer_end(fake_header_len));
        get_rng().fill(&mut full_packet.rebuffer_both(fake_header_len, full_packet_len));

        match writer.sock.send(&full_packet).await {
            Ok(_) => Ok(()),
            Err(err) => Err(FlowControllerError::SocketError(err)),
        }
    }

    async fn receive_packet(&self, packet: ByteBuffer, tailor_len: usize) -> Result<ByteBuffer, FlowControllerError> {
        let mut writer = self.internal.write().await;

        loop {
            let packet = match writer.sock.recv(&packet).await {
                Ok(res) => res,
                Err(err) => return Err(FlowControllerError::SocketError(err)),
            };

            let (encrypted_packet, encrypted_tailor) = packet.split_buf(packet.len() - tailor_len - T::tailor_overhead());
            let tailor = match writer.provider.get_mut().await {
                Ok(cipher) => match cipher.deobfuscate_tailor(encrypted_tailor) {
                    Ok((tailor, transcript)) => match cipher.verify_tailor(transcript) {
                        Ok(_) => tailor,
                        Err(err) => {
                            debug!("error verifying packet tailor: {}", err);
                            continue;
                        }
                    },
                    Err(err) => {
                        debug!("error decrypting packet tailor: {}", err);
                        continue;
                    }
                },
                Err(err) => return Err(FlowControllerError::MissingCache(err)),
            };

            let packet_flags = PacketFlags::from_bits_truncate(tailor.get(0).clone());
            if packet_flags.is_discardable() {
                info!("decoy packet received, skipping...");
                continue;
            }

            let payload_len = Tailor::get_payload_length(&tailor) as usize;
            return Ok(encrypted_packet.rebuffer_start(encrypted_packet.len() - payload_len).expand_end(tailor_len));
        }
    }
}
