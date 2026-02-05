use std::sync::Arc;

use log::{debug, info};
use rand::Rng;

use crate::bytes::ByteBuffer;
use crate::cache::CachedValue;
use crate::constants::Settings;
use crate::crypto::ClientCryptoTool;
use crate::flow::common::FlowManager;
use crate::flow::config::FlowConfig;
use crate::flow::decoy::DecoyCommunicationMode;
use crate::flow::error::FlowControllerError;
use crate::tailor::{PacketFlags, Tailor};
use crate::utils::random::get_rng;
use crate::utils::socket::Socket;
use crate::utils::sync::Mutex;

struct ClientFlowManagerInternalSend<'a> {
    provider: CachedValue<ClientCryptoTool<'a>>,
    config: FlowConfig,
}

struct ClientFlowManagerInternalReceive<'a> {
    provider: CachedValue<ClientCryptoTool<'a>>,
}

pub struct ClientFlowManager<'a, DP: DecoyCommunicationMode<FlowManagerT = Self>> {
    decoy_provider: Mutex<DP>,
    send_internal: Mutex<ClientFlowManagerInternalSend<'a>>,
    receive_internal: Mutex<ClientFlowManagerInternalReceive<'a>>,
    sock: Socket,
    mtu: usize,
    tailor: usize,
    settings: Arc<Settings>,
}

impl<'a, DP: DecoyCommunicationMode<FlowManagerT = Self>> ClientFlowManager<'a, DP> {
    async fn new(config: FlowConfig, cipher: CachedValue<ClientCryptoTool<'a>>, settings: Arc<Settings>, mtu: usize, tailor: usize, sock: Socket) -> Result<Arc<Self>, FlowControllerError> {
        let send_provider = cipher.create_sibling().await.map_err(FlowControllerError::MissingCache)?;
        let receive_provider = cipher.create_sibling().await.map_err(FlowControllerError::MissingCache)?;
        let value = Arc::new_cyclic(|m| ClientFlowManager {
            decoy_provider: Mutex::new(DP::new(m.clone(), settings.clone(), tailor)),
            send_internal: Mutex::new(ClientFlowManagerInternalSend {
                provider: send_provider,
                config,
            }),
            receive_internal: Mutex::new(ClientFlowManagerInternalReceive {
                provider: receive_provider,
            }),
            sock,
            mtu,
            tailor,
            settings,
        });
        value.decoy_provider.lock().await.start().await;
        Ok(value)
    }
}

impl<'a, DP: DecoyCommunicationMode<FlowManagerT = Self>> FlowManager for ClientFlowManager<'a, DP> {
    /// Packet should consist of: encrypted payload || valid plaintext tailor.
    /// NB! DecoyCommunicationMode implementations *should not* send non-decoy packets via this method, but they can, if they want.
    async fn send_packet(&self, packet: ByteBuffer, generated: bool) -> Result<(), FlowControllerError> {
        let notified_packet = {
            let mut lock = self.decoy_provider.lock().await;
            let notified_packet = lock.feed_output(packet, generated).await;
            if notified_packet.is_none() {
                return Ok(());
            }
            notified_packet
        };

        let mut lock = self.send_internal.lock().await;
        let input_packet = notified_packet.unwrap();

        let (packet_data, packet_tailor) = input_packet.split_buf(input_packet.len() - self.tailor);
        let packet_flags = PacketFlags::from_bits_truncate(packet_tailor.get(0).clone());
        let encrypted_packet = match lock.provider.get_mut().await {
            Ok(cipher) => match cipher.obfuscate_tailor(packet_tailor) {
                Ok(res) => packet_data.expand_end(res.len()),
                Err(err) => return Err(FlowControllerError::TailorEncryption(err)),
            },
            Err(err) => return Err(FlowControllerError::MissingCache(err)),
        };

        let fake_header_len = lock.config.fake_header_mode.len();
        let full_packet_len = fake_header_len + lock.config.fake_body_mode.get_length(self.mtu, fake_header_len + encrypted_packet.len(), packet_flags.is_service());
        let full_packet = encrypted_packet.expand_start(full_packet_len);

        lock.config.fake_header_mode.fill(full_packet.rebuffer_end(fake_header_len));
        get_rng().fill(&mut full_packet.rebuffer_both(fake_header_len, full_packet_len));

        match self.sock.send(full_packet.clone()).await {
            Ok(_) => Ok(()),
            Err(err) => Err(FlowControllerError::SocketError(err)),
        }
    }

    async fn receive_packet(&self, packet: ByteBuffer) -> Result<ByteBuffer, FlowControllerError> {
        loop {
            let packet = match self.sock.recv(packet.clone()).await {
                Ok(res) => res,
                Err(err) => return Err(FlowControllerError::SocketError(err)),
            };

            let notified_packet = {
                let mut lock = self.decoy_provider.lock().await;
                let notified_packet = lock.feed_input(packet).await;
                if notified_packet.is_none() {
                    continue;
                }
                notified_packet
            };

            let mut lock = self.receive_internal.lock().await;
            let input_packet = notified_packet.unwrap();

            let (encrypted_packet, encrypted_tailor) = input_packet.split_buf(input_packet.len() - self.tailor - ClientCryptoTool::tailor_overhead());
            let tailor = match lock.provider.get_mut().await {
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
            return Ok(encrypted_packet.rebuffer_start(encrypted_packet.len() - payload_len).expand_end(self.tailor));
        }
    }
}
