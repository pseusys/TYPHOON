use std::sync::Arc;

use log::{debug, info};
use rand::Rng;

use crate::bytes::{ByteBuffer, ByteBufferMut, DynamicByteBuffer};
use crate::cache::CachedValue;
use crate::crypto::ClientCryptoTool;
use crate::flow::common::FlowManager;
use crate::flow::config::FlowConfig;
use crate::flow::decoy::DecoyCommunicationMode;
use crate::flow::error::FlowControllerError;
use crate::settings::Settings;
use crate::tailor::{IdentityType, PacketFlags, Tailor};
use crate::utils::random::get_rng;
use crate::utils::socket::Socket;
use crate::utils::sync::{AsyncExecutor, Mutex};

struct ClientFlowManagerInternalSend<T: IdentityType + Clone> {
    provider: CachedValue<ClientCryptoTool<T>>,
    config: FlowConfig,
}

struct ClientFlowManagerInternalReceive<T: IdentityType + Clone> {
    provider: CachedValue<ClientCryptoTool<T>>,
}

/// Client-side flow manager that handles packet encryption, decoy traffic, and socket I/O.
pub struct ClientFlowManager<T: IdentityType + Clone, AE: AsyncExecutor, DP: Send + Sync> {
    decoy_provider: Mutex<DP>,
    send_internal: Mutex<ClientFlowManagerInternalSend<T>>,
    receive_internal: Mutex<ClientFlowManagerInternalReceive<T>>,
    sock: Socket,
    mtu: usize,
    settings: Arc<Settings<AE>>,
}

impl<T: IdentityType + Clone + 'static, AE: AsyncExecutor + 'static, DP: DecoyCommunicationMode<AE, Self> + 'static> ClientFlowManager<T, AE, DP> {
    pub(crate) async fn new(config: FlowConfig, cipher: CachedValue<ClientCryptoTool<T>>, settings: Arc<Settings<AE>>, sock: Socket) -> Result<Arc<Self>, FlowControllerError> {
        let send_provider = cipher.create_sibling().await.map_err(FlowControllerError::MissingCache)?;
        let receive_provider = cipher.create_sibling().await.map_err(FlowControllerError::MissingCache)?;
        let value = Arc::new_cyclic(|m| ClientFlowManager {
            decoy_provider: Mutex::new(DP::new(m.clone(), settings.clone())),
            send_internal: Mutex::new(ClientFlowManagerInternalSend {
                provider: send_provider,
                config,
            }),
            receive_internal: Mutex::new(ClientFlowManagerInternalReceive {
                provider: receive_provider,
            }),
            sock,
            mtu: settings.mtu(),
            settings,
        });
        value.decoy_provider.lock().await.start().await;
        Ok(value)
    }
}

impl<T: IdentityType + Clone + 'static, AE: AsyncExecutor + 'static, DP: DecoyCommunicationMode<AE, Self> + 'static> FlowManager for ClientFlowManager<T, AE, DP> {
    /// Packet should consist of: encrypted payload || valid plaintext tailor.
    /// NB! DecoyCommunicationMode implementations *should not* send non-decoy packets via this method, but they can, if they want.
    async fn send_packet(&self, packet: DynamicByteBuffer, generated: bool) -> Result<(), FlowControllerError> {
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

        let (packet_data, packet_tailor) = input_packet.split_buf(input_packet.len() - T::length());
        let packet_flags = PacketFlags::from_bits_truncate(packet_tailor.get(0).clone());
        let encrypted_packet = match lock.provider.get_mut().await.map_err(FlowControllerError::MissingCache)?.obfuscate_tailor(packet_tailor, self.settings.pool()) {
            Ok(res) => packet_data.expand_end(res.len()),
            Err(err) => return Err(FlowControllerError::TailorEncryption(err)),
        };

        let fake_header_len = lock.config.fake_header_mode.len();
        let full_packet_len = fake_header_len + lock.config.fake_body_mode.get_length(self.mtu, fake_header_len + encrypted_packet.len(), packet_flags.is_service());
        let full_packet = encrypted_packet.expand_start(full_packet_len);

        lock.config.fake_header_mode.fill(full_packet.rebuffer_end(fake_header_len));
        get_rng().fill(&mut full_packet.rebuffer_both(fake_header_len, full_packet_len));

        self.sock.send(full_packet.clone()).await.map_err(FlowControllerError::SocketError)?;
        Ok(())
    }

    async fn receive_packet(&self, packet: DynamicByteBuffer) -> Result<DynamicByteBuffer, FlowControllerError> {
        loop {
            let packet = self.sock.recv(packet.clone()).await.map_err(FlowControllerError::SocketError)?;
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

            let (encrypted_packet, encrypted_tailor) = input_packet.split_buf(input_packet.len() - T::length() - ClientCryptoTool::<T>::tailor_overhead());
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

            let payload_len = Tailor::<T>::get_payload_length(&tailor) as usize;
            return Ok(encrypted_packet.rebuffer_start(encrypted_packet.len() - payload_len).expand_end(T::length()));
        }
    }
}
