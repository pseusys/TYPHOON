/// Server-side flow manager implementation.
use std::collections::HashMap;
use std::hash::Hash;
use std::sync::Arc;

use log::{debug, info};
use rand::Rng;

use crate::bytes::{ByteBuffer, ByteBufferMut, DynamicByteBuffer};
use crate::crypto::ServerCryptoTool;
use crate::flow::common::FlowManager;
use crate::flow::config::FlowConfig;
use crate::flow::decoy::DecoyCommunicationMode;
use crate::flow::error::FlowControllerError;
use crate::settings::Settings;
use crate::tailor::{IdentityType, PacketFlags, Tailor};
use crate::utils::random::get_rng;
use crate::utils::socket::Socket;
use crate::utils::sync::{AsyncExecutor, Mutex};

/// Server-side flow manager that handles per-user packet encryption, decoy traffic, and socket I/O.
/// User addresses and crypto state are stored in the global SharedMap (accessed via ServerCryptoTool).
/// Per-user decoy providers are local to each flow manager instance.
pub struct ServerFlowManager<T: IdentityType + Clone + Eq + Hash + Send + ToString, AE: AsyncExecutor, DP: Send + Sync> {
    decoy_providers: Mutex<HashMap<T, DP>>,
    crypto: Mutex<ServerCryptoTool<T>>,
    config: Mutex<FlowConfig>,
    sock: Socket,
    mtu: usize,
    settings: Arc<Settings<AE>>,
}

impl<T: IdentityType + Clone + Eq + Hash + Send + ToString + 'static, AE: AsyncExecutor + 'static, DP: DecoyCommunicationMode<T, AE, Self> + 'static> ServerFlowManager<T, AE, DP> {
    /// Create a new server flow manager.
    pub fn new(config: FlowConfig, crypto: ServerCryptoTool<T>, settings: Arc<Settings<AE>>, sock: Socket) -> Arc<Self> {
        Arc::new(ServerFlowManager {
            decoy_providers: Mutex::new(HashMap::new()),
            crypto: Mutex::new(crypto),
            config: Mutex::new(config),
            sock,
            mtu: settings.mtu(),
            settings,
        })
    }

    /// Register a per-user decoy provider and start its background timer.
    /// The user's address and crypto state must already be in the global SharedMap.
    pub async fn register_user(self: &Arc<Self>, id: T) {
        let weak = Arc::downgrade(self);
        let mut dp = DP::new(weak, self.settings.clone(), id.clone());
        dp.start().await;
        let mut providers = self.decoy_providers.lock().await;
        providers.insert(id, dp);
    }

    /// Remove a user's decoy provider from this flow manager.
    pub async fn remove_user(&self, id: &T) {
        let mut providers = self.decoy_providers.lock().await;
        providers.remove(id);
    }
}

impl<T: IdentityType + Clone + Eq + Hash + Send + ToString + 'static, AE: AsyncExecutor + 'static, DP: DecoyCommunicationMode<T, AE, Self> + 'static> FlowManager for ServerFlowManager<T, AE, DP> {
    async fn send_packet(&self, packet: DynamicByteBuffer, generated: bool) -> Result<(), FlowControllerError> {
        let identity_len = T::length();

        // Extract identity from the plaintext tailor at the end of the packet.
        let tailor_buf = packet.rebuffer_start(packet.len() - identity_len);
        let identity = ServerCryptoTool::<T>::extract_identity(&tailor_buf);

        // Feed decoy provider for rate tracking.
        let notified_packet = {
            let mut providers = self.decoy_providers.lock().await;
            if let Some(dp) = providers.get_mut(&identity) {
                let notified = dp.feed_output(packet, generated).await;
                if notified.is_none() {
                    return Ok(());
                }
                notified.unwrap()
            } else {
                packet
            }
        };

        // Look up user address from global state (via crypto tool).
        let addr = {
            let mut crypto = self.crypto.lock().await;
            crypto.get_user_addr(&identity).await.map_err(|_| FlowControllerError::UserNotFound {
                identity: identity.to_string(),
            })?
        };

        // Split into data + tailor, encrypt tailor.
        let (packet_data, packet_tailor) = notified_packet.split_buf(notified_packet.len() - identity_len);
        let packet_flags = PacketFlags::from_bits_truncate(packet_tailor.get(0).clone());

        let encrypted_tailor = {
            let mut crypto = self.crypto.lock().await;
            crypto.obfuscate_tailor(packet_tailor, self.settings.pool()).await.map_err(FlowControllerError::TailorEncryption)?
        };
        let encrypted_packet = packet_data.expand_end(encrypted_tailor.len());

        // Add fake header and body.
        let mut config = self.config.lock().await;
        let fake_header_len = config.fake_header_mode.len();
        let full_packet_len = fake_header_len + config.fake_body_mode.get_length(self.mtu, fake_header_len + encrypted_packet.len(), packet_flags.is_service());
        let full_packet = encrypted_packet.expand_start(full_packet_len);

        config.fake_header_mode.fill(full_packet.rebuffer_end(fake_header_len));
        get_rng().fill(&mut full_packet.rebuffer_both(fake_header_len, full_packet_len));
        drop(config);

        self.sock.send_to(full_packet, addr).await.map_err(FlowControllerError::SocketError)?;
        Ok(())
    }

    async fn receive_packet(&self, packet: DynamicByteBuffer) -> Result<DynamicByteBuffer, FlowControllerError> {
        let identity_len = T::length();
        let tailor_overhead = ServerCryptoTool::<T>::tailor_overhead();

        loop {
            let (packet, _source_addr) = self.sock.recv_from(packet.clone()).await.map_err(FlowControllerError::SocketError)?;

            // Strip encrypted tailor from the end.
            let (encrypted_packet, encrypted_tailor) = packet.split_buf(packet.len() - identity_len - tailor_overhead);

            // Deobfuscate and verify tailor.
            let (tailor, identity) = {
                let mut crypto = self.crypto.lock().await;
                let (tailor, transcript) = match crypto.deobfuscate_tailor(encrypted_tailor) {
                    Ok(result) => result,
                    Err(err) => {
                        debug!("error decrypting packet tailor: {}", err);
                        continue;
                    }
                };
                let identity = ServerCryptoTool::<T>::extract_identity(&tailor);
                match crypto.verify_tailor(&identity, transcript).await {
                    Ok(_) => {}
                    Err(err) => {
                        debug!("error verifying packet tailor: {}", err);
                        continue;
                    }
                }
                (tailor, identity)
            };

            // Feed decoy provider for rate tracking.
            {
                let mut providers = self.decoy_providers.lock().await;
                if let Some(dp) = providers.get_mut(&identity) {
                    let notified = dp.feed_input(tailor.clone()).await;
                    if notified.is_none() {
                        continue;
                    }
                }
            }

            // Check if decoy packet.
            let packet_flags = PacketFlags::from_bits_truncate(tailor.get(0).clone());
            if packet_flags.is_discardable() {
                info!("decoy packet received, skipping...");
                continue;
            }

            // Extract payload.
            let payload_len = Tailor::<T>::get_payload_length(&tailor) as usize;
            return Ok(encrypted_packet.rebuffer_start(encrypted_packet.len() - payload_len).expand_end(identity_len));
        }
    }
}
