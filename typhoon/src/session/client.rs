/// Client-side session manager implementation.
use std::mem::take;
use std::sync::Arc;

use log::{debug, info};

use crate::bytes::{ByteBuffer, ByteBufferMut, DynamicByteBuffer};
use crate::cache::SharedValue;
use crate::crypto::ClientCryptoTool;
use crate::flow::FlowManager;
use crate::session::common::SessionManager;
use crate::session::error::SessionControllerError;
use crate::session::health::HealthProvider;
use crate::settings::Settings;
use crate::settings::consts::TAILOR_LENGTH;
use crate::tailor::{IdentityType, PacketFlags, Tailor};
use crate::utils::random::{SupportRng, get_rng};
use crate::utils::sync::{AsyncExecutor, Mutex, create_channel};

struct ClientSessionManagerInternalSend<T: IdentityType + Clone> {
    cipher: SharedValue<ClientCryptoTool<T>>,
    incremental_counter: u32,
}

struct ClientSessionManagerInternalReceive<T: IdentityType + Clone> {
    cipher: SharedValue<ClientCryptoTool<T>>,
}

/// Client-side session manager that encrypts data and manages health checking.
pub struct ClientSessionManager<T: IdentityType + Clone + 'static, AE: AsyncExecutor + 'static, FM: FlowManager + Send + Sync + 'static> {
    health_provider: HealthProvider<T, AE, Self>,
    send_internal: Mutex<ClientSessionManagerInternalSend<T>>,
    receive_internal: Mutex<ClientSessionManagerInternalReceive<T>>,
    flows: Vec<FM>,
    settings: Arc<Settings<AE>>,
}

impl<T: IdentityType + Clone> ClientSessionManagerInternalSend<T> {
    fn next_packet_number(&mut self) -> u64 {
        self.incremental_counter += 1;
        let timestamp = (crate::utils::time::unix_timestamp_ms() / 1000) as u32;
        ((timestamp as u64) << 32) | (self.incremental_counter as u64)
    }
}

impl<T: IdentityType + Clone, AE: AsyncExecutor, FM: FlowManager + Send + Sync> ClientSessionManager<T, AE, FM> {
    /// Create a new client session manager without starting the handshake.
    /// Call `start()` after the background receive loop is running.
    pub async fn new(cipher: SharedValue<ClientCryptoTool<T>>, flows: Vec<FM>, settings: Arc<Settings<AE>>) -> Result<Arc<Self>, SessionControllerError> {
        let send_cipher = cipher.create_sibling().await;
        let receive_cipher = cipher.create_sibling().await;
        let health_state_crypto = cipher.create_sibling().await;

        let (response_tx, response_rx) = create_channel(1);
        let (shadowride_tx, _) = create_channel(1);

        let value = Arc::new_cyclic(|weak| {
            let health_provider = HealthProvider::new(weak.clone(), settings.clone(), health_state_crypto, response_tx, shadowride_tx, response_rx);

            ClientSessionManager {
                health_provider,
                send_internal: Mutex::new(ClientSessionManagerInternalSend {
                    cipher: send_cipher,
                    incremental_counter: 0,
                }),
                receive_internal: Mutex::new(ClientSessionManagerInternalReceive {
                    cipher: receive_cipher,
                }),
                flows,
                settings,
            }
        });

        Ok(value)
    }

    /// Perform the initial handshake and start the background health check timer.
    /// Must be called after the background receive loop is running so that
    /// handshake responses can be received and fed back to the health provider.
    pub async fn start(&self) -> Result<(), SessionControllerError> {
        self.health_provider.perform_handshake().await;
        Ok(())
    }

    /// Select a flow manager (currently uses the first one).
    fn select_flow(&self) -> &FM {
        get_rng().random_item(&self.flows).expect("at least one flow manager required")
    }
}

impl<T: IdentityType + Clone, AE: AsyncExecutor, FM: FlowManager + Send + Sync> SessionManager for ClientSessionManager<T, AE, FM> {
    async fn send_packet(&self, packet: DynamicByteBuffer, generated: bool) -> Result<(), SessionControllerError> {
        let full_packet = if generated {
            // Health provider already assembled (body + tailor), pass through directly.
            packet
        } else {
            // User data: encrypt payload, create DATA tailor, check for shadowriding.
            let mut send_lock = self.send_internal.lock().await;
            let encrypted_payload = send_lock.cipher.get_mut().await.encrypt_payload(packet, None).map_err(SessionControllerError::CryptoError)?;

            let payload_length = encrypted_payload.len() as u16;
            let packet_number = send_lock.next_packet_number();
            let identity = send_lock.cipher.get().await.identity();

            let encrypted_payload_len = encrypted_payload.len();
            let tailor_buf = encrypted_payload.expand_end(T::length()).rebuffer_start(encrypted_payload_len);
            let tailor = Tailor::data(tailor_buf, &identity, payload_length, packet_number);

            // Let health provider potentially attach a shadowride.
            // Clone is cheap (Arc), and writes are visible through the shared buffer.
            self.health_provider.feed_output(tailor.clone()).await?;

            // Include encrypted payload: encrypted_payload || tailor (TAILOR_LENGTH + T::length() bytes).
            encrypted_payload.expand_end(TAILOR_LENGTH + T::length())
        };

        self.select_flow().send_packet(full_packet, false).await.map_err(SessionControllerError::FlowError)
    }

    async fn receive_packet(&self) -> Result<DynamicByteBuffer, SessionControllerError> {
        let recv_buf = self.settings.pool().allocate(None);

        loop {
            let packet = self.select_flow().receive_packet(recv_buf.clone()).await.map_err(SessionControllerError::FlowError)?;

            // The flow manager returns: encrypted_payload || plaintext_tailor (full TAILOR_LENGTH + T::length() bytes).
            let (payload_part, tailor_part) = packet.split_buf(packet.len() - T::length() - TAILOR_LENGTH);
            let tailor = Tailor::<T>::new(tailor_part);

            // Handle termination.
            if tailor.flags().is_termination() {
                return Err(SessionControllerError::ConnectionTerminated(tailor.code()));
            }

            // Handle handshake response.
            if tailor.flags().contains(PacketFlags::HANDSHAKE) {
                self.health_provider.feed_handshake_input(tailor.clone(), payload_part.clone()).await?;
            }

            // Handle health check (standalone or shadowride).
            if tailor.flags().contains(PacketFlags::HEALTH_CHECK) {
                self.health_provider.feed_input(tailor.clone()).await?;
            }

            // If there is data payload, decrypt and return.
            if tailor.flags().has_payload() {
                let mut recv_lock = self.receive_internal.lock().await;
                match recv_lock.cipher.get_mut().await.decrypt_payload(payload_part, None) {
                    Ok(decrypted) => return Ok(decrypted),
                    Err(err) => {
                        debug!("error decrypting payload: {}", err);
                        continue;
                    }
                }
            }

            // Pure health check with no data: loop back.
            info!("standalone health check processed, waiting for next packet");
        }
    }
}

impl<T: IdentityType + Clone, AE: AsyncExecutor, FM: FlowManager + Send + Sync> Drop for ClientSessionManager<T, AE, FM> {
    fn drop(&mut self) {
        drop(take(&mut self.flows));
    }
}
