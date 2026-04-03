/// Client-side session manager implementation.
use std::mem::take;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

use log::{debug, info, trace};

use crate::bytes::{ByteBuffer, ByteBufferMut, DynamicByteBuffer};
use crate::cache::SharedValue;
use crate::crypto::ClientCryptoTool;
use crate::flow::FlowManager;
use crate::session::common::SessionManager;
use crate::session::error::SessionControllerError;
use crate::session::health::HealthProvider;
use crate::settings::Settings;
use crate::settings::consts::TAILOR_LENGTH;
use crate::tailor::{ClientConnectionHandler, IdentityType, PacketFlags, Tailor};
use crate::utils::random::{SupportRng, get_rng};
use crate::utils::sync::{AsyncExecutor, Mutex, create_watch};

struct ClientSessionManagerInternalSend<T: IdentityType + Clone> {
    cipher: SharedValue<ClientCryptoTool<T>>,
}

struct ClientSessionManagerInternalReceive<T: IdentityType + Clone> {
    cipher: SharedValue<ClientCryptoTool<T>>,
}

/// Client-side session manager that encrypts data and manages health checking.
pub struct ClientSessionManager<T: IdentityType + Clone + 'static, AE: AsyncExecutor + 'static, FM: FlowManager + Send + Sync + 'static, CC: ClientConnectionHandler + 'static> {
    health_provider: HealthProvider<T, AE, Self, CC>,
    send_internal: Mutex<ClientSessionManagerInternalSend<T>>,
    receive_internal: Mutex<ClientSessionManagerInternalReceive<T>>,
    incremental_counter: AtomicU32,
    flows: Vec<FM>,
    settings: Arc<Settings<AE>>,
}


impl<T: IdentityType + Clone, AE: AsyncExecutor, FM: FlowManager + Send + Sync, CC: ClientConnectionHandler + 'static> ClientSessionManager<T, AE, FM, CC> {
    /// Create a new client session manager without starting the handshake.
    /// Call `start()` after the background receive loop is running.
    pub async fn new(cipher: SharedValue<ClientCryptoTool<T>>, flows: Vec<FM>, settings: Arc<Settings<AE>>, initial_data_generator: CC) -> Result<Arc<Self>, SessionControllerError> {
        let send_cipher = cipher.create_sibling().await;
        let receive_cipher = cipher.create_sibling().await;
        let health_state_crypto = cipher.create_sibling().await;

        let (response_tx, response_rx) = create_watch();
        let (shadowride_tx, _) = create_watch();

        let value = Arc::new_cyclic(|weak| {
            let health_provider = HealthProvider::new(weak.clone(), settings.clone(), health_state_crypto, response_tx, shadowride_tx, response_rx, initial_data_generator);

            ClientSessionManager {
                health_provider,
                send_internal: Mutex::new(ClientSessionManagerInternalSend {
                    cipher: send_cipher,
                }),
                receive_internal: Mutex::new(ClientSessionManagerInternalReceive {
                    cipher: receive_cipher,
                }),
                incremental_counter: AtomicU32::new(0),
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

    fn next_packet_number(&self) -> u64 {
        let counter = self.incremental_counter.fetch_add(1, Ordering::Relaxed) + 1;
        let timestamp = (crate::utils::time::unix_timestamp_ms() / 1000) as u32;
        ((timestamp as u64) << 32) | (counter as u64)
    }
}

impl<T: IdentityType + Clone, AE: AsyncExecutor, FM: FlowManager + Send + Sync, CC: ClientConnectionHandler + 'static> SessionManager for ClientSessionManager<T, AE, FM, CC> {
    async fn send_packet(&self, packet: DynamicByteBuffer, generated: bool) -> Result<(), SessionControllerError> {
        trace!("client session: send_packet {} bytes (generated={})", packet.len(), generated);
        let full_packet = if generated {
            // Health provider already assembled (body + tailor), pass through directly.
            packet
        } else {
            // User data: encrypt payload, create DATA tailor, check for shadowriding.
            let (encrypted_payload, payload_length, identity) = {
                let mut send_lock = self.send_internal.lock().await;
                let encrypted_payload = send_lock.cipher.get_mut().await.encrypt_payload(packet, None).map_err(SessionControllerError::CryptoError)?;
                let payload_length = encrypted_payload.len() as u16;
                let identity = send_lock.cipher.get().await.identity();
                (encrypted_payload, payload_length, identity)
                // send_lock released here
            };
            let packet_number = self.next_packet_number();

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
        loop {
            // Allocate a fresh buffer each iteration: the decrypted payload view shares backing
            // memory with recv_buf, so reusing it across iterations would corrupt payloads that
            // have already been queued in the channel but not yet consumed.
            let recv_buf = self.settings.pool().allocate_for_recv();
            let packet = self.select_flow().receive_packet(recv_buf).await.map_err(SessionControllerError::FlowError)?;

            // The flow manager returns: encrypted_payload || plaintext_tailor (full TAILOR_LENGTH + T::length() bytes).
            let (payload_part, tailor_part) = packet.split_buf(packet.len() - T::length() - TAILOR_LENGTH);
            let tailor = Tailor::<T>::new(tailor_part);
            debug!("client session: recv flags={:?} cd={} pn={:#018x} payload_len={} has_payload={}", tailor.flags(), tailor.code(), tailor.packet_number(), tailor.payload_length(), tailor.flags().has_payload());

            // Handle termination.
            if tailor.flags().is_termination() {
                debug!("client session: connection terminated by server (code={:?})", tailor.code());
                return Err(SessionControllerError::ConnectionTerminated(tailor.code()));
            }

            // Handle handshake response.
            if tailor.flags().contains(PacketFlags::HANDSHAKE) {
                debug!("client session: routing handshake response to health provider");
                self.health_provider.feed_handshake_input(tailor.clone(), payload_part.clone()).await?;
            }

            // Handle health check (standalone or shadowride).
            if tailor.flags().contains(PacketFlags::HEALTH_CHECK) {
                trace!("client session: routing health check to health provider");
                self.health_provider.feed_input(tailor.clone()).await?;
            }

            // If there is data payload, decrypt and return.
            if tailor.flags().has_payload() {
                let mut recv_lock = self.receive_internal.lock().await;
                match recv_lock.cipher.get_mut().await.decrypt_payload(payload_part, None) {
                    Ok(decrypted) => {
                        trace!("client session: decrypted {}B (encrypted payload was {}B)", decrypted.len(), tailor.payload_length());
                        return Ok(decrypted);
                    }
                    Err(err) => {
                        debug!("client session: decrypt error: {}", err);
                        continue;
                    }
                }
            }

            // Pure health check with no data: loop back.
            info!("standalone health check processed, waiting for next packet");
        }
    }
}

impl<T: IdentityType + Clone, AE: AsyncExecutor, FM: FlowManager + Send + Sync, CC: ClientConnectionHandler + 'static> Drop for ClientSessionManager<T, AE, FM, CC> {
    fn drop(&mut self) {
        drop(take(&mut self.flows));
    }
}
