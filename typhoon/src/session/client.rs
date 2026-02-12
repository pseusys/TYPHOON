/// Client-side session manager implementation.
use std::sync::Arc;

use log::{debug, info};

use crate::bytes::{ByteBuffer, ByteBufferMut, DynamicByteBuffer};
use crate::cache::CachedValue;
use crate::crypto::ClientCryptoTool;
use crate::flow::FlowManager;
use crate::session::common::SessionManager;
use crate::session::error::SessionControllerError;
use crate::session::health::HealthProvider;
use crate::settings::Settings;
use crate::settings::consts::TAILOR_LENGTH;
use crate::tailor::{IdentityType, PacketFlags, Tailor};
use crate::utils::sync::{AsyncExecutor, Mutex, channel};

struct ClientSessionManagerInternalSend {
    cipher: CachedValue<ClientCryptoTool>,
    identity: Vec<u8>,
    incremental_counter: u32,
}

impl ClientSessionManagerInternalSend {
    fn next_packet_number(&mut self) -> u64 {
        self.incremental_counter += 1;
        let timestamp = (crate::utils::time::unix_timestamp_ms() / 1000) as u32;
        ((timestamp as u64) << 32) | (self.incremental_counter as u64)
    }
}

struct ClientSessionManagerInternalReceive {
    cipher: CachedValue<ClientCryptoTool>,
}

/// Client-side session manager that encrypts data and manages health checking.
pub struct ClientSessionManager<T: IdentityType + 'static, AE: AsyncExecutor + 'static, FM: FlowManager + Send + Sync + 'static> {
    health_provider: Mutex<HealthProvider<T, AE, Self>>,
    send_internal: Mutex<ClientSessionManagerInternalSend>,
    receive_internal: Mutex<ClientSessionManagerInternalReceive>,
    flows: Vec<Arc<FM>>,
    tailor_size: usize,
    settings: Arc<Settings<AE>>,
}

impl<T: IdentityType, AE: AsyncExecutor, FM: FlowManager + Send + Sync> ClientSessionManager<T, AE, FM> {
    /// Create a new client session manager.
    pub async fn new(
        cipher: CachedValue<ClientCryptoTool>,
        flows: Vec<Arc<FM>>,
        settings: Arc<Settings<AE>>,
        identity_len: usize,
    ) -> Result<Arc<Self>, SessionControllerError> {
        let mut send_cipher = cipher.create_sibling().await.map_err(SessionControllerError::MissingCache)?;
        let receive_cipher = cipher.create_sibling().await.map_err(SessionControllerError::MissingCache)?;

        let identity = send_cipher.get().await.map_err(SessionControllerError::MissingCache)?.identity();
        let tailor_size = TAILOR_LENGTH + identity_len;
        let (response_tx, response_rx) = channel(1);
        let (shadowride_tx, shadowride_rx) = channel(1);

        let value = Arc::new_cyclic(|weak| {
            let health_provider = HealthProvider::new(
                weak.clone(),
                settings.clone(),
                identity.clone(),
                response_tx,
                shadowride_tx,
            );

            ClientSessionManager {
                health_provider: Mutex::new(health_provider),
                send_internal: Mutex::new(ClientSessionManagerInternalSend {
                    cipher: send_cipher,
                    identity,
                    incremental_counter: 0,
                }),
                receive_internal: Mutex::new(ClientSessionManagerInternalReceive {
                    cipher: receive_cipher,
                }),
                flows,
                tailor_size,
                settings,
            }
        });

        value.health_provider.lock().await.start(response_rx, shadowride_rx).await;
        Ok(value)
    }

    /// Select a flow manager (currently uses the first one).
    fn select_flow(&self) -> &Arc<FM> {
        self.flows.first().expect("at least one flow manager required")
    }
}

impl<T: IdentityType, AE: AsyncExecutor, FM: FlowManager + Send + Sync> SessionManager for ClientSessionManager<T, AE, FM> {
    async fn send_packet(&self, packet: DynamicByteBuffer, generated: bool) -> Result<(), SessionControllerError> {
        let full_packet = if generated {
            // Health provider already assembled (body + tailor), pass through directly.
            packet
        } else {
            // User data: encrypt payload, create DATA tailor, check for shadowriding.
            let mut send_lock = self.send_internal.lock().await;
            let encrypted_payload = send_lock.cipher.get_mut().await.map_err(SessionControllerError::MissingCache)?.encrypt_payload(packet, None).map_err(SessionControllerError::CryptoError)?;

            let payload_length = encrypted_payload.len() as u16;
            let packet_number = send_lock.next_packet_number();
            let identity_buffer = self.settings.pool().allocate_precise_from_slice_with_capacity(&send_lock.identity, 0, 0);
            let mut tailor = Tailor::data(T::from_bytes(identity_buffer.slice()), payload_length, packet_number);

            // Let health provider potentially attach a shadowride.
            {
                let health_lock = self.health_provider.lock().await;
                health_lock.feed_output(&mut tailor).await;
            }

            let tailor_buffer = self.settings.pool().allocate(Some(self.tailor_size));
            let tailor_data = tailor.to_buffer(tailor_buffer);

            // Assemble: encrypted_payload || plaintext_tailor.
            let assembled = encrypted_payload.expand_end(tailor_data.len());
            assembled.slice_start_mut(encrypted_payload.len()).copy_from_slice(tailor_data.slice());
            assembled
        };

        let flow = self.select_flow();
        flow.send_packet(full_packet, false).await.map_err(SessionControllerError::FlowError)
    }

    async fn receive_packet(&self) -> Result<DynamicByteBuffer, SessionControllerError> {
        let flow = self.select_flow();
        let recv_buf = self.settings.pool().allocate(None);

        loop {
            let packet = flow.receive_packet(recv_buf.clone()).await.map_err(SessionControllerError::FlowError)?;

            // The flow manager returns: encrypted_payload || plaintext_tailor.
            let (payload_part, tailor_part) = packet.split_buf(packet.len() - self.tailor_size);
            let tailor = Tailor::from_buffer(&tailor_part, self.tailor_size - TAILOR_LENGTH);

            // Handle termination.
            if tailor.flags.is_termination() {
                return Err(SessionControllerError::ConnectionTerminated(tailor.code));
            }

            // Handle health check (standalone or shadowride).
            if tailor.flags.contains(PacketFlags::HEALTH_CHECK) {
                let health_lock = self.health_provider.lock().await;
                health_lock.feed_input(&tailor).await;
            }

            // If there is data payload, decrypt and return.
            if tailor.flags.has_payload() {
                let mut recv_lock = self.receive_internal.lock().await;
                match recv_lock.cipher.get_mut().await.map_err(SessionControllerError::MissingCache)?.decrypt_payload(payload_part, None) {
                    Ok(decrypted) => return Ok(decrypted),
                    Err(err) => {
                        debug!("error decrypting payload: {}", err);
                        continue;
                    },
                }
            }

            // Pure health check with no data: loop back.
            info!("standalone health check processed, waiting for next packet");
        }
    }
}
