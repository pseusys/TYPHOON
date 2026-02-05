use std::sync::Arc;
use std::time::Duration;

use futures::stream::select_all;
use log::{debug, info, warn};
use rand::Rng;
use tokio_stream::StreamExt;

use crate::bytes::{ByteBuffer, BytePool};
use crate::cache::{CachedValue, SharedValue};
use crate::constants::consts::TAILOR_LENGTH;
use crate::constants::{keys, Settings};
use crate::crypto::ClientCryptoTool;
use crate::flow::{FlowHandle, FlowCommand};
use crate::session::common::{SessionCommand, SessionHandle, SessionInternal, SessionOutput, SessionReturn};
use crate::session::error::SessionControllerError;
use crate::session::health::HealthCheckMode;
use crate::tailor::{PacketFlags, Tailor};
use crate::utils::channel;
use crate::utils::random::get_rng;
use crate::utils::sync::{spawn, timeout, Mutex, RwLock, Receiver};
use crate::utils::time::unix_timestamp_ms;

async fn receive_with_index(index: usize, receiver: &mut Receiver<ByteBuffer>) -> (usize, Option<ByteBuffer>) {
    (index, receiver.recv().await)
}

/// Client-side session controller that manages flows, handles handshake,
/// and provides a simple send/recv interface.
pub struct ClientSessionController<'a> {
    tool: Mutex<SharedValue<ClientCryptoTool<'a>>>,
    identity: Vec<u8>,
    flows: Mutex<Vec<FlowHandle>>,
    shadowride: RwLock<Option<(u64, u32)>>,
    tailor_len: usize,
    settings: Settings,
    pool: &'a BytePool,
    internal: SessionInternal,
}

impl<'a: 'static> ClientSessionController<'a> {
    /// Create and initialize a new client session controller.
    /// Performs the full handshake sequence and starts health check provider.
    pub async fn connect<HC: HealthCheckMode>(cipher: ClientCryptoTool<'a>, flows: Vec<FlowHandle>, initial_data: ByteBuffer, settings: Settings, pool: &'a BytePool) -> Result<SessionHandle, SessionControllerError> {
        if flows.is_empty() {
            return Err(SessionControllerError::SessionDecayed);
        }

        // TODO: broadcast
        let tool = SharedValue::new(cipher);

        // TODO: handshake identity must bear protocol version
        let identity = cipher.identity().to_vec();
        let tailor_len = TAILOR_LENGTH + cipher.identity_len();

        let (internal, user_handle) = channel::new(32);

        let controller = Arc::new(Self {
            tool: Mutex::new(tool),
            identity,
            flows: Mutex::new(flows),
            shadowride: RwLock::new(None),
            tailor_len,
            settings,
            pool,
            internal,
        });

        controller.perform_handshake(initial_data).await?;
        info!("handshake completed, session established");

        spawn(HC::new(user_handle.clone()).run());
        spawn(controller.clone().run_send_loop());
        spawn(controller.clone().run_receive_loop());

        Ok(user_handle)
    }

    /// Perform the handshake sequence using the crypto tool.
    async fn perform_handshake(&self, initial_data: ByteBuffer) -> Result<(), SessionControllerError> {
        let max_retries = self.settings.get(&keys::MAX_RETRIES);
        let timeout_default = self.settings.get(&keys::TIMEOUT_DEFAULT);
        let handshake_factor = self.settings.get(&keys::HANDSHAKE_NEXT_IN_FACTOR);

        let next_in = self.generate_next_in(handshake_factor as f32);

        for retry in 0..max_retries {
            debug!("handshake attempt {}/{}", retry + 1, max_retries);

            let packet_number = self.make_packet_number();
            let (client_data, handshake_secret, mut initial_cipher) = self.tool.lock().await.get().create_handshake();

            let encrypted_initial_data = match initial_cipher.encrypt_auth(initial_data.clone(), None) {
                Ok(data) => data,
                Err(e) => {
                    warn!("handshake encryption failed: {}", e);
                    continue;
                }
            };

            if let Err(e) = self.send_handshake_request(packet_number, next_in, encrypted_initial_data, handshake_secret).await {
                warn!("handshake send failed: {}", e);
                continue;
            }

            let wait_duration = Duration::from_millis(next_in as u64 + timeout_default);
            match timeout(wait_duration, self.receive_handshake_response()).await {
                Some(Ok(encrypted_response)) => {
                    let decrypted_response = match initial_cipher.decrypt_auth(encrypted_response, None) {
                        Ok(data) => data,
                        Err(e) => {
                            warn!("handshake response decryption failed: {}", e);
                            continue;
                        }
                    };

                    let mut tool_guard = self.tool.lock().await;
                    match tool_guard.get().process_handshake_response(client_data, decrypted_response) {
                        // TODO: update cached value
                        Ok(key) => {
                            let cert = tool_guard.extract();
                            tool_guard.set(ClientCryptoTool::new(cert, identity, initial_key))
                        },
                        Err(e) => {
                            warn!("handshake response processing failed: {}", e);
                            continue;
                        }
                    };

                    return Ok(());
                }
                Some(Err(e)) => {
                    warn!("handshake response error: {}", e);
                }
                None => {
                    warn!("handshake timeout ({}ms)!", wait_duration.as_millis());
                }
            }
        }

        Err(SessionControllerError::HandshakeFailed)
    }

    /// Send a handshake request packet.
    async fn send_handshake_request(&self, packet_number: u64, next_in: u32, initial_data: ByteBuffer, handshake_secret: ByteBuffer) -> Result<(), SessionControllerError> {
        // TODO: pick random
        let mut mutex_lock = self.flows.lock().await;
        let flow = mutex_lock.first_mut().ok_or(SessionControllerError::SessionDecayed)?;

        let packet_handshake = self.pool.allocate(Some(handshake_secret.len()));
        packet_handshake.slice_mut().copy_from_slice(handshake_secret.slice());

        let packet_body = packet_handshake.prepend_buf(&initial_data);
        let packet_body_length = packet_body.len();

        let tailor = Tailor::handshake(ByteBuffer::from(self.identity.as_slice()), 0, next_in, packet_number);
        let packet_tailor = packet_body.expand_end(self.tailor_len + ClientCryptoTool::tailor_overhead()).rebuffer_start(packet_body_length);
        let full_packet = self.tool.lock().await.obfuscate_tailor(tailor.to_buffer(packet_tailor)).map_err(SessionControllerError::CipherError)?;

        // TODO: error handling
        flow.send(FlowCommand::SendPacket(full_packet)).await;
        Ok(())
    }

    /// Wait for and process a handshake response.
    async fn receive_handshake_response(&self) -> Result<ByteBuffer, SessionControllerError> {
        let mut mutex_lock = self.flows.lock().await;
        let streams: Vec<_> = mutex_lock.into_iter().map(|h| BroadcastStream::new(h.api_receiver())).collect();

        let mut merged = select_all(streams);
        while let Some(res) = merged.next().await {
            let tailor_buf = res.rebuffer_start(res.len() - self.tailor_len);
            let tailor = Tailor::from_buffer(&tailor_buf, self.identity.len());
            if tailor.flags.contains(PacketFlags::HANDSHAKE) {
                return Ok(res.rebuffer_end(res.len() - self.tailor_len));
            }
        }

        Err(SessionControllerError::SessionDecayed)
    }

    /// Send loop that handles outgoing commands.
    async fn run_send_loop(self: Arc<Self>) {
        let mut receiver = self.internal.api_receiver();
        loop {
            match receiver.recv().await {
                Ok(SessionCommand::SendData { data }) => {
                    let success = self.handle_send_data(data).await.is_ok();
                    self.internal.ret(SessionReturn::SendDataResult(success));
                },
                Ok(SessionCommand::BeginShadowride { packet_number, next_in }) => {
                    *self.shadowride.write().await = Some((packet_number, next_in));
                }
                Ok(SessionCommand::EndShadowride) => {
                    let consumed = self.shadowride.write().await.take().is_none();
                    self.internal.ret(SessionReturn::EndShadowrideResult(consumed));
                }
                Ok(SessionCommand::SendHealthCheck { packet_number, next_in }) => {
                    let success = self.handle_send_health_check(packet_number, next_in).await.is_ok();
                    self.internal.ret(SessionReturn::SendHealthCheckResult(success));
                }
                Ok(SessionCommand::Shutdown) => {
                    debug!("session controller received shutdown command");
                    break;
                }
                Err(err) => {
                    debug!("session controller command channel closed: {err}");
                    break;
                }
            }
        }

        self.internal.send(SessionOutput::Terminated);

        for flow in &self.flows {
            flow.shutdown().await;
        }
    }

    /// Receive loop that forwards incoming packets.
    async fn run_receive_loop(self: Arc<Self>) {
        loop {
            let mut received_any = false;
            let mut all_closed = true;

            let mut receivers = self.packet_receivers.lock().await;
            for receiver in receivers.iter_mut() {
                let poll_duration = Duration::from_millis(10);
                match timeout(poll_duration, receiver.recv()).await {
                    Some(Some(received)) => {
                        received_any = true;
                        all_closed = false;
                        self.process_received_packet(received);
                    }
                    Some(None) => {}
                    None => {
                        all_closed = false;
                    }
                }
            }
            drop(receivers);

            if all_closed {
                debug!("receive loop: all packet receivers closed, exiting");
                break;
            }

            if !received_any {
                tokio::task::yield_now().await;
            }
        }
    }

    /// Process a received packet and forward to output channel.
    fn process_received_packet(&self, received: ReceivedPacket) {
        let tailor_buf = received
            .packet
            .rebuffer_start(received.packet.len() - received.tailor_len);
        let tailor = Tailor::from_buffer(&tailor_buf, self.identity.len());

        if tailor.flags.contains(PacketFlags::HEALTH_CHECK) {
            debug!(
                "session: received health check response (pn={}, next_in={})",
                tailor.packet_number, tailor.time
            );
            self.internal.send(SessionOutput::HealthResponse {
                packet_number: tailor.packet_number,
                next_in: tailor.time,
            });

            if !tailor.flags.has_payload() {
                return;
            }
        }

        if tailor.flags.is_termination() {
            debug!("session: received termination packet");
            self.internal.send(SessionOutput::Terminated);
            return;
        }

        if tailor.flags.has_payload() {
            let payload = received
                .packet
                .rebuffer_end(received.packet.len() - received.tailor_len);
            self.internal.send(SessionOutput::Data(payload));
        }
    }

    /// Handle a send data command.
    async fn handle_send_data(&self, data: ByteBuffer) -> Result<(), SessionControllerError> {
        let flow = self.flows.first().ok_or(SessionControllerError::SessionDecayed)?;

        let tailor = Tailor::data(ByteBuffer::from(self.identity.as_slice()), data.len() as u16, self.make_packet_number());

        let packet = ByteBuffer::empty_with_capacity(data.len() + self.tailor_len, 0, 0);
        let packet = packet.append_buf(&data);
        let packet = tailor.to_buffer(packet.expand_end(self.tailor_len));

        if let Some((packet_number, next_in)) = self.shadowride.write().await.take() {
            debug!("session: embedding health check shadowride into data packet");
            let tailor_start = packet.len() - self.tailor_len;
            let slice = packet.slice_mut();
            slice[tailor_start] |= PacketFlags::HEALTH_CHECK.bits();
            slice[tailor_start + 2..tailor_start + 6].copy_from_slice(&next_in.to_be_bytes());
            slice[tailor_start + 6..tailor_start + 14].copy_from_slice(&packet_number.to_be_bytes());
        }

        flow.send_packet(packet).await?;
        Ok(())
    }

    /// Handle a send health check command.
    async fn handle_send_health_check(
        &self,
        packet_number: u64,
        next_in: u32,
    ) -> Result<(), SessionControllerError> {
        let flow = self.flows.first().ok_or(SessionControllerError::SessionDecayed)?;

        let tailor = Tailor::health_check(ByteBuffer::from(self.identity.as_slice()), next_in, packet_number);
        let buffer = ByteBuffer::empty(self.tailor_len);
        let packet = tailor.to_buffer(buffer);

        flow.send_packet(packet).await?;
        Ok(())
    }

    fn generate_next_in(&self, multiplier: f32) -> u32 {
        let min_val = self.settings.get(&keys::HEALTH_CHECK_NEXT_IN_MIN) as f32;
        let max_val = self.settings.get(&keys::HEALTH_CHECK_NEXT_IN_MAX) as f32;
        (get_rng().gen_range(min_val..=max_val) * multiplier) as u32
    }

    fn make_packet_number(&self) -> u64 {
        let timestamp = (unix_timestamp_ms() / 1000) as u32;
        let random: u32 = get_rng().gen_range(0..u32::MAX);
        ((timestamp as u64) << 32) | (random as u64)
    }
}
