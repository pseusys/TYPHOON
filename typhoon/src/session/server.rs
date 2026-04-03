/// Server-side session manager implementation.
use std::future::Future;
use std::hash::Hash;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Weak as StdWeak};

use log::{debug, trace};

use crate::bytes::{ByteBuffer, ByteBufferMut, DynamicByteBuffer, FixedByteBuffer};
use crate::cache::{CachedMapEntryTemplate, SharedMap};
use crate::crypto::{UserCryptoState, UserServerState};
use crate::session::common::SessionManager;
use crate::session::error::SessionControllerError;
use crate::settings::Settings;
use crate::settings::consts::TAILOR_LENGTH;
use crate::tailor::{IdentityType, PacketFlags, ReturnCode, Tailor};
use crate::utils::bitset::AtomicBitSet;
use crate::utils::sync::{AsyncExecutor, NotifyQueueSender};
use crate::utils::time::unix_timestamp_ms;

/// Trait for routing outgoing packets from a session back to the network.
/// Implemented by the Listener, stored as `Weak<R>` in each session.
pub trait OutgoingRouter<T>: Send + Sync {
    fn route_packet<'a>(&'a self, packet: DynamicByteBuffer, identity: &'a T) -> impl Future<Output = bool> + Send + 'a;
}

/// Incoming packet for the server session manager: body + tailor view.
pub struct IncomingPacket<T: IdentityType> {
    pub body: DynamicByteBuffer,
    pub tailor: Tailor<T>,
}

/// Server-side session manager for a single client connection.
pub struct ServerSessionManager<T: IdentityType + Clone + Eq + Hash + Send + ToString + 'static, AE: AsyncExecutor + 'static, R: OutgoingRouter<T> + 'static> {
    /// Sync template — used per-call to create a local cache entry; no Mutex needed.
    crypto_send: CachedMapEntryTemplate<T, UserServerState>,
    /// Sync template — used per-call to create a local cache entry; no Mutex needed.
    crypto_recv: CachedMapEntryTemplate<T, UserServerState>,
    identity: T,
    /// Lock-free bitmask of flow indices from which this client has been seen.
    active_flows: AtomicBitSet,
    incremental_counter: AtomicU32,
    incoming_tx: NotifyQueueSender<DynamicByteBuffer>,
    router: StdWeak<R>,
    settings: Arc<Settings<AE>>,
}

impl<T: IdentityType + Clone + Eq + Hash + Send + ToString, AE: AsyncExecutor, R: OutgoingRouter<T> + 'static> ServerSessionManager<T, AE, R> {
    /// Create a server session manager from pre-decapsulated handshake data.
    ///
    /// `response_body` must be pre-computed by calling `secret.encapsulate_handshake_server`
    /// **before** acquiring the `users` lock, so that CPU-intensive crypto work is not
    /// serialized through the shared-map mutex.
    ///
    /// Returns `(Arc<Self>, response_packet)`. The caller already holds `session_key` from
    /// the encapsulation step and uses it to upgrade the user's crypto state after sending the response.
    #[cfg(any(feature = "fast_software", feature = "fast_hardware"))]
    pub async fn from_handshake(
        response_body: DynamicByteBuffer,
        initial_key: FixedByteBuffer<32>,
        handshake_tailor: Tailor<T>,
        identity: T,
        secret: &crate::certificate::ServerSecret<'_>,
        users: &mut SharedMap<T, UserServerState>,
        incoming_tx: NotifyQueueSender<DynamicByteBuffer>,
        router: StdWeak<R>,
        num_flows: usize,
        settings: Arc<Settings<AE>>,
    ) -> Result<(Arc<Self>, DynamicByteBuffer), SessionControllerError> {
        use crate::certificate::ObfuscationBufferContainer;

        // Register user with initial key so that the handshake response tailor is
        // authenticated with the initial key (the client can verify before deriving session key).
        let obfuscation_buffer = secret.obfuscation_buffer();
        let crypto_state = UserCryptoState::new(&initial_key, obfuscation_buffer);
        let user_state = UserServerState::new(crypto_state);

        // Insert user into shared map under server-generated identity.
        users.insert(identity.clone(), user_state).await;

        // Create independent send/receive templates from the shared map.
        let crypto_send = users.create_cache_for(identity.clone());
        let crypto_recv = users.create_cache_for(identity.clone());

        // Assemble response packet: response_body || tailor.
        let next_in = handshake_tailor.time();
        let response_body_len = response_body.len();
        let tailor_buf = response_body.expand_end(T::length()).rebuffer_start(response_body_len);
        let _response_tailor = Tailor::handshake(
            tailor_buf,
            &identity,
            ReturnCode::Success.into(),
            next_in,
            handshake_tailor.packet_number(),
            response_body_len as u16,
        );
        // Include the response body in the packet: response_body || tailor (TAILOR_LENGTH + T::length() bytes).
        let response_packet = response_body.expand_end(TAILOR_LENGTH + T::length());

        let session = Arc::new(Self {
            crypto_send,
            crypto_recv,
            identity,
            active_flows: AtomicBitSet::new(num_flows),
            incremental_counter: AtomicU32::new(0),
            incoming_tx,
            router,
            settings,
        });

        Ok((session, response_packet))
    }

    /// Create a server session manager from pre-decapsulated handshake data (full mode).
    /// `response_body` must be pre-computed outside the `users` lock.
    #[cfg(any(feature = "full_software", feature = "full_hardware"))]
    pub async fn from_handshake(
        response_body: DynamicByteBuffer,
        initial_key: FixedByteBuffer<32>,
        handshake_tailor: Tailor<T>,
        identity: T,
        users: &mut SharedMap<T, UserServerState>,
        incoming_tx: NotifyQueueSender<DynamicByteBuffer>,
        router: StdWeak<R>,
        num_flows: usize,
        settings: Arc<Settings<AE>>,
    ) -> Result<(Arc<Self>, DynamicByteBuffer), SessionControllerError> {
        // Register user with initial key so that the handshake response tailor is
        // encrypted with the initial key (the client can decrypt before deriving session key).
        let crypto_state = UserCryptoState::new(&initial_key);
        let user_state = UserServerState::new(crypto_state);

        // Insert user into shared map under server-generated identity.
        users.insert(identity.clone(), user_state).await;

        // Create independent send/receive templates from the shared map.
        let crypto_send = users.create_cache_for(identity.clone());
        let crypto_recv = users.create_cache_for(identity.clone());

        // Assemble response packet: response_body || tailor.
        let next_in = handshake_tailor.time();
        let response_body_len = response_body.len();
        let tailor_buf = response_body.expand_end(T::length()).rebuffer_start(response_body_len);
        let _response_tailor = Tailor::handshake(
            tailor_buf,
            &identity,
            ReturnCode::Success.into(),
            next_in,
            handshake_tailor.packet_number(),
            response_body_len as u16,
        );
        // Include the response body in the packet: response_body || tailor (TAILOR_LENGTH + T::length() bytes).
        let response_packet = response_body.expand_end(TAILOR_LENGTH + T::length());

        let session = Arc::new(Self {
            crypto_send,
            crypto_recv,
            identity,
            active_flows: AtomicBitSet::new(num_flows),
            incremental_counter: AtomicU32::new(0),
            incoming_tx,
            router,
            settings,
        });

        Ok((session, response_packet))
    }

    /// Mark `flow_index` as active for this session (lock-free, no bounds limit).
    pub fn note_active_flow(&self, flow_index: usize) {
        self.active_flows.set(flow_index);
    }

    /// Choose an active flow index to use for outgoing packets (lock-free).
    /// Falls back to flow 0 if none have been seen yet.
    pub fn select_active_flow(&self, num_flows: usize) -> usize {
        self.active_flows.random_set_index(num_flows)
    }

    /// Get the next packet number: (unix_timestamp_seconds << 32) | incremental.
    fn next_packet_number(&self) -> u64 {
        let counter = self.incremental_counter.fetch_add(1, Ordering::Relaxed) + 1;
        let timestamp = (unix_timestamp_ms() / 1000) as u32;
        ((timestamp as u64) << 32) | (counter as u64)
    }

    /// Route a packet to the network via the outgoing router (Listener).
    async fn route_outgoing(&self, packet: DynamicByteBuffer) -> Result<(), SessionControllerError> {
        let router = self.router.upgrade().ok_or_else(|| SessionControllerError::FlowError(
            crate::flow::FlowControllerError::UserNotFound { identity: self.identity.to_string() },
        ))?;
        if !router.route_packet(packet, &self.identity).await {
            return Err(SessionControllerError::FlowError(
                crate::flow::FlowControllerError::UserNotFound { identity: self.identity.to_string() },
            ));
        }
        Ok(())
    }

    /// Process an incoming packet from the Listener.
    /// Decrypted data is sent to the ClientHandle via user_data_tx.
    pub async fn process_incoming(&self, incoming: IncomingPacket<T>) -> Result<(), SessionControllerError> {
        let IncomingPacket { body, tailor } = incoming;
        debug!("server session: process_incoming flags={:?} cd={} pn={:#018x} payload_len={}", tailor.flags(), tailor.code(), tailor.packet_number(), tailor.payload_length());

        // Handle termination.
        if tailor.flags().is_termination() {
            debug!("server session: connection terminated by client (code={:?})", tailor.code());
            return Err(SessionControllerError::ConnectionTerminated(tailor.code()));
        }

        // Handle health check: respond after the client's requested delay.
        if tailor.flags().contains(PacketFlags::HEALTH_CHECK) && !tailor.flags().has_payload() {
            let next_in = tailor.time();
            let pn = tailor.packet_number();
            trace!("server session: standalone health check pn={} next_in={}", pn, next_in);
            self.schedule_health_response(next_in, pn).await?;
        }

        // If there is data payload, decrypt and forward to ClientHandle.
        // The local entry is dropped before user_data_tx.send() to avoid holding any
        // shared-map reader across a potentially-blocking channel send.
        if tailor.flags().has_payload() {
            let payload_len = tailor.payload_length() as usize;
            let encrypted_payload = body.rebuffer_start(body.len() - payload_len);

            let decrypt_result = {
                let mut entry = self.crypto_recv.create_entry();
                let user_state = entry.get_mut().await.map_err(SessionControllerError::MissingCache)?;
                user_state.crypto_mut().decrypt_payload(encrypted_payload, None)
                // entry drops here
            };

            match decrypt_result {
                Ok(decrypted) => {
                    trace!("server session: decrypted {}B (encrypted payload was {}B), forwarding to client handle", decrypted.len(), payload_len);
                    // If this is a shadowride (data + health check), respond to the health check.
                    if tailor.flags().contains(PacketFlags::HEALTH_CHECK) {
                        self.schedule_health_response(tailor.time(), tailor.packet_number()).await?;
                    }
                    self.incoming_tx.push(decrypted);
                }
                Err(err) => {
                    debug!("server session: decrypt error: {}", err);
                }
            }
        }

        Ok(())
    }

    /// Schedule a health check response.
    async fn schedule_health_response(&self, client_next_in: u32, _client_pn: u64) -> Result<(), SessionControllerError> {
        let pn = self.next_packet_number();
        let buf = self.settings.pool().allocate(Some(T::length()));
        let response_tailor = Tailor::health_check(buf, &self.identity, client_next_in, pn);

        self.route_outgoing(response_tailor.into_buffer()).await
    }
}

impl<T: IdentityType + Clone + Eq + Hash + Send + ToString, AE: AsyncExecutor, R: OutgoingRouter<T> + 'static> SessionManager for ServerSessionManager<T, AE, R> {
    async fn send_packet(&self, packet: DynamicByteBuffer, generated: bool) -> Result<(), SessionControllerError> {
        trace!("server session: send_packet {} bytes (generated={})", packet.len(), generated);
        let full_packet = if generated {
            // Already assembled (tailor included), pass through.
            packet
        } else {
            // User data: encrypt payload, create DATA tailor, assemble.
            // Create a local entry per call — no Mutex contention.
            let mut entry = self.crypto_send.create_entry();
            let user_state = entry.get_mut().await.map_err(SessionControllerError::MissingCache)?;
            let encrypted_payload = user_state.crypto_mut().encrypt_payload(packet, None).map_err(SessionControllerError::CryptoError)?;

            let payload_length = encrypted_payload.len() as u16;
            drop(entry);
            let packet_number = self.next_packet_number();

            let encrypted_payload_len = encrypted_payload.len();
            let tailor_buf = encrypted_payload.expand_end(T::length()).rebuffer_start(encrypted_payload_len);
            let _tailor = Tailor::data(tailor_buf, &self.identity, payload_length, packet_number);
            // Include encrypted payload: encrypted_payload || tailor (TAILOR_LENGTH + T::length() bytes).
            encrypted_payload.expand_end(TAILOR_LENGTH + T::length())
        };

        self.route_outgoing(full_packet).await
    }

    #[cfg(feature = "client")]
    async fn receive_packet(&self) -> Result<DynamicByteBuffer, SessionControllerError> {
        // Not used directly — the Listener drives incoming packet processing.
        Err(SessionControllerError::HealthProviderDied)
    }
}

impl<T: IdentityType + Clone + Eq + Hash + Send + ToString, AE: AsyncExecutor, R: OutgoingRouter<T> + 'static> Drop for ServerSessionManager<T, AE, R> {
    fn drop(&mut self) {
        let identity = self.identity.clone();
        let packet_number = (unix_timestamp_ms() / 1000) as u64 * (1u64 << 32);
        let buf = self.settings.pool().allocate(Some(T::length()));
        let tailor = Tailor::termination(buf, &identity, ReturnCode::Success, packet_number);
        let router = self.router.clone();
        self.settings.executor().spawn(async move {
            if let Some(router) = router.upgrade() {
                router.route_packet(tailor.into_buffer(), &identity).await;
            }
        });
    }
}
