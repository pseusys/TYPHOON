/// Server-side session manager implementation.
use std::future::Future;
use std::hash::Hash;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Weak as StdWeak};

use log::{debug, warn};
use rand::Rng;

use crate::bytes::{ByteBuffer, ByteBufferMut, DynamicByteBuffer, FixedByteBuffer};
use crate::cache::{CachedMapEntryTemplate, SharedMap};
use crate::crypto::{UserCryptoState, UserServerState};
use crate::session::common::SessionManager;
use crate::session::error::SessionControllerError;
use crate::session::server_health::ServerHealthProvider;
use crate::settings::{Settings, keys};
use crate::settings::consts::TAILOR_LENGTH;
use crate::tailor::{IdentityType, PacketFlags, ReturnCode, Tailor};
use crate::utils::bitset::AtomicBitSet;
use crate::utils::random::get_rng;
use crate::utils::sync::{AsyncExecutor, NotifyQueueSender};
use crate::utils::time::unix_timestamp_ms;

/// Trait for routing outgoing packets from a session back to the network.
/// Implemented by the Listener, stored as `Weak<R>` in each session.
pub trait OutgoingRouter<T>: Send + Sync {
    fn route_packet<'a>(&'a self, packet: DynamicByteBuffer, identity: &'a T) -> impl Future<Output = bool> + Send + 'a;
    /// Remove all state associated with the given identity (session map, user crypto, decoy providers).
    fn remove_session<'a>(&'a self, identity: &'a T) -> impl Future<Output = ()> + Send + 'a;
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
    health_provider: ServerHealthProvider,
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

        // Generate server's next_in for the handshake response (tells client when to send first health check).
        let server_next_in = get_rng().gen_range(
            settings.get(&keys::HEALTH_CHECK_NEXT_IN_MIN)..=settings.get(&keys::HEALTH_CHECK_NEXT_IN_MAX),
        ) as u32;

        // Assemble response packet: response_body || tailor.
        let response_body_len = response_body.len();
        let tailor_buf = response_body.expand_end(T::length()).rebuffer_start(response_body_len);
        let _response_tailor = Tailor::handshake(
            tailor_buf,
            &identity,
            ReturnCode::Success.into(),
            server_next_in,
            handshake_tailor.packet_number(),
            response_body_len as u16,
        );
        // Include the response body in the packet: response_body || tailor (TAILOR_LENGTH + T::length() bytes).
        let response_packet = response_body.expand_end(TAILOR_LENGTH + T::length());

        let health_provider = ServerHealthProvider::new(router.clone(), identity.clone(), settings.clone(), server_next_in);

        let session = Arc::new(Self {
            crypto_send,
            crypto_recv,
            identity,
            active_flows: AtomicBitSet::new(num_flows),
            incremental_counter: AtomicU32::new(0),
            incoming_tx,
            router,
            settings,
            health_provider,
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

        // Generate server's next_in for the handshake response (tells client when to send first health check).
        let server_next_in = get_rng().gen_range(
            settings.get(&keys::HEALTH_CHECK_NEXT_IN_MIN)..=settings.get(&keys::HEALTH_CHECK_NEXT_IN_MAX),
        ) as u32;

        // Assemble response packet: response_body || tailor.
        let response_body_len = response_body.len();
        let tailor_buf = response_body.expand_end(T::length()).rebuffer_start(response_body_len);
        let _response_tailor = Tailor::handshake(
            tailor_buf,
            &identity,
            ReturnCode::Success.into(),
            server_next_in,
            handshake_tailor.packet_number(),
            response_body_len as u16,
        );
        // Include the response body in the packet: response_body || tailor (TAILOR_LENGTH + T::length() bytes).
        let response_packet = response_body.expand_end(TAILOR_LENGTH + T::length());

        let health_provider = ServerHealthProvider::new(router.clone(), identity.clone(), settings.clone(), server_next_in);

        let session = Arc::new(Self {
            crypto_send,
            crypto_recv,
            identity,
            active_flows: AtomicBitSet::new(num_flows),
            incremental_counter: AtomicU32::new(0),
            incoming_tx,
            router,
            settings,
            health_provider,
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

    /// Spawn a cleanup task that notifies the client and removes this session from shared state.
    /// Called from ClientHandle::Drop (server-side close). Sends TERMINATION while the session
    /// is still in the router's sessions map (so route_packet can resolve the active flow),
    /// then removes all associated state. All removes are no-ops if the client already sent
    /// TERMINATION and route_incoming already called remove_session.
    pub fn spawn_cleanup(&self, executor: &AE) {
        let identity = self.identity.clone();
        let router = self.router.clone();
        let pn = (unix_timestamp_ms() / 1000) as u64 * (1u64 << 32);
        let buf = self.settings.pool().allocate(Some(T::length()));
        let termination = Tailor::termination(buf, &self.identity, ReturnCode::Success, pn).into_buffer();
        executor.spawn(async move {
            if let Some(router) = router.upgrade() {
                router.route_packet(termination, &identity).await;
                router.remove_session(&identity).await;
            }
        });
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
        debug!("server session [{}]: received {:?} packet", self.identity.to_string(), tailor.flags());

        // Handle termination.
        if tailor.flags().is_termination() {
            debug!("server session [{}]: connection terminated by client (code={})", self.identity.to_string(), tailor.code());
            return Err(SessionControllerError::ConnectionTerminated(tailor.code()));
        }

        // Handle health check: forward to health provider.
        if tailor.flags().contains(PacketFlags::HEALTH_CHECK) && !tailor.flags().has_payload() {
            self.health_provider.feed_health_check(tailor.packet_number());
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
                    // If this is a shadowride (data + health check), respond to the health check.
                    if tailor.flags().contains(PacketFlags::HEALTH_CHECK) {
                        self.health_provider.feed_health_check(tailor.time(), tailor.packet_number());
                    }
                    self.incoming_tx.push(decrypted);
                }
                Err(err) => {
                    warn!("server session [{}]: payload decryption failed: {}", self.identity.to_string(), err);
                }
            }
        }

        Ok(())
    }

}

impl<T: IdentityType + Clone + Eq + Hash + Send + ToString, AE: AsyncExecutor, R: OutgoingRouter<T> + 'static> SessionManager for ServerSessionManager<T, AE, R> {
    async fn send_packet(&self, packet: DynamicByteBuffer, generated: bool) -> Result<(), SessionControllerError> {
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
            let assembled = encrypted_payload.expand_end(TAILOR_LENGTH + T::length());
            debug!("server session [{}]: sending data packet", self.identity.to_string());
            assembled
        };

        self.route_outgoing(full_packet).await
    }

    #[cfg(feature = "client")]
    async fn receive_packet(&self) -> Result<DynamicByteBuffer, SessionControllerError> {
        // Not used directly — the Listener drives incoming packet processing.
        Err(SessionControllerError::HealthProviderDied)
    }
}

