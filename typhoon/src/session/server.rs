#[cfg(all(test, feature = "tokio", feature = "server", feature = "client"))]
#[path = "../../tests/session/server.rs"]
mod tests;

/// Server-side session manager implementation.
use std::hash::Hash;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Weak as StdWeak};

use async_trait::async_trait;
use log::{debug, warn};
use rand::Rng;

use crate::bytes::{ByteBuffer, ByteBufferMut, DynamicByteBuffer};
use crate::cache::{CachedMapEntryTemplate, SharedMap};
use crate::crypto::{UserCryptoState, UserServerState};
use crate::flow::FlowControllerError;
use crate::session::common::SessionManager;
use crate::session::error::SessionControllerError;
use crate::session::server_health::ServerHealthProvider;
use crate::settings::consts::TAILOR_LENGTH;
use crate::settings::{Settings, keys};
use crate::tailor::{IdentityType, PacketFlags, ReturnCode, Tailor};
use crate::utils::bitset::AtomicBitSet;
use crate::utils::random::get_rng;
use crate::utils::sync::{AsyncExecutor, NotifyQueueSender};
use crate::utils::unix_timestamp_ms;

/// Trait for routing outgoing packets from a session back to the network.
/// Implemented by the Listener, stored as `Weak<dyn OutgoingRouter<T>>` in each session.
#[async_trait]
pub trait OutgoingRouter<T: Send + Sync>: Send + Sync {
    async fn route_packet(&self, packet: DynamicByteBuffer, identity: &T) -> bool;
    /// Remove all state associated with the given identity (session map, user crypto, decoy providers).
    async fn remove_session(&self, identity: &T);
}

/// Incoming packet for the server session manager: body + tailor view.
pub struct IncomingPacket<T: IdentityType> {
    pub body: DynamicByteBuffer,
    pub tailor: Tailor<T>,
}

/// Server-side session manager for a single client connection.
pub struct ServerSessionManager<T: IdentityType + Clone + Eq + Hash + Send + ToString + 'static, AE: AsyncExecutor + 'static> {
    /// Sync template — used per-call to create a local cache entry; no Mutex needed.
    crypto_send: CachedMapEntryTemplate<T, UserServerState>,
    /// Sync template — used per-call to create a local cache entry; no Mutex needed.
    crypto_recv: CachedMapEntryTemplate<T, UserServerState>,
    identity: T,
    /// Lock-free bitmask of flow indices from which this client has been seen.
    active_flows: AtomicBitSet,
    incremental_counter: AtomicU32,
    incoming_tx: NotifyQueueSender<DynamicByteBuffer>,
    router: StdWeak<dyn OutgoingRouter<T>>,
    settings: Arc<Settings<AE>>,
    health_provider: ServerHealthProvider,
}

impl<T: IdentityType + Clone + Eq + Hash + Send + ToString, AE: AsyncExecutor> ServerSessionManager<T, AE> {
    /// Assemble a new server session from a pre-decapsulated handshake.
    ///
    /// `crypto_state` must be constructed with the initial handshake key **before** calling
    /// this function (the caller uses its `Listener::make_initial_crypto_state` helper).
    /// `response_body` must also be pre-computed outside the `users` lock so that
    /// CPU-intensive McEliece work is not serialized through the shared-map mutex.
    ///
    /// Returns `(Arc<Self>, response_packet)`. The caller holds `session_key` from the
    /// encapsulation step and upgrades the user's crypto state after sending the response.
    pub(crate) async fn assemble_session(crypto_state: UserCryptoState, response_body: DynamicByteBuffer, handshake_tailor: Tailor<T>, identity: T, users: &mut SharedMap<T, UserServerState>, incoming_tx: NotifyQueueSender<DynamicByteBuffer>, router: StdWeak<dyn OutgoingRouter<T>>, num_flows: usize, settings: Arc<Settings<AE>>) -> Result<(Arc<Self>, DynamicByteBuffer), SessionControllerError> {
        let user_state = UserServerState::new(crypto_state);

        users.insert(identity.clone(), user_state).await;

        let crypto_send = users.create_cache_for(identity.clone());
        let crypto_recv = users.create_cache_for(identity.clone());

        let server_next_in = get_rng().gen_range(settings.get(&keys::HEALTH_CHECK_NEXT_IN_MIN)..=settings.get(&keys::HEALTH_CHECK_NEXT_IN_MAX)) as u32;

        let response_body_len = response_body.len();
        let tailor_buf = response_body.expand_end(T::length()).rebuffer_start(response_body_len);
        let _response_tailor = Tailor::handshake(tailor_buf, &identity, ReturnCode::Success.into(), server_next_in, handshake_tailor.packet_number(), response_body_len as u16);
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
        let router = self.router.upgrade().ok_or_else(|| {
            SessionControllerError::FlowError(FlowControllerError::UserNotFound {
                identity: self.identity.to_string(),
            })
        })?;
        if !router.route_packet(packet, &self.identity).await {
            return Err(SessionControllerError::FlowError(FlowControllerError::UserNotFound {
                identity: self.identity.to_string(),
            }));
        }
        Ok(())
    }

    /// Process an incoming packet from the Listener.
    /// Decrypted data is sent to the ClientHandle via user_data_tx.
    pub async fn process_incoming(&self, incoming: IncomingPacket<T>) -> Result<(), SessionControllerError> {
        let IncomingPacket {
            body,
            tailor,
        } = incoming;
        debug!("server session [{}]: received {:?} packet", self.identity.to_string(), tailor.flags());

        if tailor.flags().is_termination() {
            debug!("server session [{}]: connection terminated by client (code={})", self.identity.to_string(), tailor.code());
            return Err(SessionControllerError::ConnectionTerminated(tailor.code()));
        }

        if tailor.flags().contains(PacketFlags::HEALTH_CHECK) && !tailor.flags().has_payload() {
            self.health_provider.feed_health_check(tailor.time(), tailor.packet_number());
        }

        if tailor.flags().has_payload() {
            let payload_len = tailor.payload_length() as usize;
            let encrypted_payload = body.rebuffer_start(body.len() - payload_len);

            let decrypt_result = {
                let mut entry = self.crypto_recv.create_entry();
                let user_state = entry.get_mut().await.map_err(SessionControllerError::MissingCache)?;
                user_state.crypto_mut().decrypt_payload(encrypted_payload, None)
            };

            match decrypt_result {
                Ok(decrypted) => {
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

impl<T: IdentityType + Clone + Eq + Hash + Send + ToString, AE: AsyncExecutor> SessionManager for ServerSessionManager<T, AE> {
    async fn send_packet(&self, packet: DynamicByteBuffer, generated: bool) -> Result<(), SessionControllerError> {
        let full_packet = if generated {
            packet
        } else {
            let mut entry = self.crypto_send.create_entry();
            let user_state = entry.get_mut().await.map_err(SessionControllerError::MissingCache)?;
            let encrypted_payload = user_state.crypto_mut().encrypt_payload(packet, None).map_err(SessionControllerError::CryptoError)?;

            let payload_length = encrypted_payload.len() as u16;
            drop(entry);
            let packet_number = self.next_packet_number();

            let encrypted_payload_len = encrypted_payload.len();
            let tailor_buf = encrypted_payload.expand_end(T::length()).rebuffer_start(encrypted_payload_len);
            let _tailor = Tailor::data(tailor_buf, &self.identity, payload_length, packet_number);
            let assembled = encrypted_payload.expand_end(TAILOR_LENGTH + T::length());
            debug!("server session [{}]: sending data packet", self.identity.to_string());
            assembled
        };

        self.route_outgoing(full_packet).await
    }

    #[cfg(feature = "client")]
    async fn receive_packet(&self) -> Result<DynamicByteBuffer, SessionControllerError> {
        Err(SessionControllerError::HealthProviderDied)
    }
}
