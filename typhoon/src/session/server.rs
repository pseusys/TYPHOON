#[cfg(all(test, feature = "tokio", feature = "server", feature = "client"))]
#[path = "../../tests/session/server.rs"]
mod tests;

/// Server-side session manager implementation.
use std::hash::Hash;
use std::marker::PhantomData;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Weak as StdWeak};

use async_trait::async_trait;
use log::{debug, warn};
use rand::Rng;

use crate::bytes::{ByteBuffer, ByteBufferMut, DynamicByteBuffer};
use crate::cache::{CachedMapEntryTemplate, SharedMap};
use crate::crypto::{UserCryptoState, UserServerState};
use crate::session::error::SessionControllerError;
use crate::session::server_health::ServerHealthProvider;
use crate::settings::{Settings, keys};
use crate::tailer::{IdentityType, PacketFlags, ReturnCode, Tailer};
use crate::utils::bitset::AtomicBitSet;
use crate::utils::random::get_rng;
use crate::utils::sync::{AsyncExecutor, NotifyQueueSender, WatchSender};
use crate::utils::unix_timestamp_ms;

/// Trait for routing outgoing packets from a session back to the network.
/// Implemented by the standalone `Router` owned by the listener and shared with each `ClientHandle`.
#[async_trait]
pub trait OutgoingRouter<T: Send + Sync>: Send + Sync {
    async fn route_packet(&self, packet: DynamicByteBuffer, identity: &T) -> bool;
    /// True if `identity`'s currently-registered session is still the one established by the handshake with packet number `handshake_pn`.
    async fn is_current_session(&self, identity: &T, handshake_pn: u64) -> bool;
    /// Remove all state associated with the given identity (session map, user crypto, decoy providers) — but only if the currently-registered session is still the one established by `handshake_pn`.
    /// Returns whether removal happened.
    async fn remove_session(&self, identity: &T, handshake_pn: u64) -> bool;
}

/// Incoming packet for the server session manager: body + tailer view.
pub struct IncomingPacket<T: IdentityType> {
    pub body: DynamicByteBuffer,
    pub tailer: Tailer<T>,
}

/// Server-side session manager for a single client connection.
/// Encapsulates per-user crypto state, the active-flow bitmask, the inbound-data pump, and the health-check provider.
pub struct ServerSessionManager<T: IdentityType + Clone + Eq + Hash + Send + ToString + 'static, AE: AsyncExecutor + 'static> {
    /// Sync template — used per-call to create a local cache entry; no Mutex needed.
    crypto_send: CachedMapEntryTemplate<T, UserServerState>,
    /// Sync template — used per-call to create a local cache entry; no Mutex needed.
    crypto_recv: CachedMapEntryTemplate<T, UserServerState>,
    identity: T,
    /// Packet number of the handshake that established this session.
    handshake_pn: u64,
    /// Lock-free bitmask of flow indices from which this client has been seen.
    active_flows: AtomicBitSet,
    /// Per-session monotonic packet-number counter; shared with the health-check provider and every flow manager's decoy provider for this user so the PN stream is single-sequence across data, health-check, decoy, and termination packets.
    counter: Arc<AtomicU32>,
    incoming_tx: NotifyQueueSender<DynamicByteBuffer>,
    /// Fired once this session is removed, so a task blocked on `incoming_tx`'s receiver can stop waiting instead of hanging.
    end_tx: WatchSender<()>,
    health_provider: ServerHealthProvider,
    _phantom: PhantomData<AE>,
}

impl<T: IdentityType + Clone + Eq + Hash + Send + ToString, AE: AsyncExecutor> ServerSessionManager<T, AE> {
    /// Assemble a new server session from a pre-decapsulated handshake.
    ///
    /// `crypto_state` must be constructed with the initial handshake key **before** calling
    /// this function (the caller uses its `Listener::make_initial_crypto_state` helper).
    /// `response_body` must also be pre-computed outside the `users` lock so that
    /// CPU-intensive `McEliece` work is not serialized through the shared-map mutex.
    /// `router` is forwarded to the health provider only — the session itself
    /// no longer holds a router reference.
    ///
    /// Returns `(Arc<Self>, response_packet)`. The caller holds `session_key` from the
    /// encapsulation step and upgrades the user's crypto state after sending the response.
    pub(crate) async fn assemble_session(crypto_state: UserCryptoState, response_body: DynamicByteBuffer, handshake_tailer: Tailer<T>, identity: T, users: &mut SharedMap<T, UserServerState>, incoming_tx: NotifyQueueSender<DynamicByteBuffer>, end_tx: WatchSender<()>, router: StdWeak<dyn OutgoingRouter<T>>, num_flows: usize, settings: Arc<Settings<AE>>) -> (Arc<Self>, DynamicByteBuffer) {
        let user_state = UserServerState::new(crypto_state);

        users.insert(identity.clone(), user_state).await;

        let crypto_send = users.create_cache_for(identity.clone());
        let crypto_recv = users.create_cache_for(identity.clone());

        let server_next_in = get_rng().gen_range(settings.get(&keys::HEALTH_CHECK_NEXT_IN_MIN)..=settings.get(&keys::HEALTH_CHECK_NEXT_IN_MAX)) as u32;
        let handshake_pn = handshake_tailer.packet_number();

        let response_body_len = response_body.len();
        let tailer_buf = response_body.expand_end(T::length()).rebuffer_start(response_body_len);
        let _response_tailer = Tailer::handshake(tailer_buf, &identity, ReturnCode::Success.into(), server_next_in, handshake_pn, response_body_len as u16);
        let response_packet = response_body.expand_end(Tailer::<T>::len());

        let health_provider = ServerHealthProvider::new(router, identity.clone(), settings, server_next_in, handshake_pn);

        let session = Arc::new(Self {
            crypto_send,
            crypto_recv,
            identity,
            handshake_pn,
            active_flows: AtomicBitSet::new(num_flows),
            counter: Arc::new(AtomicU32::new(0)),
            incoming_tx,
            end_tx,
            health_provider,
            _phantom: PhantomData,
        });

        (session, response_packet)
    }

    /// Packet number of the handshake that established this session.
    pub fn handshake_pn(&self) -> u64 {
        self.handshake_pn
    }

    /// Wake any task waiting on the incoming-data receiver, signaling that the session has ended.
    #[inline]
    pub(crate) fn signal_end(&self) {
        self.end_tx.send(());
    }

    /// Per-session monotonic packet-number counter, shared with the health-check provider and per-flow decoy providers.
    pub fn counter(&self) -> Arc<AtomicU32> {
        Arc::clone(&self.counter)
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

    /// Build the next outgoing wire packet for this session: encrypts the payload, appends the data tailer, and returns the assembled buffer.
    pub async fn prepare_outgoing(&self, packet: DynamicByteBuffer, generated: bool) -> Result<DynamicByteBuffer, SessionControllerError> {
        if generated {
            return Ok(packet);
        }
        let mut entry = self.crypto_send.create_entry();
        let user_state = entry.get_mut().await.map_err(SessionControllerError::MissingCache)?;
        let encrypted_payload = user_state.crypto_mut().encrypt_payload(packet, None).map_err(SessionControllerError::Crypto)?;

        let payload_length = encrypted_payload.len() as u16;
        drop(entry);
        let packet_number = self.next_packet_number();

        let encrypted_payload_len = encrypted_payload.len();
        let tailer_buf = encrypted_payload.expand_end(T::length()).rebuffer_start(encrypted_payload_len);
        let tailer = Tailer::data(tailer_buf, &self.identity, payload_length, packet_number);

        // Let the health provider potentially attach a shadowride.
        self.health_provider.feed_output(tailer.clone()).await?;

        let assembled = encrypted_payload.expand_end(Tailer::<T>::len());
        debug!("server session [{}]: sending data packet", self.identity.to_string());
        Ok(assembled)
    }

    /// Get the next packet number: `(incremental << 32) | unix_timestamp_seconds`.
    /// The counter is kept in the dominant half so raw `PN` ordering is immune to clock adjustments.
    fn next_packet_number(&self) -> u64 {
        let counter = self.counter.fetch_add(1, Ordering::Relaxed).wrapping_add(1);
        let timestamp = (unix_timestamp_ms() / 1000) as u32;
        ((counter as u64) << 32) | (timestamp as u64)
    }

    /// Process an incoming packet from the Listener.
    /// Decrypted data is sent to the `ClientHandle` via `user_data_tx`.
    pub async fn process_incoming(&self, incoming: IncomingPacket<T>) -> Result<(), SessionControllerError> {
        let IncomingPacket {
            body,
            tailer,
        } = incoming;
        debug!("server session [{}]: received {:?} packet", self.identity.to_string(), tailer.flags());

        if tailer.flags().is_termination() {
            debug!("server session [{}]: connection terminated by client (code={})", self.identity.to_string(), tailer.code());
            return Err(SessionControllerError::ConnectionTerminated(tailer.code()));
        }

        if tailer.flags().contains(PacketFlags::HEALTH_CHECK) && !tailer.flags().has_payload() {
            self.health_provider.feed_health_check(tailer.time(), tailer.packet_number());
        }

        if tailer.flags().has_payload() {
            let payload_len = tailer.payload_length() as usize;
            let encrypted_payload = body.rebuffer_start(body.len() - payload_len);

            let decrypt_result = {
                let mut entry = self.crypto_recv.create_entry();
                let user_state = entry.get_mut().await.map_err(SessionControllerError::MissingCache)?;
                user_state.crypto_mut().decrypt_payload(encrypted_payload, None)
            };

            match decrypt_result {
                Ok(decrypted) => {
                    if tailer.flags().contains(PacketFlags::HEALTH_CHECK) {
                        self.health_provider.feed_health_check(tailer.time(), tailer.packet_number());
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
