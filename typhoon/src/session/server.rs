/// Server-side session manager implementation.
use std::future::Future;
use std::hash::Hash;
use std::pin::Pin;
use std::sync::{Arc, Weak as StdWeak};

use log::debug;

use crate::bytes::{ByteBuffer, ByteBufferMut, DynamicByteBuffer};
use crate::cache::{CachedMapEntry, SharedMap};
#[cfg(any(feature = "full_software", feature = "full_hardware"))]
use crate::crypto::ServerSecret;
use crate::crypto::{UserCryptoState, UserServerState};
use crate::session::common::SessionManager;
use crate::session::error::SessionControllerError;
use crate::settings::Settings;
use crate::tailor::{IdentityType, PacketFlags, ReturnCode, Tailor};
use crate::utils::sync::{AsyncExecutor, ChannelSender, Mutex};
use crate::utils::time::unix_timestamp_ms;

/// Trait for routing outgoing packets from a session back to the network.
/// Implemented by the Listener, stored as `Weak<dyn OutgoingRouter<T>>` in each session.
pub(crate) trait OutgoingRouter<T>: Send + Sync {
    fn route_packet<'a>(&'a self, packet: DynamicByteBuffer, identity: &'a T) -> Pin<Box<dyn Future<Output = bool> + Send + 'a>>;
}

/// Incoming packet for the server session manager: body + tailor view.
pub struct IncomingPacket<T: IdentityType> {
    pub body: DynamicByteBuffer,
    pub tailor: Tailor<T>,
}

/// Server-side session manager for a single client connection.
pub struct ServerSessionManager<T: IdentityType + Clone + Eq + Hash + Send + ToString + 'static, AE: AsyncExecutor + 'static> {
    crypto: Mutex<CachedMapEntry<T, UserServerState>>,
    identity: T,
    incremental_counter: Mutex<u32>,
    user_data_tx: ChannelSender<DynamicByteBuffer>,
    router: StdWeak<dyn OutgoingRouter<T>>,
    settings: Arc<Settings<AE>>,
}

impl<T: IdentityType + Clone + Eq + Hash + Send + ToString, AE: AsyncExecutor> ServerSessionManager<T, AE> {
    /// Process a client handshake and create a new server session manager.
    ///
    /// Returns `(Arc<Self>, response_packet)` where response_packet should be sent back
    /// through a flow manager to complete the handshake.
    #[cfg(any(feature = "fast_software", feature = "fast_hardware"))]
    pub async fn from_handshake(
        handshake_body: DynamicByteBuffer,
        handshake_tailor: Tailor<T>,
        source_addr: std::net::SocketAddr,
        secret: &crate::crypto::ServerSecret<'_>,
        users: &mut SharedMap<T, UserServerState>,
        user_data_tx: ChannelSender<DynamicByteBuffer>,
        router: StdWeak<dyn OutgoingRouter<T>>,
        settings: Arc<Settings<AE>>,
    ) -> Result<(Arc<Self>, DynamicByteBuffer), SessionControllerError> {
        use crate::crypto::ObfuscationBufferContainer;

        let pool = settings.pool();

        // Decapsulate client handshake to get server data + initial encryption key.
        let (server_data, _initial_key) = secret.decapsulate_handshake_server(handshake_body);

        // Generate server handshake response and derive session key.
        let (response_body, session_key) = secret.encapsulate_handshake_server(server_data, pool);

        // Create per-user crypto state.
        let obfuscation_buffer = secret.obfuscation_buffer();
        let crypto_state = UserCryptoState::new(&session_key, obfuscation_buffer);
        let user_state = UserServerState::new(crypto_state, source_addr);

        // Insert user into shared map.
        let identity = handshake_tailor.identity();
        users.insert(identity.clone(), user_state).await;

        // Create crypto cache for this session.
        let crypto_cache = users.create_cache_for(identity.clone());

        // Assemble response packet: response_body || tailor.
        let next_in = handshake_tailor.time();
        let response_body_len = response_body.len();
        let tailor_buf = response_body.expand_end(T::length()).rebuffer_start(response_body_len);
        let response_tailor = Tailor::handshake(
            tailor_buf,
            &identity,
            ReturnCode::Success.into(),
            next_in,
            handshake_tailor.packet_number(),
        );
        let response_packet = response_tailor.into_buffer();

        let session = Arc::new(Self {
            crypto: Mutex::new(crypto_cache),
            identity,
            incremental_counter: Mutex::new(0),
            user_data_tx,
            router,
            settings,
        });

        Ok((session, response_packet))
    }

    /// Process a client handshake and create a new server session manager (full mode).
    #[cfg(any(feature = "full_software", feature = "full_hardware"))]
    pub async fn from_handshake(
        handshake_body: DynamicByteBuffer,
        handshake_tailor: Tailor<T>,
        source_addr: std::net::SocketAddr,
        secret: &ServerSecret<'_>,
        users: &mut SharedMap<T, UserServerState>,
        user_data_tx: ChannelSender<DynamicByteBuffer>,
        router: StdWeak<dyn OutgoingRouter<T>>,
        settings: Arc<Settings<AE>>,
    ) -> Result<(Arc<Self>, DynamicByteBuffer), SessionControllerError> {
        let pool = settings.pool();

        // Decapsulate client handshake to get server data + initial encryption key.
        let (server_data, _initial_key) = secret.decapsulate_handshake_server(handshake_body);

        // Generate server handshake response and derive session key.
        let (response_body, session_key) = secret.encapsulate_handshake_server(server_data, pool);

        // Create per-user crypto state.
        let crypto_state = UserCryptoState::new(&session_key);
        let user_state = UserServerState::new(crypto_state, source_addr);

        // Insert user into shared map.
        let identity = handshake_tailor.identity();
        users.insert(identity.clone(), user_state).await;

        // Create crypto cache for this session.
        let crypto_cache = users.create_cache_for(identity.clone());

        // Assemble response packet: response_body || tailor.
        let next_in = handshake_tailor.time();
        let response_body_len = response_body.len();
        let tailor_buf = response_body.expand_end(T::length()).rebuffer_start(response_body_len);
        let response_tailor = Tailor::handshake(
            tailor_buf,
            &identity,
            ReturnCode::Success.into(),
            next_in,
            handshake_tailor.packet_number(),
        );
        let response_packet = response_tailor.into_buffer();

        let session = Arc::new(Self {
            crypto: Mutex::new(crypto_cache),
            identity,
            incremental_counter: Mutex::new(0),
            user_data_tx,
            router,
            settings,
        });

        Ok((session, response_packet))
    }

    /// Get the next packet number: (unix_timestamp_seconds << 32) | incremental.
    async fn next_packet_number(&self) -> u64 {
        let mut counter = self.incremental_counter.lock().await;
        *counter += 1;
        let timestamp = (unix_timestamp_ms() / 1000) as u32;
        ((timestamp as u64) << 32) | (*counter as u64)
    }

    /// Route a packet to the network via the outgoing router (Listener).
    async fn route_outgoing(&self, packet: DynamicByteBuffer) -> Result<(), SessionControllerError> {
        let router = self.router.upgrade().ok_or(SessionControllerError::FlowError(
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

        // Handle termination.
        if tailor.flags().is_termination() {
            return Err(SessionControllerError::ConnectionTerminated(tailor.code()));
        }

        // Handle health check: respond after the client's requested delay.
        if tailor.flags().contains(PacketFlags::HEALTH_CHECK) && !tailor.flags().has_payload() {
            let next_in = tailor.time();
            let pn = tailor.packet_number();
            self.schedule_health_response(next_in, pn).await?;
        }

        // If there is data payload, decrypt and forward to ClientHandle.
        if tailor.flags().has_payload() {
            let payload_len = tailor.payload_length() as usize;
            let encrypted_payload = body.rebuffer_start(body.len() - payload_len);

            let mut crypto_lock = self.crypto.lock().await;
            let user_state = crypto_lock.get_mut().await.map_err(SessionControllerError::MissingCache)?;
            match user_state.crypto_mut().decrypt_payload(encrypted_payload, None) {
                Ok(decrypted) => {
                    // If this is a shadowride (data + health check), also respond to the health check.
                    if tailor.flags().contains(PacketFlags::HEALTH_CHECK) {
                        drop(crypto_lock);
                        self.schedule_health_response(tailor.time(), tailor.packet_number()).await?;
                    }
                    if !self.user_data_tx.send(decrypted).await {
                        return Err(SessionControllerError::HealthProviderDied);
                    }
                }
                Err(err) => {
                    debug!("error decrypting payload: {}", err);
                }
            }
        }

        Ok(())
    }

    /// Schedule a health check response.
    async fn schedule_health_response(&self, client_next_in: u32, _client_pn: u64) -> Result<(), SessionControllerError> {
        let pn = self.next_packet_number().await;
        let identity = self.identity.clone();
        let buf = self.settings.pool().allocate(Some(T::length()));
        let response_tailor = Tailor::health_check(buf, &identity, client_next_in, pn);

        self.route_outgoing(response_tailor.into_buffer()).await
    }
}

impl<T: IdentityType + Clone + Eq + Hash + Send + ToString, AE: AsyncExecutor> SessionManager for ServerSessionManager<T, AE> {
    async fn send_packet(&self, packet: DynamicByteBuffer, generated: bool) -> Result<(), SessionControllerError> {
        let full_packet = if generated {
            // Already assembled (tailor included), pass through.
            packet
        } else {
            // User data: encrypt payload, create DATA tailor, assemble.
            let mut crypto_lock = self.crypto.lock().await;
            let user_state = crypto_lock.get_mut().await.map_err(SessionControllerError::MissingCache)?;
            let encrypted_payload = user_state.crypto_mut().encrypt_payload(packet, None).map_err(SessionControllerError::CryptoError)?;

            let payload_length = encrypted_payload.len() as u16;
            let packet_number = {
                drop(crypto_lock);
                self.next_packet_number().await
            };

            let encrypted_payload_len = encrypted_payload.len();
            let tailor_buf = encrypted_payload.expand_end(T::length()).rebuffer_start(encrypted_payload_len);
            let tailor = Tailor::data(tailor_buf, &self.identity, payload_length, packet_number);
            tailor.into_buffer()
        };

        self.route_outgoing(full_packet).await
    }

    async fn receive_packet(&self) -> Result<DynamicByteBuffer, SessionControllerError> {
        // Not used directly — the Listener drives incoming packet processing.
        Err(SessionControllerError::HealthProviderDied)
    }
}
