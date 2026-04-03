use std::collections::HashMap;
use std::future::Future;
use std::hash::Hash;
use std::pin::Pin;
use std::sync::Arc;

use crossbeam::queue::SegQueue;
use log::{debug, info, trace};

use crate::bytes::{ByteBuffer, ByteBufferMut, DynamicByteBuffer};
use crate::cache::SharedMap;
use crate::certificate::ServerKeyPair;
use crate::certificate::ServerSecret;
#[cfg(any(feature = "fast_software", feature = "fast_hardware"))]
use crate::certificate::ObfuscationBufferContainer;
use crate::crypto::{UserCryptoState, UserServerState};
use crate::flow::FlowConfig;
use crate::flow::FlowManager;
use crate::flow::decoy::DecoyCommunicationMode;
use crate::flow::server::ServerFlowManager;
use crate::session::SessionManager;
use crate::session::server::{IncomingPacket, OutgoingRouter, ServerSessionManager};
use crate::settings::{Settings, keys};
use crate::socket::error::ServerSocketError;
use crate::tailor::{IdentityType, PacketFlags, ReturnCode, ServerConnectionHandler, Tailor};
use crate::utils::socket::Socket;
use crate::crypto::PAYLOAD_CRYPTO_OVERHEAD;
use crate::utils::sync::{AsyncExecutor, Mutex, RwLock, WatchReceiver, WatchSender, create_watch};

/// Configuration for a single server flow manager.
pub struct ServerFlowConfiguration {
    socket: Option<Socket>,
    address: Option<std::net::SocketAddr>,
    config: FlowConfig,
}

impl ServerFlowConfiguration {
    /// Create a configuration with a pre-built socket.
    pub fn new(config: FlowConfig, socket: Socket) -> Self {
        Self {
            socket: Some(socket),
            address: None,
            config,
        }
    }

    /// Create a configuration that will bind a socket to the given address.
    pub fn with_address(config: FlowConfig, address: std::net::SocketAddr) -> Self {
        Self {
            socket: None,
            address: Some(address),
            config,
        }
    }
}

/// Builder for constructing a `Listener`.
pub struct ListenerBuilder<T: IdentityType + Clone + Eq + Hash + Send + ToString, AE: AsyncExecutor + 'static, DP, IG: ServerConnectionHandler<T>> {
    settings: Option<Arc<Settings<AE>>>,
    flow_configs: Vec<ServerFlowConfiguration>,
    secret: ServerSecret<'static>,
    identity_generator: IG,
    _phantom: std::marker::PhantomData<(T, DP)>,
}

impl<T: IdentityType + Clone + Eq + Hash + Send + ToString + 'static, AE: AsyncExecutor + 'static, DP: DecoyCommunicationMode<T, AE, ServerFlowManager<T, AE, DP>> + 'static, IG: ServerConnectionHandler<T> + 'static> ListenerBuilder<T, AE, DP, IG> {
    /// Create a new builder with the given server key pair and identity generator.
    pub fn new(key_pair: ServerKeyPair, identity_generator: IG) -> Self {
        Self {
            settings: None,
            flow_configs: Vec::new(),
            secret: key_pair.into_server_secret(),
            identity_generator,
            _phantom: std::marker::PhantomData,
        }
    }

    /// Set custom settings.
    pub fn with_settings(mut self, settings: Arc<Settings<AE>>) -> Self {
        self.settings = Some(settings);
        self
    }

    /// Append a single flow manager configuration.
    pub fn add_flow(mut self, config: ServerFlowConfiguration) -> Self {
        self.flow_configs.push(config);
        self
    }

    /// Set all flow manager configurations at once.
    pub fn with_flows(mut self, configs: Vec<ServerFlowConfiguration>) -> Self {
        self.flow_configs = configs;
        self
    }

    /// Build the listener, creating all flow managers.
    #[cfg(any(feature = "fast_software", feature = "fast_hardware"))]
    pub async fn build(mut self) -> Result<Listener<T, AE, DP, IG>, ServerSocketError> {
        if self.flow_configs.is_empty() {
            return Err(ServerSocketError::NoFlows);
        }

        let settings = self.settings.take().unwrap_or_else(|| Arc::new(Settings::default()));
        let users: SharedMap<T, UserServerState> = SharedMap::new();
        let mut flows = Vec::with_capacity(self.flow_configs.len());

        let tailor_wire_len = T::length() + crate::crypto::ServerCryptoTool::<T>::tailor_overhead();
        let mut max_data_payload = usize::MAX;

        let obfs_buffer = self.secret.obfuscation_buffer();

        for flow_config in self.flow_configs.drain(..) {
            flow_config.config.assert(settings.mtu()).map_err(ServerSocketError::FlowError)?;

            let flow_overhead = flow_config.config.max_overhead()
                + PAYLOAD_CRYPTO_OVERHEAD
                + tailor_wire_len;
            max_data_payload = max_data_payload.min(settings.mtu().saturating_sub(flow_overhead));

            let sock = match flow_config.socket {
                Some(socket) => socket,
                None => {
                    let address = flow_config.address.expect("ServerFlowConfiguration must have either socket or address");
                    Socket::bind(address).await.map_err(ServerSocketError::SocketError)?
                }
            };

            let crypto_send = crate::crypto::ServerCryptoTool::new(users.create_cache(), obfs_buffer.clone());
            let crypto_recv = crate::crypto::ServerCryptoTool::new(users.create_cache(), obfs_buffer.clone());
            let flow = ServerFlowManager::new(flow_config.config, crypto_send, crypto_recv, settings.clone(), sock);
            flows.push(flow);
        }
        let max_data_payload = if max_data_payload == usize::MAX { settings.mtu() } else { max_data_payload };
        info!("listener built: max_data_payload={}B (mtu={}B, {} flow(s))", max_data_payload, settings.mtu(), flows.len());

        // Accept signal: WatchSender — fires once per pushed ClientHandle to wake accept().
        let (accept_signal_tx, accept_signal_rx) = create_watch();

        Ok(Listener {
            flows,
            sessions: RwLock::new(HashMap::new()),
            users: Mutex::new(users),
            secret: self.secret,
            identity_generator: self.identity_generator,
            accept_queue: SegQueue::new(),
            accept_signal_tx,
            accept_signal_rx: Mutex::new(accept_signal_rx),
            max_data_payload,
            settings,
        })
    }

    /// Build the listener, creating all flow managers (full mode).
    #[cfg(any(feature = "full_software", feature = "full_hardware"))]
    pub async fn build(mut self) -> Result<Listener<T, AE, DP, IG>, ServerSocketError> {
        if self.flow_configs.is_empty() {
            return Err(ServerSocketError::NoFlows);
        }

        let settings = self.settings.take().unwrap_or_else(|| Arc::new(Settings::default()));
        let users: SharedMap<T, UserServerState> = SharedMap::new();
        let mut flows = Vec::with_capacity(self.flow_configs.len());

        let tailor_wire_len = T::length() + crate::crypto::ServerCryptoTool::<T>::tailor_overhead();
        let mut max_data_payload = usize::MAX;

        let secret_arc = Arc::new(self.secret);

        for flow_config in self.flow_configs.drain(..) {
            flow_config.config.assert(settings.mtu()).map_err(ServerSocketError::FlowError)?;

            let flow_overhead = flow_config.config.max_overhead()
                + PAYLOAD_CRYPTO_OVERHEAD
                + tailor_wire_len;
            max_data_payload = max_data_payload.min(settings.mtu().saturating_sub(flow_overhead));

            let sock = match flow_config.socket {
                Some(socket) => socket,
                None => {
                    let address = flow_config.address.expect("ServerFlowConfiguration must have either socket or address");
                    Socket::bind(address).await.map_err(ServerSocketError::SocketError)?
                }
            };

            let crypto_send = crate::crypto::ServerCryptoTool::new(users.create_cache(), Arc::clone(&secret_arc));
            let crypto_recv = crate::crypto::ServerCryptoTool::new(users.create_cache(), Arc::clone(&secret_arc));
            let flow = ServerFlowManager::new(flow_config.config, crypto_send, crypto_recv, settings.clone(), sock);
            flows.push(flow);
        }
        let max_data_payload = if max_data_payload == usize::MAX { settings.mtu() } else { max_data_payload };
        info!("listener built: max_data_payload={}B (mtu={}B, {} flow(s))", max_data_payload, settings.mtu(), flows.len());

        // Accept signal: WatchSender — fires once per pushed ClientHandle to wake accept().
        let (accept_signal_tx, accept_signal_rx) = create_watch();

        Ok(Listener {
            flows,
            sessions: RwLock::new(HashMap::new()),
            users: Mutex::new(users),
            secret: secret_arc,
            identity_generator: self.identity_generator,
            accept_queue: SegQueue::new(),
            accept_signal_tx,
            accept_signal_rx: Mutex::new(accept_signal_rx),
            max_data_payload,
            settings,
        })
    }
}

/// Server-side listener that manages flow managers and client sessions.
pub struct Listener<T: IdentityType + Clone + Eq + Hash + Send + ToString + 'static, AE: AsyncExecutor + 'static, DP: DecoyCommunicationMode<T, AE, ServerFlowManager<T, AE, DP>> + 'static, IG: ServerConnectionHandler<T> + 'static> {
    flows: Vec<Arc<ServerFlowManager<T, AE, DP>>>,
    sessions: RwLock<HashMap<T, Arc<ServerSessionManager<T, AE>>>>,
    users: Mutex<SharedMap<T, UserServerState>>,
    #[cfg(any(feature = "fast_software", feature = "fast_hardware"))]
    secret: ServerSecret<'static>,
    #[cfg(any(feature = "full_software", feature = "full_hardware"))]
    secret: Arc<ServerSecret<'static>>,
    identity_generator: IG,
    accept_queue: SegQueue<ClientHandle<T, AE>>,
    accept_signal_tx: WatchSender<()>,
    accept_signal_rx: Mutex<WatchReceiver<()>>,
    /// Maximum user-data bytes per packet so the wire packet fits within MTU.
    max_data_payload: usize,
    settings: Arc<Settings<AE>>,
}

impl<T: IdentityType + Clone + Eq + Hash + Send + ToString + 'static, AE: AsyncExecutor + 'static, DP: DecoyCommunicationMode<T, AE, ServerFlowManager<T, AE, DP>> + 'static, IG: ServerConnectionHandler<T> + 'static> Listener<T, AE, DP, IG> {
    /// Start the listener's background receive loops.
    /// Must be called after build() to begin processing incoming packets.
    ///
    /// Each flow gets two tasks:
    /// - A fast **drain task** that calls `receive_raw` and immediately pushes
    ///   raw packets into a channel via `try_send`, then loops back. If the
    ///   route task is slow and the channel is full the packet is dropped, keeping
    ///   the OS socket buffer empty at all times.
    /// - A **route task** that pulls from the channel and calls `route_incoming`.
    pub async fn start(self: &Arc<Self>) {
        let drain_capacity = self.settings.get(&keys::DRAIN_CHANNEL_CAPACITY) as usize;

        for (index, flow) in self.flows.iter().enumerate() {
            let queue = Arc::new(crossbeam::queue::ArrayQueue::new(drain_capacity));
            let (wake_tx, mut wake_rx) = create_watch::<()>();

            // Drain task: only reads from the socket and pushes to the lock-free queue immediately.
            let flow_drain = Arc::clone(flow);
            let settings_drain = Arc::clone(&self.settings);
            let queue_drain = Arc::clone(&queue);
            self.settings.executor().spawn(async move {
                loop {
                    // Allocate a fresh buffer each iteration: the decrypted payload view
                    // shares backing memory with recv_buf, so reusing it across iterations
                    // would corrupt queue items that haven't been consumed yet.
                    let recv_buf = settings_drain.pool().allocate_for_recv();
                    match flow_drain.receive_raw(recv_buf).await {
                        Ok(raw_packet) => {
                            // push: drop the packet rather than blocking the drain loop.
                            queue_drain.push(raw_packet).ok();
                            wake_tx.send(());
                        }
                        Err(err) => {
                            debug!("flow manager {} receive error: {}", index, err);
                            break;
                        }
                    }
                }
                // wake_tx dropped here — route task will see None from wake_rx.recv() and exit.
            });

            // Route task: drains the queue each time the drain task signals a new packet.
            let listener = Arc::clone(self);
            self.settings.executor().spawn(async move {
                loop {
                    while let Some(raw_packet) = queue.pop() {
                        listener.route_incoming(raw_packet, index).await;
                    }
                    if wake_rx.recv().await.is_none() {
                        break;
                    }
                }
            });
        }
    }

    /// Route an incoming packet to the appropriate session or create a new one.
    async fn route_incoming(self: &Arc<Self>, raw_packet: crate::flow::server::RawReceivedPacket<T>, flow_index: usize) {
        let identity = raw_packet.tailor.identity();

        // Check if this is a handshake packet from a new client.
        if raw_packet.tailor.flags().contains(PacketFlags::HANDSHAKE) {
            {
                let sessions = self.sessions.read().await;
                if sessions.contains_key(&identity) {
                    debug!("duplicate handshake from known client, ignoring");
                    return;
                }
            }

            self.handle_new_client(raw_packet, flow_index).await;
            return;
        }

        // Route to existing session via direct Arc call.
        let session = {
            let sessions = self.sessions.read().await;
            sessions.get(&identity).cloned()
        };

        if let Some(session) = session {
            // Record which flow this packet arrived on (lock-free, atomic bitmask on session).
            session.note_active_flow(flow_index);

            let incoming = IncomingPacket {
                body: raw_packet.body,
                tailor: raw_packet.tailor,
            };
            if let Err(err) = session.process_incoming(incoming).await {
                debug!("session processing error for {}: {}", identity.to_string(), err);
            }
        } else {
            debug!("packet from unknown identity {}, dropping", identity.to_string());
        }
    }

    /// Handle a handshake from a new client: create session, send response, publish ClientHandle.
    async fn handle_new_client(self: &Arc<Self>, raw_packet: crate::flow::server::RawReceivedPacket<T>, flow_index: usize) {
        // Decapsulate client handshake to get server data, initial key, and client initial data.
        let (server_data, initial_key, client_initial_data) = self.secret.decapsulate_handshake_server(raw_packet.body);

        // Check client version from the handshake tailor ID field.
        let client_version_identity = raw_packet.tailor.identity();
        if !self.identity_generator.verify_version(client_version_identity.to_bytes()) {
            // Temporarily register client with initial key so the tailor can be obfuscated.
            {
                let mut users = self.users.lock().await;
                #[cfg(any(feature = "fast_software", feature = "fast_hardware"))]
                let crypto_state = UserCryptoState::new(&initial_key, self.secret.obfuscation_buffer());
                #[cfg(any(feature = "full_software", feature = "full_hardware"))]
                let crypto_state = UserCryptoState::new(&initial_key);
                users.insert(client_version_identity.clone(), UserServerState::new(crypto_state)).await;
            }
            self.flows[flow_index].register_user_addr(client_version_identity.clone(), raw_packet.source_addr).await;
            let pn = ((crate::utils::time::unix_timestamp_ms() / 1000) as u64) << 32;
            let buf = self.settings.pool().allocate(Some(T::length()));
            let tailor = Tailor::termination(buf, &client_version_identity, ReturnCode::VersionMismatch, pn);
            if let Err(err) = self.flows[flow_index].send_packet(tailor.into_buffer(), true).await {
                debug!("failed to send version mismatch rejection: {}", err);
            }
            {
                let mut users = self.users.lock().await;
                users.remove(&client_version_identity).await;
            }
            return;
        }

        // Generate identity from decrypted client initial data and produce server initial data.
        let identity = self.identity_generator.generate(&client_initial_data);
        let server_initial_data = self.identity_generator.initial_data(&identity);

        // Incoming data queue and wake signal: session pushes decrypted packets, ClientHandle pops.
        let incoming_queue: Arc<crossbeam::queue::SegQueue<DynamicByteBuffer>> = Arc::new(crossbeam::queue::SegQueue::new());
        let (incoming_wake_tx, incoming_wake_rx) = create_watch::<()>();

        // Create Weak<dyn OutgoingRouter<T>> for the session to send packets back.
        let self_dyn: Arc<dyn OutgoingRouter<T>> = Arc::clone(self) as Arc<dyn OutgoingRouter<T>>;
        let router_weak = Arc::downgrade(&self_dyn);

        // Create session manager from pre-decapsulated handshake data.
        // User is initially registered with the initial key so the handshake response
        // tailor can be verified by the client before it derives the session key.
        let (session, response_packet, session_key) = {
            let mut users = self.users.lock().await;
            match ServerSessionManager::from_handshake(
                server_data,
                initial_key,
                &server_initial_data,
                raw_packet.tailor,
                identity.clone(),
                &self.secret,
                &mut users,
                Arc::clone(&incoming_queue),
                incoming_wake_tx,
                router_weak,
                self.flows.len(),
                self.settings.clone(),
            )
            .await
            {
                Ok(result) => result,
                Err(err) => {
                    debug!("handshake failed: {}", err);
                    return;
                }
            }
        };

        // Register initial source address on the handshake flow manager.
        self.flows[flow_index].register_user_addr(identity.clone(), raw_packet.source_addr).await;

        // Register user in all flow managers for decoy traffic.
        for flow in &self.flows {
            flow.register_user(identity.clone()).await;
        }

        // Send handshake response through the flow that received the handshake.
        // At this point the tailor is encrypted/authenticated with the initial key.
        if let Err(err) = self.flows[flow_index].send_packet(response_packet, false).await {
            debug!("failed to send handshake response: {}", err);
            return;
        }

        // Upgrade user crypto from initial key to session key.
        // Re-insert propagates the change to all CachedMap instances via version bump.
        {
            let mut users = self.users.lock().await;
            if let Some(user_state) = users.get(&identity).cloned() {
                let mut upgraded = user_state;
                #[cfg(any(feature = "fast_software", feature = "fast_hardware"))]
                upgraded.upgrade_crypto(&session_key, self.secret.obfuscation_buffer());
                #[cfg(any(feature = "full_software", feature = "full_hardware"))]
                upgraded.upgrade_crypto(&session_key);
                users.insert(identity.clone(), upgraded).await;
            }
        }

        // Mark the handshake flow as active for this session (lock-free, atomic bitmask).
        session.note_active_flow(flow_index);

        // Store session.
        {
            let mut sessions = self.sessions.write().await;
            sessions.insert(identity.clone(), Arc::clone(&session));
        }

        // Create and publish ClientHandle via crossbeam queue.
        let client_handle = ClientHandle {
            session,
            incoming_queue,
            incoming_wake: Mutex::new(incoming_wake_rx),
            max_data_payload: self.max_data_payload,
            settings: self.settings.clone(),
        };
        self.accept_queue.push(client_handle);
        self.accept_signal_tx.send(());

        info!("new client connected: {}", identity.to_string());
    }

    /// Wait for the next client connection and return a handle to it.
    pub async fn accept(&self) -> Result<ClientHandle<T, AE>, ServerSocketError> {
        loop {
            if let Some(handle) = self.accept_queue.pop() {
                return Ok(handle);
            }
            match self.accept_signal_rx.lock().await.recv().await {
                Some(()) => continue,
                None => return Err(ServerSocketError::ListenerStopped),
            }

        }
    }
}

/// OutgoingRouter implementation: selects an active flow via the per-session bitmask and sends the packet.
impl<T: IdentityType + Clone + Eq + Hash + Send + ToString + 'static, AE: AsyncExecutor + 'static, DP: DecoyCommunicationMode<T, AE, ServerFlowManager<T, AE, DP>> + 'static, IG: ServerConnectionHandler<T> + 'static> OutgoingRouter<T> for Listener<T, AE, DP, IG> {
    fn route_packet<'a>(&'a self, packet: DynamicByteBuffer, identity: &'a T) -> Pin<Box<dyn Future<Output = bool> + Send + 'a>> {
        Box::pin(async move {
            let session = {
                let sessions = self.sessions.read().await;
                sessions.get(identity).cloned()
            };
            let Some(session) = session else { return false; };
            let flow_idx = session.select_active_flow(self.flows.len());
            if flow_idx < self.flows.len() {
                self.flows[flow_idx].send_packet(packet, false).await.is_ok()
            } else {
                false
            }
        })
    }
}

/// Handle to a connected client, providing send/receive operations.
/// Not cloneable — only one handle per connection.
pub struct ClientHandle<T: IdentityType + Clone + Eq + Hash + Send + ToString + 'static, AE: AsyncExecutor + 'static> {
    session: Arc<ServerSessionManager<T, AE>>,
    incoming_queue: Arc<crossbeam::queue::SegQueue<DynamicByteBuffer>>,
    incoming_wake: Mutex<WatchReceiver<()>>,
    /// Maximum user-data bytes per packet so the wire packet fits within MTU.
    max_data_payload: usize,
    settings: Arc<Settings<AE>>,
}

impl<T: IdentityType + Clone + Eq + Hash + Send + ToString, AE: AsyncExecutor> ClientHandle<T, AE> {
    /// Send a packet using a pre-allocated buffer.
    pub async fn send(&self, packet: DynamicByteBuffer) -> Result<(), ServerSocketError> {
        trace!("ClientHandle::send {} bytes", packet.len());
        self.session.send_packet(packet, false).await.map_err(ServerSocketError::SessionError)
    }

    /// Send a byte slice, splitting into payload-sized chunks so each wire packet fits within MTU.
    pub async fn send_bytes(&self, data: &[u8]) -> Result<(), ServerSocketError> {
        let total = data.chunks(self.max_data_payload).count();
        trace!("ClientHandle::send_bytes {} bytes → {} chunk(s) of max {}B", data.len(), total, self.max_data_payload);
        for chunk in data.chunks(self.max_data_payload) {
            let buffer = self.settings.pool().allocate(Some(chunk.len()));
            buffer.slice_mut().copy_from_slice(chunk);
            self.send(buffer).await?;
        }
        Ok(())
    }

    /// Maximum user-data bytes per `send` call so the wire packet fits within MTU.
    pub fn max_data_payload(&self) -> usize {
        self.max_data_payload
    }

    /// Receive a packet, returning the decrypted payload as a buffer.
    pub async fn receive(&self) -> Result<DynamicByteBuffer, ServerSocketError> {
        loop {
            if let Some(buf) = self.incoming_queue.pop() {
                trace!("ClientHandle::receive {} bytes", buf.len());
                return Ok(buf);
            }
            match self.incoming_wake.lock().await.recv().await {
                Some(()) => continue,
                None => return Err(ServerSocketError::ChannelClosed),
            }
        }
    }

    /// Receive a packet, returning the decrypted payload as a byte vector.
    pub async fn receive_bytes(&self) -> Result<Vec<u8>, ServerSocketError> {
        let buffer = self.receive().await?;
        Ok(buffer.slice().to_vec())
    }
}
