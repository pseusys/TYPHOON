use std::collections::HashMap;
use std::hash::Hash;
use std::net::SocketAddr;
use std::sync::Arc;

use async_trait::async_trait;
use crossbeam::queue::SegQueue;
use log::{debug, info, warn};

use crate::bytes::{ByteBuffer, ByteBufferMut, DynamicByteBuffer};
use crate::cache::SharedMap;
#[cfg(any(feature = "fast_software", feature = "fast_hardware"))]
use crate::certificate::ObfuscationBufferContainer;
use crate::certificate::{ServerKeyPair, ServerSecret};
use crate::crypto::{PAYLOAD_CRYPTO_OVERHEAD, ServerCryptoTool, UserCryptoState, UserServerState};
use crate::flow::decoy::{DecoyFactory, random_decoy_factory};
use crate::flow::probe::ProbeFactory;
use crate::flow::server::{RawReceivedPacket, ServerFlowManager};
use crate::flow::{FlowConfig, FlowManager};
use crate::session::server::{IncomingPacket, OutgoingRouter, ServerSessionManager};
use crate::session::{SessionControllerError, SessionManager};
use crate::settings::{Settings, keys};
use crate::socket::error::ServerSocketError;
use crate::tailor::{IdentityType, PacketFlags, ReturnCode, ServerConnectionHandler, Tailor};
use crate::utils::socket::Socket;
use crate::utils::sync::{AsyncExecutor, Mutex, NotifyQueueReceiver, RwLock, WatchReceiver, WatchSender, create_bounded_notify_queue, create_notify_queue, create_watch};
use crate::utils::unix_timestamp_ms;

/// Configuration for a single server flow manager.
pub struct ServerFlowConfiguration<T: IdentityType + Clone, AE: AsyncExecutor> {
    socket: Option<Socket>,
    address: Option<SocketAddr>,
    config: FlowConfig,
    /// Number of SO_REUSEPORT reader sockets to create (Linux only; default 1).
    /// Values > 1 are silently clamped to 1 on non-Linux platforms.
    reader_count: usize,
    /// Optional per-flow decoy factory. Falls back to the listener's default when `None`.
    decoy_factory: Option<DecoyFactory<T, AE>>,
    /// Optional per-flow probe factory. Falls back to the listener's default when `None`.
    probe_factory: Option<ProbeFactory<AE>>,
}

impl<T: IdentityType + Clone + 'static, AE: AsyncExecutor + 'static> ServerFlowConfiguration<T, AE> {
    /// Create a configuration with a pre-built socket.
    pub fn new(config: FlowConfig, socket: Socket) -> Self {
        Self {
            socket: Some(socket),
            address: None,
            config,
            reader_count: 1,
            decoy_factory: None,
            probe_factory: None,
        }
    }

    /// Create a configuration that will bind a socket to the given address.
    pub fn with_address(config: FlowConfig, address: SocketAddr) -> Self {
        Self {
            socket: None,
            address: Some(address),
            config,
            reader_count: 1,
            decoy_factory: None,
            probe_factory: None,
        }
    }

    /// Set the number of SO_REUSEPORT reader sockets (Linux only).
    /// The kernel distributes incoming datagrams across all sockets by 4-tuple hash,
    /// enabling N concurrent `recv_from` drain tasks with no per-packet locking.
    /// Has no effect (silently clamped to 1) on non-Linux platforms.
    pub fn with_reader_count(mut self, count: usize) -> Self {
        self.reader_count = count.max(1);
        self
    }

    /// Override the decoy provider factory for this flow.
    /// When not set, the listener's default factory (random selection) is used.
    pub fn with_decoy_factory(mut self, factory: DecoyFactory<T, AE>) -> Self {
        self.decoy_factory = Some(factory);
        self
    }

    /// Override the decoy provider for this flow using a concrete type.
    pub fn with_decoy<DP: crate::flow::decoy::DecoyCommunicationMode<T, AE> + 'static>(mut self) -> Self {
        self.decoy_factory = Some(crate::flow::decoy::decoy_factory::<T, AE, DP>());
        self
    }

    /// Override the active probe handler factory for this flow.
    pub fn with_probe_factory(mut self, factory: ProbeFactory<AE>) -> Self {
        self.probe_factory = Some(factory);
        self
    }

    /// Override the active probe handler type for this flow.
    pub fn with_probe<PM: crate::flow::probe::ActiveProbeHandler<AE> + Default + 'static>(mut self) -> Self {
        self.probe_factory = Some(crate::flow::probe::probe_factory::<AE, PM>());
        self
    }
}

/// Builder for constructing a `Listener`.
pub struct ListenerBuilder<T: IdentityType + Clone + Eq + Hash + Send + ToString + 'static, AE: AsyncExecutor + 'static, IG: ServerConnectionHandler<T>> {
    settings: Option<Arc<Settings<AE>>>,
    flow_configs: Vec<ServerFlowConfiguration<T, AE>>,
    secret: ServerSecret<'static>,
    identity_generator: IG,
    default_decoy_factory: DecoyFactory<T, AE>,
    default_probe_factory: Option<ProbeFactory<AE>>,
}

impl<T: IdentityType + Clone + Eq + Hash + Send + ToString + 'static, AE: AsyncExecutor + 'static, IG: ServerConnectionHandler<T> + 'static> ListenerBuilder<T, AE, IG> {
    /// Create a new builder with the given server key pair and identity generator.
    /// Decoy providers are randomly selected per-user by default.
    pub fn new(key_pair: ServerKeyPair, identity_generator: IG) -> Self {
        Self {
            settings: None,
            flow_configs: Vec::new(),
            secret: key_pair.into_server_secret(),
            identity_generator,
            default_decoy_factory: random_decoy_factory(),
            default_probe_factory: None,
        }
    }

    /// Set custom settings.
    pub fn with_settings(mut self, settings: Arc<Settings<AE>>) -> Self {
        self.settings = Some(settings);
        self
    }

    /// Override the default decoy factory used for flows that have no per-flow override.
    pub fn with_decoy_factory(mut self, factory: DecoyFactory<T, AE>) -> Self {
        self.default_decoy_factory = factory;
        self
    }

    /// Override the default decoy provider type for all flows without a per-flow override.
    pub fn with_decoy<DP: crate::flow::decoy::DecoyCommunicationMode<T, AE> + 'static>(mut self) -> Self {
        self.default_decoy_factory = crate::flow::decoy::decoy_factory::<T, AE, DP>();
        self
    }

    /// Set the default active probe handler factory for flows that have no per-flow override.
    pub fn with_probe_factory(mut self, factory: ProbeFactory<AE>) -> Self {
        self.default_probe_factory = Some(factory);
        self
    }

    /// Set the default active probe handler type for flows without a per-flow override.
    pub fn with_probe<PM: crate::flow::probe::ActiveProbeHandler<AE> + Default + 'static>(mut self) -> Self {
        self.default_probe_factory = Some(crate::flow::probe::probe_factory::<AE, PM>());
        self
    }

    /// Append a single flow manager configuration.
    pub fn add_flow(mut self, config: ServerFlowConfiguration<T, AE>) -> Self {
        self.flow_configs.push(config);
        self
    }

    /// Set all flow manager configurations at once.
    pub fn with_flows(mut self, configs: Vec<ServerFlowConfiguration<T, AE>>) -> Self {
        self.flow_configs = configs;
        self
    }

    /// Build the listener, creating all flow managers.
    #[cfg(any(feature = "fast_software", feature = "fast_hardware"))]
    pub async fn build(mut self) -> Result<Listener<T, AE, IG>, ServerSocketError> {
        if self.flow_configs.is_empty() {
            return Err(ServerSocketError::NoFlows);
        }

        let settings = self.settings.take().unwrap_or_else(|| Arc::new(Settings::default()));
        let users: SharedMap<T, UserServerState> = SharedMap::new();
        let mut flows = Vec::with_capacity(self.flow_configs.len());

        let tailor_wire_len = T::length() + ServerCryptoTool::<T>::tailor_overhead();
        let mut max_data_payload = usize::MAX;

        let obfs_buffer = self.secret.obfuscation_buffer();

        for flow_config in self.flow_configs.drain(..) {
            flow_config.config.assert(settings.mtu()).map_err(ServerSocketError::FlowError)?;

            max_data_payload = max_data_payload.min(flow_config.config.max_user_payload(settings.mtu(), PAYLOAD_CRYPTO_OVERHEAD, tailor_wire_len));

            let socks: Vec<Arc<Socket>> = if let Some(socket) = flow_config.socket {
                vec![Arc::new(socket)]
            } else {
                let address = flow_config.address.expect("ServerFlowConfiguration must have either socket or address");
                cfg_if::cfg_if! {
                    if #[cfg(target_os = "linux")] {
                        if flow_config.reader_count > 1 {
                            Socket::bind_reuse_port(address, flow_config.reader_count)
                                .map_err(ServerSocketError::SocketError)?
                                .into_iter().map(Arc::new).collect()
                        } else {
                            vec![Arc::new(Socket::bind(address).await.map_err(ServerSocketError::SocketError)?)]
                        }
                    } else {
                        vec![Arc::new(Socket::bind(address).await.map_err(ServerSocketError::SocketError)?)]
                    }
                }
            };

            let decoy_factory = flow_config.decoy_factory.unwrap_or_else(|| Arc::clone(&self.default_decoy_factory));
            let probe_factory = flow_config.probe_factory.as_ref().or(self.default_probe_factory.as_ref());
            let crypto_send = ServerCryptoTool::new(users.create_cache(), obfs_buffer);
            let crypto_recv = ServerCryptoTool::new(users.create_cache(), obfs_buffer);
            let flow = ServerFlowManager::new(flow_config.config, probe_factory, crypto_send, crypto_recv, settings.clone(), socks, decoy_factory).await;
            flows.push(flow);
        }
        let max_data_payload = if max_data_payload == usize::MAX {
            settings.mtu()
        } else {
            max_data_payload
        };
        info!("listener built: max_data_payload={}B (mtu={}B, {} flow(s))", max_data_payload, settings.mtu(), flows.len());

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
    pub async fn build(mut self) -> Result<Listener<T, AE, IG>, ServerSocketError> {
        if self.flow_configs.is_empty() {
            return Err(ServerSocketError::NoFlows);
        }

        let settings = self.settings.take().unwrap_or_else(|| Arc::new(Settings::default()));
        let users: SharedMap<T, UserServerState> = SharedMap::new();
        let mut flows = Vec::with_capacity(self.flow_configs.len());

        let tailor_wire_len = T::length() + ServerCryptoTool::<T>::tailor_overhead();
        let mut max_data_payload = usize::MAX;

        let secret_arc = Arc::new(self.secret);

        for flow_config in self.flow_configs.drain(..) {
            flow_config.config.assert(settings.mtu()).map_err(ServerSocketError::FlowError)?;

            max_data_payload = max_data_payload.min(flow_config.config.max_user_payload(settings.mtu(), PAYLOAD_CRYPTO_OVERHEAD, tailor_wire_len));

            let socks: Vec<Arc<Socket>> = match flow_config.socket {
                Some(socket) => vec![Arc::new(socket)],
                None => {
                    let address = flow_config.address.expect("ServerFlowConfiguration must have either socket or address");
                    cfg_if::cfg_if! {
                        if #[cfg(target_os = "linux")] {
                            if flow_config.reader_count > 1 {
                                Socket::bind_reuse_port(address, flow_config.reader_count)
                                    .map_err(ServerSocketError::SocketError)?
                                    .into_iter().map(Arc::new).collect()
                            } else {
                                vec![Arc::new(Socket::bind(address).await.map_err(ServerSocketError::SocketError)?)]
                            }
                        } else {
                            vec![Arc::new(Socket::bind(address).await.map_err(ServerSocketError::SocketError)?)]
                        }
                    }
                }
            };

            let decoy_factory = flow_config.decoy_factory.unwrap_or_else(|| Arc::clone(&self.default_decoy_factory));
            let probe_factory = flow_config.probe_factory.as_ref().or(self.default_probe_factory.as_ref());
            let crypto_send = ServerCryptoTool::new(users.create_cache(), Arc::clone(&secret_arc));
            let crypto_recv = ServerCryptoTool::new(users.create_cache(), Arc::clone(&secret_arc));
            let flow = ServerFlowManager::new(flow_config.config, probe_factory, crypto_send, crypto_recv, settings.clone(), socks, decoy_factory).await;
            flows.push(flow);
        }
        let max_data_payload = if max_data_payload == usize::MAX {
            settings.mtu()
        } else {
            max_data_payload
        };
        info!("listener built: max_data_payload={}B (mtu={}B, {} flow(s))", max_data_payload, settings.mtu(), flows.len());

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
pub struct Listener<T: IdentityType + Clone + Eq + Hash + Send + ToString + 'static, AE: AsyncExecutor + 'static, IG: ServerConnectionHandler<T> + 'static> {
    flows: Vec<Arc<ServerFlowManager<T, AE>>>,
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

impl<T: IdentityType + Clone + Eq + Hash + Send + ToString + 'static, AE: AsyncExecutor + 'static, IG: ServerConnectionHandler<T> + 'static> Listener<T, AE, IG> {
    /// Create initial user crypto state from a handshake key (fast mode).
    #[cfg(any(feature = "fast_software", feature = "fast_hardware"))]
    #[inline]
    fn make_initial_crypto_state(&self, initial_key: &impl ByteBuffer) -> UserCryptoState {
        UserCryptoState::new(initial_key, self.secret.obfuscation_buffer())
    }

    /// Create initial user crypto state from a handshake key (full mode).
    #[cfg(any(feature = "full_software", feature = "full_hardware"))]
    #[inline]
    fn make_initial_crypto_state(&self, initial_key: &impl ByteBuffer) -> UserCryptoState {
        UserCryptoState::new(initial_key)
    }

    /// Upgrade a user's crypto state from initial key to session key (fast mode).
    #[cfg(any(feature = "fast_software", feature = "fast_hardware"))]
    #[inline]
    fn upgrade_user_crypto(&self, user_state: &mut UserServerState, session_key: &impl ByteBuffer) {
        user_state.upgrade_crypto(session_key, self.secret.obfuscation_buffer());
    }

    /// Upgrade a user's crypto state from initial key to session key (full mode).
    #[cfg(any(feature = "full_software", feature = "full_hardware"))]
    #[inline]
    fn upgrade_user_crypto(&self, user_state: &mut UserServerState, session_key: &impl ByteBuffer) {
        user_state.upgrade_crypto(session_key);
    }

    /// Start the listener's background receive loops.
    /// Must be called after build() to begin processing incoming packets.
    ///
    /// Each flow gets N+1 tasks (where N = number of SO_REUSEPORT sockets, normally 1):
    /// - N **drain tasks**, one per socket, each calling `receive_raw` and immediately pushing
    ///   raw packets into a shared bounded channel. If the route task is slow and the channel is
    ///   full the packet is dropped, keeping the OS socket buffer empty at all times.
    ///   When all N drain tasks exit the `Arc<BoundedNotifyQueueSender>` refcount reaches 0,
    ///   dropping the sender and closing the channel so the route task terminates.
    /// - A **route task** that pulls from the shared channel and calls `route_incoming`.
    pub async fn start(self: &Arc<Self>) {
        let drain_capacity = self.settings.get(&keys::DRAIN_CHANNEL_CAPACITY) as usize;

        for (index, flow) in self.flows.iter().enumerate() {
            let (drain_tx, mut drain_rx) = create_bounded_notify_queue(drain_capacity);
            let drain_tx = Arc::new(drain_tx);

            for (sock_index, sock) in flow.recv_socks().iter().enumerate() {
                let drain_tx = Arc::clone(&drain_tx);
                let sock = Arc::clone(sock);
                let flow_drain = Arc::clone(flow);
                let settings_drain = Arc::clone(&self.settings);
                self.settings.executor().spawn(async move {
                    loop {
                        let recv_buf = settings_drain.pool().allocate_for_recv();
                        match flow_drain.receive_raw(recv_buf, &sock).await {
                            Ok(raw_packet) => drain_tx.push(raw_packet),
                            Err(err) => {
                                warn!("flow manager {index} socket {sock_index}: receive error: {err}");
                                break;
                            }
                        }
                    }
                });
            }
            drop(drain_tx);

            let listener = Arc::clone(self);
            self.settings.executor().spawn(async move {
                while let Some(raw_packet) = drain_rx.recv().await {
                    listener.route_incoming(raw_packet, index).await;
                }
            });
        }
    }

    /// Route an incoming packet to the appropriate session or create a new one.
    async fn route_incoming(self: &Arc<Self>, raw_packet: RawReceivedPacket<T>, flow_index: usize) {
        let identity = raw_packet.tailor.identity();

        if raw_packet.tailor.flags().contains(PacketFlags::HANDSHAKE) {
            self.handle_new_client(raw_packet, flow_index).await;
            return;
        }

        let session = {
            let sessions = self.sessions.read().await;
            sessions.get(&identity).cloned()
        };

        if let Some(session) = session {
            self.flows[flow_index].ensure_user(identity.clone(), raw_packet.source_addr).await;
            session.note_active_flow(flow_index);

            let incoming = IncomingPacket {
                body: raw_packet.body,
                tailor: raw_packet.tailor,
            };
            if let Err(err) = session.process_incoming(incoming).await {
                debug!("session processing error for {}: {}", identity.to_string(), err);
                if matches!(err, SessionControllerError::ConnectionTerminated(_)) {
                    self.remove_session(&identity).await;
                }
            }
        } else {
            debug!("packet from unknown identity {}, dropping", identity.to_string());
        }
    }

    /// Handle a handshake from a new client: create session, send response, publish ClientHandle.
    async fn handle_new_client(self: &Arc<Self>, raw_packet: RawReceivedPacket<T>, flow_index: usize) {
        let (server_data, initial_key, client_initial_data) = self.secret.decapsulate_handshake_server(raw_packet.body, self.settings.pool());

        let client_version_identity = raw_packet.tailor.identity();
        if !self.identity_generator.verify_version(client_version_identity.to_bytes()) {
            {
                let mut users = self.users.lock().await;
                let crypto_state = self.make_initial_crypto_state(&initial_key);
                users.insert(client_version_identity.clone(), UserServerState::new(crypto_state)).await;
            }
            self.flows[flow_index].register_user_addr(client_version_identity.clone(), raw_packet.source_addr).await;
            let pn = ((unix_timestamp_ms() / 1000) as u64) << 32;
            let buf = self.settings.pool().allocate(Some(T::length()));
            let tailor = Tailor::termination(buf, &client_version_identity, ReturnCode::VersionMismatch, pn);
            if let Err(err) = self.flows[flow_index].send_packet(tailor.into_buffer(), true).await {
                warn!("failed to send version mismatch rejection: {err}");
            }
            {
                let mut users = self.users.lock().await;
                users.remove(&client_version_identity).await;
            }
            self.flows[flow_index].remove_user(&client_version_identity).await;
            return;
        }

        let identity = self.identity_generator.generate(client_initial_data.slice());
        let server_initial_data = self.identity_generator.initial_data(&identity);

        let (incoming_tx, incoming_rx) = create_notify_queue::<DynamicByteBuffer>();
        let router_weak = Arc::downgrade(self);

        let (response_body, session_key) = self.secret.encapsulate_handshake_server(server_data, self.settings.pool(), server_initial_data.slice(), &initial_key);

        let (session, response_packet, replacing) = {
            let mut users = self.users.lock().await;
            let replacing = users.contains_key(&identity);
            if replacing {
                debug!("re-handshake for {}: replacing existing session (last wins)", identity.to_string());
                users.remove(&identity).await;
            }
            let initial_crypto_state = self.make_initial_crypto_state(&initial_key);
            let result = ServerSessionManager::assemble_session(initial_crypto_state, response_body, raw_packet.tailor, identity.clone(), &mut users, incoming_tx, router_weak, self.flows.len(), self.settings.clone()).await;
            match result {
                Ok((session, response_packet)) => (session, response_packet, replacing),
                Err(err) => {
                    warn!("handshake failed: {err}");
                    return;
                }
            }
        };

        if replacing {
            self.sessions.write().await.remove(&identity);
            for flow in &self.flows {
                flow.remove_user(&identity).await;
            }
        }

        self.flows[flow_index].register_user_addr(identity.clone(), raw_packet.source_addr).await;
        self.flows[flow_index].register_user(identity.clone()).await;

        if let Err(err) = self.flows[flow_index].send_packet(response_packet, false).await {
            warn!("failed to send handshake response: {err}");
            self.users.lock().await.remove(&identity).await;
            for flow in &self.flows {
                flow.remove_user(&identity).await;
            }
            return;
        }

        {
            let mut users = self.users.lock().await;
            users
                .modify(&identity, |user_state| {
                    self.upgrade_user_crypto(user_state, &session_key);
                })
                .await;
        }

        session.note_active_flow(flow_index);

        {
            let mut sessions = self.sessions.write().await;
            if sessions.contains_key(&identity) {
                debug!("concurrent handshake for {}: last wins, displacing earlier session", identity.to_string());
            }
            sessions.insert(identity.clone(), Arc::clone(&session));
        }

        let client_handle = ClientHandle {
            session,
            incoming_rx: Mutex::new(incoming_rx),
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
                Some(()) => {}
                None => return Err(ServerSocketError::ListenerStopped),
            }
        }
    }
}

/// OutgoingRouter implementation: selects an active flow via the per-session bitmask and sends the packet.
#[async_trait]
impl<T: IdentityType + Clone + Eq + Hash + Send + Sync + ToString + 'static, AE: AsyncExecutor + 'static, IG: ServerConnectionHandler<T> + 'static> OutgoingRouter<T> for Listener<T, AE, IG> {
    async fn route_packet(&self, packet: DynamicByteBuffer, identity: &T) -> bool {
        let session = {
            let sessions = self.sessions.read().await;
            sessions.get(identity).cloned()
        };
        let Some(session) = session else {
            return false;
        };
        let flow_idx = session.select_active_flow(self.flows.len());
        if flow_idx < self.flows.len() {
            self.flows[flow_idx].send_packet(packet, false).await.is_ok()
        } else {
            false
        }
    }

    async fn remove_session(&self, identity: &T) {
        if self.sessions.write().await.remove(identity).is_none() {
            return;
        }
        self.users.lock().await.remove(identity).await;
        for flow in &self.flows {
            flow.remove_user(identity).await;
        }
        info!("client session removed: {}", identity.to_string());
    }
}

/// Handle to a connected client, providing send/receive operations.
/// Not cloneable — only one handle per connection.
pub struct ClientHandle<T: IdentityType + Clone + Eq + Hash + Send + ToString + 'static, AE: AsyncExecutor + 'static> {
    session: Arc<ServerSessionManager<T, AE>>,
    incoming_rx: Mutex<NotifyQueueReceiver<DynamicByteBuffer>>,
    /// Maximum user-data bytes per packet so the wire packet fits within MTU.
    max_data_payload: usize,
    settings: Arc<Settings<AE>>,
}

impl<T: IdentityType + Clone + Eq + Hash + Send + ToString, AE: AsyncExecutor> ClientHandle<T, AE> {
    /// Send a packet using a pre-allocated buffer.
    pub async fn send(&self, packet: DynamicByteBuffer) -> Result<(), ServerSocketError> {
        self.session.send_packet(packet, false).await.map_err(ServerSocketError::SessionError)
    }

    /// Send a byte slice, splitting into payload-sized chunks so each wire packet fits within MTU.
    pub async fn send_bytes(&self, data: &[u8]) -> Result<(), ServerSocketError> {
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
        let buf = self.incoming_rx.lock().await.recv().await.ok_or(ServerSocketError::ChannelClosed)?;
        Ok(buf)
    }

    /// Receive a packet, returning the decrypted payload as a byte vector.
    pub async fn receive_bytes(&self) -> Result<Vec<u8>, ServerSocketError> {
        let buffer = self.receive().await?;
        Ok(buffer.slice().to_vec())
    }
}

impl<T: IdentityType + Clone + Eq + Hash + Send + ToString + 'static, AE: AsyncExecutor + 'static> Drop for ClientHandle<T, AE> {
    fn drop(&mut self) {
        self.session.spawn_cleanup(self.settings.executor());
    }
}
