use std::collections::HashMap;
use std::future::Future;
use std::hash::Hash;
use std::marker::PhantomData;
use std::pin::Pin;
use std::sync::Arc;

use crossbeam::queue::SegQueue;
use log::{debug, info};

use crate::bytes::{ByteBuffer, DynamicByteBuffer};
use crate::cache::SharedMap;
use crate::crypto::ServerSecret;
#[cfg(any(feature = "fast_software", feature = "fast_hardware"))]
use crate::crypto::ObfuscationBufferContainer;
use crate::crypto::UserServerState;
use crate::flow::FlowConfig;
use crate::flow::FlowManager;
use crate::flow::decoy::DecoyCommunicationMode;
use crate::flow::server::ServerFlowManager;
use crate::session::SessionManager;
use crate::session::server::{IncomingPacket, OutgoingRouter, ServerSessionManager};
use crate::settings::{Settings, keys};
use crate::socket::error::ServerSocketError;
use crate::tailor::{IdentityType, PacketFlags};
use crate::utils::random::{SupportRng, get_rng};
use crate::utils::socket::Socket;
use crate::utils::sync::{AsyncExecutor, ChannelReceiver, ChannelSender, Mutex, create_channel};

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
pub struct ListenerBuilder<T: IdentityType + Clone + Eq + Hash + Send + ToString, AE: AsyncExecutor + 'static, DP> {
    settings: Option<Arc<Settings<AE>>>,
    flow_configs: Vec<ServerFlowConfiguration>,
    secret: ServerSecret<'static>,
    _phantom: std::marker::PhantomData<(T, DP)>,
}

impl<T: IdentityType + Clone + Eq + Hash + Send + ToString + 'static, AE: AsyncExecutor + 'static, DP: DecoyCommunicationMode<T, AE, ServerFlowManager<T, AE, DP>> + 'static> ListenerBuilder<T, AE, DP> {
    /// Create a new builder with the given server secret.
    pub fn new(secret: ServerSecret<'static>) -> Self {
        Self {
            settings: None,
            flow_configs: Vec::new(),
            secret,
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
    pub async fn build(mut self) -> Result<Listener<T, AE, DP>, ServerSocketError> {
        if self.flow_configs.is_empty() {
            return Err(ServerSocketError::NoFlows);
        }

        let settings = self.settings.take().unwrap_or_else(|| Arc::new(Settings::default()));
        let users: SharedMap<T, UserServerState> = SharedMap::new();
        let mut flows = Vec::with_capacity(self.flow_configs.len());

        let obfs_buffer = self.secret.obfuscation_buffer();

        for flow_config in self.flow_configs.drain(..) {
            flow_config.config.assert(settings.mtu()).map_err(ServerSocketError::FlowError)?;

            let sock = match flow_config.socket {
                Some(socket) => socket,
                None => {
                    let address = flow_config.address.expect("ServerFlowConfiguration must have either socket or address");
                    Socket::bind(address).await.map_err(ServerSocketError::SocketError)?
                }
            };

            let crypto = crate::crypto::ServerCryptoTool::new(users.create_cache(), obfs_buffer.clone());
            let flow = ServerFlowManager::new(flow_config.config, crypto, settings.clone(), sock);
            flows.push(flow);
        }

        let buffer_size = settings.get(&keys::RECEIVE_BUFFER_SIZE) as usize;
        let (accept_signal_tx, accept_signal_rx) = create_channel(buffer_size);

        Ok(Listener {
            flows,
            sessions: Mutex::new(HashMap::new()),
            users: Mutex::new(users),
            secret: self.secret,
            accept_queue: SegQueue::new(),
            accept_signal_tx,
            accept_signal_rx: Mutex::new(accept_signal_rx),
            settings,
        })
    }

    /// Build the listener, creating all flow managers (full mode).
    #[cfg(any(feature = "full_software", feature = "full_hardware"))]
    pub async fn build(mut self) -> Result<Listener<T, AE, DP>, ServerSocketError> {
        if self.flow_configs.is_empty() {
            return Err(ServerSocketError::NoFlows);
        }

        let settings = self.settings.take().unwrap_or_else(|| Arc::new(Settings::default()));
        let users: SharedMap<T, UserServerState> = SharedMap::new();
        let mut flows = Vec::with_capacity(self.flow_configs.len());

        let secret_arc = Arc::new(self.secret);

        for flow_config in self.flow_configs.drain(..) {
            flow_config.config.assert(settings.mtu()).map_err(ServerSocketError::FlowError)?;

            let sock = match flow_config.socket {
                Some(socket) => socket,
                None => {
                    let address = flow_config.address.expect("ServerFlowConfiguration must have either socket or address");
                    Socket::bind(address).await.map_err(ServerSocketError::SocketError)?
                }
            };

            let crypto = crate::crypto::ServerCryptoTool::new(users.create_cache(), Arc::clone(&secret_arc));
            let flow = ServerFlowManager::new(flow_config.config, crypto, settings.clone(), sock);
            flows.push(flow);
        }

        let buffer_size = settings.get(&keys::RECEIVE_BUFFER_SIZE) as usize;
        let (accept_signal_tx, accept_signal_rx) = create_channel(buffer_size);

        Ok(Listener {
            flows,
            sessions: Mutex::new(HashMap::new()),
            users: Mutex::new(users),
            secret: secret_arc,
            accept_queue: SegQueue::new(),
            accept_signal_tx,
            accept_signal_rx: Mutex::new(accept_signal_rx),
            settings,
        })
    }
}

/// Server-side listener that manages flow managers and client sessions.
pub struct Listener<T: IdentityType + Clone + Eq + Hash + Send + ToString + 'static, AE: AsyncExecutor + 'static, DP: DecoyCommunicationMode<T, AE, ServerFlowManager<T, AE, DP>> + 'static> {
    flows: Vec<Arc<ServerFlowManager<T, AE, DP>>>,
    sessions: Mutex<HashMap<T, Arc<ServerSessionManager<T, AE>>>>,
    users: Mutex<SharedMap<T, UserServerState>>,
    #[cfg(any(feature = "fast_software", feature = "fast_hardware"))]
    secret: ServerSecret<'static>,
    #[cfg(any(feature = "full_software", feature = "full_hardware"))]
    secret: Arc<ServerSecret<'static>>,
    accept_queue: SegQueue<ClientHandle<T, AE>>,
    accept_signal_tx: ChannelSender<()>,
    accept_signal_rx: Mutex<ChannelReceiver<()>>,
    settings: Arc<Settings<AE>>,
}

impl<T: IdentityType + Clone + Eq + Hash + Send + ToString + 'static, AE: AsyncExecutor + 'static, DP: DecoyCommunicationMode<T, AE, ServerFlowManager<T, AE, DP>> + 'static> Listener<T, AE, DP> {
    /// Start the listener's background receive loops.
    /// Must be called after build() to begin processing incoming packets.
    pub async fn start(self: &Arc<Self>) {
        for (index, flow) in self.flows.iter().enumerate() {
            let listener = Arc::clone(self);
            let flow = Arc::clone(flow);
            let recv_buf = self.settings.pool().allocate(None);

            self.settings.executor().spawn(async move {
                loop {
                    match flow.receive_raw(recv_buf.clone()).await {
                        Ok(raw_packet) => {
                            listener.route_incoming(raw_packet, index).await;
                        }
                        Err(err) => {
                            debug!("flow manager {} receive error: {}", index, err);
                            break;
                        }
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
                let sessions = self.sessions.lock().await;
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
            let sessions = self.sessions.lock().await;
            sessions.get(&identity).cloned()
        };

        if let Some(session) = session {
            // Activate this flow for the user.
            {
                let mut users = self.users.lock().await;
                if let Some(user_state) = users.get_mut(&identity) {
                    user_state.activate_flow(flow_index);
                }
            }

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
        let identity = raw_packet.tailor.identity();
        let buffer_size = self.settings.get(&keys::RECEIVE_BUFFER_SIZE) as usize;

        // Create user data channels (session <-> ClientHandle).
        let (user_data_tx, user_data_rx) = create_channel::<DynamicByteBuffer>(buffer_size);
        let (user_outgoing_tx, mut user_outgoing_rx) = create_channel::<DynamicByteBuffer>(buffer_size);

        // Create Weak<dyn OutgoingRouter<T>> for the session to send packets back.
        let self_dyn: Arc<dyn OutgoingRouter<T>> = Arc::clone(self) as Arc<dyn OutgoingRouter<T>>;
        let router_weak = Arc::downgrade(&self_dyn);

        // Process handshake and create session manager.
        let (session, response_packet) = {
            let mut users = self.users.lock().await;
            match ServerSessionManager::from_handshake(
                raw_packet.body,
                raw_packet.tailor,
                &self.secret,
                &mut users,
                user_data_tx,
                router_weak,
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

        // Mark this flow as active for the user.
        {
            let mut users = self.users.lock().await;
            if let Some(user_state) = users.get_mut(&identity) {
                user_state.activate_flow(flow_index);
            }
        }

        // Register initial source address on the handshake flow manager.
        self.flows[flow_index].register_user_addr(identity.clone(), raw_packet.source_addr).await;

        // Register user in all flow managers for decoy traffic.
        for flow in &self.flows {
            flow.register_user(identity.clone()).await;
        }

        // Send handshake response through the flow that received the handshake.
        if let Err(err) = self.flows[flow_index].send_packet(response_packet, false).await {
            debug!("failed to send handshake response: {}", err);
            return;
        }

        // Spawn background loop: process user_data_outgoing (ClientHandle -> Session -> network).
        let session_for_outgoing = Arc::clone(&session);
        self.settings.executor().spawn(async move {
            loop {
                match user_outgoing_rx.recv().await {
                    Some(data) => {
                        if let Err(err) = session_for_outgoing.send_packet(data, false).await {
                            debug!("session send error: {}", err);
                            break;
                        }
                    }
                    None => break,
                }
            }
        });

        // Store session.
        {
            let mut sessions = self.sessions.lock().await;
            sessions.insert(identity.clone(), Arc::clone(&session));
        }

        // Create and publish ClientHandle via crossbeam queue.
        let client_handle = ClientHandle {
            outgoing_tx: Arc::new(user_outgoing_tx),
            incoming_rx: Arc::new(Mutex::new(user_data_rx)),
            settings: self.settings.clone(),
            _phantom: PhantomData,
        };
        self.accept_queue.push(client_handle);
        let _ = self.accept_signal_tx.send(()).await;

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

/// OutgoingRouter implementation: selects an active flow and sends the packet.
impl<T: IdentityType + Clone + Eq + Hash + Send + ToString + 'static, AE: AsyncExecutor + 'static, DP: DecoyCommunicationMode<T, AE, ServerFlowManager<T, AE, DP>> + 'static> OutgoingRouter<T> for Listener<T, AE, DP> {
    fn route_packet<'a>(&'a self, packet: DynamicByteBuffer, identity: &'a T) -> Pin<Box<dyn Future<Output = bool> + Send + 'a>> {
        Box::pin(async move {
            let flow_idx = {
                let users = self.users.lock().await;
                select_active_flow(&users, identity, self.flows.len())
            };
            if flow_idx < self.flows.len() {
                self.flows[flow_idx].send_packet(packet, false).await.is_ok()
            } else {
                false
            }
        })
    }
}

/// Select an active flow manager index for the given user.
fn select_active_flow<T: IdentityType + Clone + Eq + Hash + Send + ToString>(
    users: &SharedMap<T, UserServerState>,
    identity: &T,
    _num_flows: usize,
) -> usize {
    match users.get(identity) {
        Some(user_state) => {
            let active = user_state.active_flows();
            let indices: Vec<usize> = active.ones().collect();
            if indices.is_empty() {
                0
            } else {
                *get_rng().random_item(&indices).unwrap()
            }
        }
        None => 0,
    }
}

/// Handle to a connected client, providing send/receive operations.
#[derive(Clone)]
pub struct ClientHandle<T: IdentityType + Clone + Eq + Hash + Send + ToString + 'static, AE: AsyncExecutor + 'static> {
    outgoing_tx: Arc<ChannelSender<DynamicByteBuffer>>,
    incoming_rx: Arc<Mutex<ChannelReceiver<DynamicByteBuffer>>>,
    settings: Arc<Settings<AE>>,
    _phantom: PhantomData<T>,
}

impl<T: IdentityType + Clone + Eq + Hash + Send + ToString, AE: AsyncExecutor> ClientHandle<T, AE> {
    /// Send a packet using a pre-allocated buffer.
    pub async fn send(&self, packet: DynamicByteBuffer) -> Result<(), ServerSocketError> {
        if self.outgoing_tx.send(packet).await {
            Ok(())
        } else {
            Err(ServerSocketError::ChannelClosed)
        }
    }

    /// Send a byte slice, allocating a buffer from the pool.
    pub async fn send_bytes(&self, data: &[u8]) -> Result<(), ServerSocketError> {
        let buffer = self.settings.pool().allocate_precise_from_slice_with_capacity(data, 0, 0);
        self.send(buffer).await
    }

    /// Receive a packet, returning the decrypted payload as a buffer.
    pub async fn receive(&self) -> Result<DynamicByteBuffer, ServerSocketError> {
        self.incoming_rx.lock().await.recv().await.ok_or(ServerSocketError::ChannelClosed)
    }

    /// Receive a packet, returning the decrypted payload as a byte vector.
    pub async fn receive_bytes(&self) -> Result<Vec<u8>, ServerSocketError> {
        let buffer = self.receive().await?;
        Ok(buffer.slice().to_vec())
    }
}
