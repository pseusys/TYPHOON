use std::collections::HashMap;
use std::future::Future;
use std::hash::Hash;
use std::net::SocketAddr;
use std::sync::{Arc, Weak};

use async_trait::async_trait;
use log::{debug, info, warn};

use crate::bytes::{ByteBuffer, DynamicByteBuffer};
use crate::cache::SharedMap;
use crate::capture::record_recv_error;
#[cfg(any(feature = "fast_software", feature = "fast_hardware"))]
use crate::certificate::ObfuscationBufferContainer;
use crate::certificate::{ServerKeyPair, ServerSecret};
use crate::crypto::{PAYLOAD_CRYPTO_OVERHEAD, ServerCryptoTool, UserCryptoState, UserServerState, verify_transcript_with_key};
use crate::flow::FlowConfig;
use crate::flow::decoy::{DecoyCommunicationMode, DecoyFactory, decoy_factory, random_decoy_factory};
use crate::flow::probe::{ActiveProbeHandler, ProbeFactory, probe_factory};
use crate::flow::server::{RawReceivedPacket, ServerFlowManager};
use crate::session::SessionControllerError;
use crate::session::server::{IncomingPacket, OutgoingRouter, ServerSessionManager};
use crate::settings::{Settings, keys};
use crate::socket::client_handle::ClientHandle;
use crate::socket::error::ServerSocketError;
use crate::socket::pool::ClientPool;
use crate::trailer::{IdentityType, PacketFlags, ReturnCode, ServerConnectionHandler, Trailer};
use crate::utils::socket::Socket;
use crate::utils::sync::{AsyncExecutor, Mutex, NotifyQueueReceiver, NotifyQueueSender, RwLock, assert_runtime, create_bounded_notify_queue, create_notify_queue, create_watch};
use crate::utils::unix_timestamp_ms;

/// Configuration for a single server flow manager.
pub struct ServerFlowConfiguration<T: IdentityType + Clone, AE: AsyncExecutor> {
    socket: Option<Socket>,
    address: Option<SocketAddr>,
    config: FlowConfig,
    /// Number of `SO_REUSEPORT` reader sockets to create (Linux only; default 1).
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

    /// Set the number of `SO_REUSEPORT` reader sockets (Linux only).
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
    pub fn with_decoy<DP: DecoyCommunicationMode<T, AE> + 'static>(mut self) -> Self {
        self.decoy_factory = Some(decoy_factory::<T, AE, DP>());
        self
    }

    /// Override the active probe handler factory for this flow.
    pub fn with_probe_factory(mut self, factory: ProbeFactory<AE>) -> Self {
        self.probe_factory = Some(factory);
        self
    }

    /// Override the active probe handler type for this flow.
    pub fn with_probe<PM: ActiveProbeHandler<AE> + Default + 'static>(mut self) -> Self {
        self.probe_factory = Some(probe_factory::<AE, PM>());
        self
    }
}

/// Builder for constructing a server-side entrypoint: either a `Listener` (via `build_listener`) or a `ClientPool` (via `build_pool`).
pub struct ServerBuilder<T: IdentityType + Clone + Eq + Hash + Send + ToString + 'static, AE: AsyncExecutor + 'static, IG: ServerConnectionHandler<T>> {
    settings: Option<Arc<Settings<AE>>>,
    flow_configs: Vec<ServerFlowConfiguration<T, AE>>,
    secret: ServerSecret<'static>,
    identity_generator: IG,
    default_decoy_factory: DecoyFactory<T, AE>,
    default_probe_factory: Option<ProbeFactory<AE>>,
}

impl<T: IdentityType + Clone + Eq + Hash + Send + ToString + 'static, AE: AsyncExecutor + 'static, IG: ServerConnectionHandler<T> + 'static> ServerBuilder<T, AE, IG> {
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
    pub fn with_decoy<DP: DecoyCommunicationMode<T, AE> + 'static>(mut self) -> Self {
        self.default_decoy_factory = decoy_factory::<T, AE, DP>();
        self
    }

    /// Set the default active probe handler factory for flows that have no per-flow override.
    pub fn with_probe_factory(mut self, factory: ProbeFactory<AE>) -> Self {
        self.default_probe_factory = Some(factory);
        self
    }

    /// Set the default active probe handler type for flows without a per-flow override.
    pub fn with_probe<PM: ActiveProbeHandler<AE> + Default + 'static>(mut self) -> Self {
        self.default_probe_factory = Some(probe_factory::<AE, PM>());
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
    ///
    /// # Errors
    ///
    /// Returns [`ServerSocketError::NoFlows`] if no flow configuration was added,
    /// [`ServerSocketError::UnsupportedRuntime`] if the active async runtime feature doesn't
    /// match the executor in use, [`ServerSocketError::Flow`] if a flow configuration is
    /// inconsistent with the MTU, or [`ServerSocketError::Socket`] if a socket fails to bind.
    ///
    /// # Panics
    ///
    /// Never in practice: every [`ServerFlowConfiguration`] is constructed with either a socket
    /// or an address set, so the internal `expect` can't fire.
    #[cfg(any(feature = "fast_software", feature = "fast_hardware"))]
    pub async fn build_listener(mut self) -> Result<Listener<T, AE, IG>, ServerSocketError> {
        assert_runtime().map_err(ServerSocketError::UnsupportedRuntime)?;
        if self.flow_configs.is_empty() {
            return Err(ServerSocketError::NoFlows);
        }

        let settings = self.settings.take().unwrap_or_else(|| Arc::new(Settings::default()));
        let users: SharedMap<T, UserServerState> = SharedMap::new();
        let mut flows = Vec::with_capacity(self.flow_configs.len());

        let trailer_wire_len = Trailer::<T>::encrypted_len_s2c();
        let mut max_data_payload = usize::MAX;

        let obfs_buffer = self.secret.obfuscation_buffer();

        for flow_config in self.flow_configs.drain(..) {
            flow_config.config.assert(settings.mtu()).map_err(ServerSocketError::Flow)?;

            max_data_payload = max_data_payload.min(flow_config.config.max_user_payload(settings.mtu(), PAYLOAD_CRYPTO_OVERHEAD, trailer_wire_len));

            let socks: Vec<Arc<Socket>> = if let Some(socket) = flow_config.socket {
                vec![Arc::new(socket)]
            } else {
                let address = flow_config.address.expect("ServerFlowConfiguration must have either socket or address");
                cfg_if::cfg_if! {
                    if #[cfg(target_os = "linux")] {
                        if flow_config.reader_count > 1 {
                            Socket::bind_reuse_port(address, flow_config.reader_count)
                                .map_err(ServerSocketError::Socket)?
                                .into_iter().map(Arc::new).collect()
                        } else {
                            vec![Arc::new(Socket::bind(address).await.map_err(ServerSocketError::Socket)?)]
                        }
                    } else {
                        vec![Arc::new(Socket::bind(address).await.map_err(ServerSocketError::Socket)?)]
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

        let (accept_tx, accept_rx) = create_notify_queue::<ClientHandle<T, AE>>();

        let router = Arc::new(Router {
            flows,
            sessions: RwLock::new(HashMap::new()),
            users: Mutex::new(users),
            connection_handler: self.identity_generator,
        });

        Ok(Listener {
            router,
            secret: self.secret,
            accept_tx,
            accept_rx: Mutex::new(accept_rx),
            max_data_payload,
            settings,
        })
    }

    /// Build the listener, creating all flow managers (full mode).
    ///
    /// # Errors
    ///
    /// Returns [`ServerSocketError::NoFlows`] if no flow configuration was added,
    /// [`ServerSocketError::UnsupportedRuntime`] if the active async runtime feature doesn't
    /// match the executor in use, [`ServerSocketError::Flow`] if a flow configuration is
    /// inconsistent with the MTU, or [`ServerSocketError::Socket`] if a socket fails to bind.
    ///
    /// # Panics
    ///
    /// Never in practice: every [`ServerFlowConfiguration`] is constructed with either a socket
    /// or an address set, so the internal `expect` can't fire.
    #[cfg(any(feature = "full_software", feature = "full_hardware"))]
    pub async fn build_listener(mut self) -> Result<Listener<T, AE, IG>, ServerSocketError> {
        assert_runtime().map_err(ServerSocketError::UnsupportedRuntime)?;
        if self.flow_configs.is_empty() {
            return Err(ServerSocketError::NoFlows);
        }

        let settings = self.settings.take().unwrap_or_else(|| Arc::new(Settings::default()));
        let users: SharedMap<T, UserServerState> = SharedMap::new();
        let mut flows = Vec::with_capacity(self.flow_configs.len());

        let trailer_wire_len = Trailer::<T>::encrypted_len_s2c();
        let mut max_data_payload = usize::MAX;

        let secret_arc = Arc::new(self.secret);

        for flow_config in self.flow_configs.drain(..) {
            flow_config.config.assert(settings.mtu()).map_err(ServerSocketError::Flow)?;

            max_data_payload = max_data_payload.min(flow_config.config.max_user_payload(settings.mtu(), PAYLOAD_CRYPTO_OVERHEAD, trailer_wire_len));

            let socks: Vec<Arc<Socket>> = if let Some(socket) = flow_config.socket {
                vec![Arc::new(socket)]
            } else {
                let address = flow_config.address.expect("ServerFlowConfiguration must have either socket or address");
                cfg_if::cfg_if! {
                    if #[cfg(target_os = "linux")] {
                        if flow_config.reader_count > 1 {
                            Socket::bind_reuse_port(address, flow_config.reader_count)
                                .map_err(ServerSocketError::Socket)?
                                .into_iter().map(Arc::new).collect()
                        } else {
                            vec![Arc::new(Socket::bind(address).await.map_err(ServerSocketError::Socket)?)]
                        }
                    } else {
                        vec![Arc::new(Socket::bind(address).await.map_err(ServerSocketError::Socket)?)]
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

        let (accept_tx, accept_rx) = create_notify_queue::<ClientHandle<T, AE>>();

        let router = Arc::new(Router {
            flows,
            sessions: RwLock::new(HashMap::new()),
            users: Mutex::new(users),
            connection_handler: self.identity_generator,
        });

        Ok(Listener {
            router,
            secret: secret_arc,
            accept_tx,
            accept_rx: Mutex::new(accept_rx),
            max_data_payload,
            settings,
        })
    }

    /// Build a `ClientPool`, the multiplexed server entrypoint: same flow construction as `build_listener`, wrapped so all `ClientHandle`s are owned and dispatched by identity.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::build_listener`].
    pub async fn build_pool(self) -> Result<ClientPool<T, AE, IG>, ServerSocketError> {
        Ok(ClientPool::new(self.build_listener().await?))
    }
}

/// Routing and session-lifecycle surface, shared by the `Listener` and every `ClientHandle` it produces.
/// Owns the `ServerConnectionHandler` plug-in so `remove_session` can notify it from one place, regardless of whether `Listener` or `ClientPool` is the entrypoint in use.
pub(crate) struct Router<T: IdentityType + Clone + Eq + Hash + Send + ToString + 'static, AE: AsyncExecutor + 'static, IG: ServerConnectionHandler<T> + 'static> {
    flows: Vec<Arc<ServerFlowManager<T, AE>>>,
    sessions: RwLock<HashMap<T, Arc<ServerSessionManager<T, AE>>>>,
    users: Mutex<SharedMap<T, UserServerState>>,
    connection_handler: IG,
}

impl<T: IdentityType + Clone + Eq + Hash + Send + ToString + 'static, AE: AsyncExecutor + 'static, IG: ServerConnectionHandler<T> + 'static> Router<T, AE, IG> {
    /// Number of flow managers the router routes through.
    #[inline]
    pub(crate) fn flow_count(&self) -> usize {
        self.flows.len()
    }
}

/// Server-side listener that drives the handshake path and produces `ClientHandle`s.
/// All routing and session lifecycle state lives in the shared `Router`.
pub struct Listener<T: IdentityType + Clone + Eq + Hash + Send + ToString + 'static, AE: AsyncExecutor + 'static, IG: ServerConnectionHandler<T> + 'static> {
    router: Arc<Router<T, AE, IG>>,
    #[cfg(any(feature = "fast_software", feature = "fast_hardware"))]
    secret: ServerSecret<'static>,
    #[cfg(any(feature = "full_software", feature = "full_hardware"))]
    secret: Arc<ServerSecret<'static>>,
    accept_tx: NotifyQueueSender<ClientHandle<T, AE>>,
    accept_rx: Mutex<NotifyQueueReceiver<ClientHandle<T, AE>>>,
    /// Maximum user-data bytes per packet so the wire packet fits within MTU.
    max_data_payload: usize,
    settings: Arc<Settings<AE>>,
}

impl<T: IdentityType + Clone + Eq + Hash + Send + ToString + 'static, AE: AsyncExecutor + 'static, IG: ServerConnectionHandler<T> + 'static> Listener<T, AE, IG> {
    /// Settings shared by this listener's flow managers and sessions.
    #[inline]
    pub(crate) fn settings(&self) -> &Arc<Settings<AE>> {
        &self.settings
    }

    /// Create initial user crypto state from a handshake key (fast mode).
    #[cfg(any(feature = "fast_software", feature = "fast_hardware"))]
    #[inline]
    fn make_initial_crypto_state(&self, initial_key: &impl ByteBuffer) -> UserCryptoState {
        UserCryptoState::new(initial_key, self.secret.obfuscation_buffer())
    }

    /// Create initial user crypto state from a handshake key (full mode).
    #[cfg(any(feature = "full_software", feature = "full_hardware"))]
    #[inline]
    #[allow(clippy::unused_self)] // keeps the same call-site shape as the fast-mode variant
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
    #[allow(clippy::unused_self)] // keeps the same call-site shape as the fast-mode variant
    fn upgrade_user_crypto(&self, user_state: &mut UserServerState, session_key: &impl ByteBuffer) {
        user_state.upgrade_crypto(session_key);
    }

    /// Start the listener's background receive loops.
    /// Must be called after `build()` to begin processing incoming packets.
    ///
    /// Each flow gets N+1 tasks (where N = number of `SO_REUSEPORT` sockets, normally 1):
    /// - N **drain tasks**, one per socket, each calling `receive_raw` and immediately pushing
    ///   raw packets into a shared bounded channel. If the route task is slow and the channel is
    ///   full the packet is dropped, keeping the OS socket buffer empty at all times.
    ///   When all N drain tasks exit the `Arc<BoundedNotifyQueueSender>` refcount reaches 0,
    ///   dropping the sender and closing the channel so the route task terminates.
    /// - A **route task** that pulls from the shared channel and calls `route_incoming`.
    pub fn start(self: &Arc<Self>) -> impl Future<Output = ()> {
        let drain_capacity = self.settings.get(&keys::DRAIN_CHANNEL_CAPACITY) as usize;

        for (index, flow) in self.router.flows.iter().enumerate() {
            let (drain_tx, mut drain_rx) = create_bounded_notify_queue(drain_capacity, Some("drain"));
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
                                record_recv_error();
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

        async {}
    }

    /// Route an incoming packet to the appropriate session or create a new one.
    async fn route_incoming(self: &Arc<Self>, raw_packet: RawReceivedPacket<T>, flow_index: usize) {
        let identity = raw_packet.trailer.identity();

        if raw_packet.trailer.flags().contains(PacketFlags::HANDSHAKE) {
            self.handle_new_client(raw_packet, flow_index).await;
            return;
        }

        let session = {
            let sessions = self.router.sessions.read().await;
            sessions.get(&identity).cloned()
        };

        if let Some(session) = session {
            self.router.flows[flow_index].ensure_user(identity.clone(), session.counter()).await;
            session.note_active_flow(flow_index);

            let incoming = IncomingPacket {
                body: raw_packet.body,
                trailer: raw_packet.trailer,
            };
            if let Err(err) = session.process_incoming(incoming).await {
                debug!("session processing error for {}: {}", identity.to_string(), err);
                if matches!(err, SessionControllerError::ConnectionTerminated(_)) {
                    self.router.remove_session(&identity, session.handshake_pn()).await;
                }
            }
        } else {
            debug!("packet from unknown identity {}, dropping", identity.to_string());
        }
    }

    /// Reject a handshake before a real identity exists (version mismatch or `generate` returning `None`), addressing the TERMINATION response with the client's version-string bytes as a transient bookkeeping key so it can still be encrypted with the just-derived initial key.
    async fn reject_handshake(self: &Arc<Self>, flow_index: usize, transient_identity: &T, source_addr: SocketAddr, handshake_pn: u64, initial_key: &impl ByteBuffer, code: ReturnCode) {
        {
            let mut users = self.router.users.lock().await;
            let crypto_state = self.make_initial_crypto_state(initial_key);
            users.insert(transient_identity.clone(), UserServerState::new(crypto_state)).await;
        }
        self.router.flows[flow_index].register_user_binding(transient_identity.clone(), source_addr, handshake_pn).await;
        let pn = (unix_timestamp_ms() / 1000) as u64;
        let buf = self.settings.pool().allocate(Some(T::length()));
        let trailer = Trailer::termination(buf, transient_identity, code, pn);
        if let Err(err) = self.router.flows[flow_index].send_packet(trailer.into_buffer(), false, false).await {
            warn!("failed to send handshake rejection ({code:?}): {err}");
        }
        {
            let mut users = self.router.users.lock().await;
            users.remove(transient_identity).await;
        }
        self.router.flows[flow_index].remove_user(transient_identity).await;
    }

    /// Handle a handshake from a new client: create session, send response, publish `ClientHandle`.
    async fn handle_new_client(self: &Arc<Self>, mut raw_packet: RawReceivedPacket<T>, flow_index: usize) {
        let handshake_transcript = raw_packet.handshake_transcript.take();
        let original_wire_packet = raw_packet.original_wire_packet.take();
        let source_addr = raw_packet.source_addr;
        let Some((server_data, initial_key, client_initial_data)) = self.secret.decapsulate_handshake_server(raw_packet.body, self.settings.pool()) else {
            if let Some(packet) = original_wire_packet {
                debug!("handshake decapsulation failed from {source_addr} (body too short for crypto header), forwarding to probe handler");
                self.router.flows[flow_index].forward_to_probe(packet, source_addr).await;
            } else {
                debug!("handshake decapsulation failed from {source_addr} and original wire packet unavailable, dropping");
            }
            return;
        };

        // Verify the handshake trailer with the initial-data encryption key just produced by the KEM decapsulation.
        let verified = matches!((&handshake_transcript, &original_wire_packet), (Some(transcript), Some(_)) if verify_transcript_with_key(&initial_key, transcript).is_ok());
        if !verified {
            if let Some(packet) = original_wire_packet {
                debug!("handshake trailer verification failed from {source_addr}, forwarding to probe handler");
                self.router.flows[flow_index].forward_to_probe(packet, source_addr).await;
            } else {
                debug!("handshake packet from {source_addr} missing deferred transcript or wire packet, dropping");
            }
            return;
        }

        let client_version_identity = raw_packet.trailer.identity();
        let handshake_pn = raw_packet.trailer.packet_number();
        if !self.router.connection_handler.verify_version(client_version_identity.to_bytes()) {
            self.reject_handshake(flow_index, &client_version_identity, raw_packet.source_addr, handshake_pn, &initial_key, ReturnCode::VersionMismatch).await;
            return;
        }

        let Some(identity) = self.router.connection_handler.generate(client_initial_data.slice()) else {
            debug!("identity generation rejected handshake from {source_addr}");
            self.reject_handshake(flow_index, &client_version_identity, raw_packet.source_addr, handshake_pn, &initial_key, ReturnCode::IdentityRejected).await;
            return;
        };

        // Reject stale or replayed handshakes before doing any further crypto work.
        let existing_handshake_pn = self.router.sessions.read().await.get(&identity).map(|s| s.handshake_pn());
        if let Some(existing_pn) = existing_handshake_pn
            && handshake_pn <= existing_pn
        {
            debug!("stale or replayed handshake for {} rejected: pn {handshake_pn:#018x} <= current {existing_pn:#018x}", identity.to_string());
            if let Some(packet) = original_wire_packet {
                self.router.flows[flow_index].forward_to_probe(packet, source_addr).await;
            }
            return;
        }

        let server_initial_data = self.router.connection_handler.initial_data(&identity);

        let (incoming_tx, incoming_rx) = create_notify_queue::<DynamicByteBuffer>();
        let (end_tx, end_rx) = create_watch::<()>();
        let router_weak: Weak<dyn OutgoingRouter<T>> = Arc::downgrade(&self.router) as Weak<dyn OutgoingRouter<T>>;

        let (response_body, session_key) = self.secret.encapsulate_handshake_server(server_data, self.settings.pool(), server_initial_data.slice(), &initial_key);

        let (session, response_packet, replacing) = {
            let mut users = self.router.users.lock().await;
            let replacing = users.contains_key(&identity);
            if replacing {
                debug!("re-handshake for {}: replacing existing session (last wins)", identity.to_string());
                users.remove(&identity).await;
            }
            let initial_crypto_state = self.make_initial_crypto_state(&initial_key);
            let (session, response_packet) = ServerSessionManager::assemble_session(initial_crypto_state, response_body, raw_packet.trailer, identity.clone(), &mut users, incoming_tx, end_tx, router_weak, self.router.flow_count(), self.settings.clone()).await;
            (session, response_packet, replacing)
        };

        if replacing {
            // Wake the displaced ClientHandle's receive() so it stops waiting.
            // on_connect(identity, existing=true) reports the reconnect once the new connection is confirmed below.
            let old = self.router.sessions.write().await.remove(&identity);
            if let Some(old) = old {
                old.signal_end();
            }
            for flow in &self.router.flows {
                flow.remove_user(&identity).await;
            }
        }

        self.router.flows[flow_index].register_user_binding(identity.clone(), raw_packet.source_addr, handshake_pn).await;
        self.router.flows[flow_index].register_user(identity.clone(), session.counter()).await;

        if let Err(err) = self.router.flows[flow_index].send_packet(response_packet, false, false).await {
            warn!("failed to send handshake response: {err}");
            self.router.users.lock().await.remove(&identity).await;
            for flow in &self.router.flows {
                flow.remove_user(&identity).await;
            }
            return;
        }

        {
            let mut users = self.router.users.lock().await;
            users
                .modify(&identity, |user_state| {
                    self.upgrade_user_crypto(user_state, &session_key);
                })
                .await;
        }

        session.note_active_flow(flow_index);

        {
            let mut sessions = self.router.sessions.write().await;
            if sessions.contains_key(&identity) {
                debug!("concurrent handshake for {}: last wins, displacing earlier session", identity.to_string());
            }
            sessions.insert(identity.clone(), Arc::clone(&session));
        }

        let client_handle = ClientHandle {
            session,
            identity: identity.clone(),
            incoming_rx: Mutex::new(incoming_rx),
            end_rx: Mutex::new(end_rx),
            max_data_payload: self.max_data_payload,
            settings: self.settings.clone(),
            router: Arc::clone(&self.router) as Arc<dyn OutgoingRouter<T>>,
        };
        self.accept_tx.push(client_handle);
        self.router.connection_handler.on_connect(&identity, replacing);

        if replacing {
            info!("client reconnected: {}", identity.to_string());
        } else {
            info!("new client connected: {}", identity.to_string());
        }
    }

    /// Wait for the next client connection and return a handle to it.
    ///
    /// # Errors
    ///
    /// Returns [`ServerSocketError::ListenerStopped`] if the listener has been stopped.
    pub async fn accept(&self) -> Result<ClientHandle<T, AE>, ServerSocketError> {
        self.accept_rx.lock().await.recv().await.ok_or(ServerSocketError::ListenerStopped)
    }
}

/// `OutgoingRouter` implementation: selects an active flow via the per-session bitmask and sends the packet.
#[async_trait]
impl<T: IdentityType + Clone + Eq + Hash + Send + Sync + ToString + 'static, AE: AsyncExecutor + 'static, IG: ServerConnectionHandler<T> + 'static> OutgoingRouter<T> for Router<T, AE, IG> {
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
            self.flows[flow_idx].send_packet(packet, false, false).await.is_ok()
        } else {
            false
        }
    }

    async fn is_current_session(&self, identity: &T, handshake_pn: u64) -> bool {
        self.sessions.read().await.get(identity).is_some_and(|s| s.handshake_pn() == handshake_pn)
    }

    async fn remove_session(&self, identity: &T, handshake_pn: u64) -> bool {
        let removed = {
            let mut sessions = self.sessions.write().await;
            match sessions.get(identity) {
                Some(s) if s.handshake_pn() == handshake_pn => sessions.remove(identity),
                _ => return false,
            }
        };
        self.users.lock().await.remove(identity).await;
        for flow in &self.flows {
            flow.remove_user(identity).await;
        }
        if let Some(session) = removed {
            session.signal_end();
        }
        self.connection_handler.on_disconnect(identity);
        info!("client session removed: {}", identity.to_string());
        true
    }
}
