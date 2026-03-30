use std::marker::PhantomData;
use std::net::SocketAddr;
use std::sync::Arc;

use log::debug;

use crate::bytes::{ByteBuffer, DynamicByteBuffer};
use crate::cache::SharedValue;
use crate::crypto::{Certificate, ClientCryptoTool, KEY_LENGTH};
use crate::flow::FlowConfig;
use crate::flow::client::ClientFlowManager;
use crate::flow::decoy::DecoyCommunicationMode;
use crate::session::{ClientSessionManager, SessionManager};
use crate::settings::{Settings, keys};
use crate::socket::error::ClientSocketError;
use crate::tailor::{ClientConnectionHandler, IdentityType};
use crate::utils::random::{SupportRng, get_rng};
use crate::utils::socket::Socket;
use crate::utils::sync::{AsyncExecutor, ChannelReceiver, Mutex, create_channel};

/// Configuration for a single flow manager.
pub struct FlowManagerConfiguration {
    socket: Option<Socket>,
    address: Option<SocketAddr>,
    config: FlowConfig,
}

impl FlowManagerConfiguration {
    /// Create a configuration with a pre-built socket.
    pub fn new(config: FlowConfig, socket: Socket) -> Self {
        Self {
            socket: Some(socket),
            address: None,
            config,
        }
    }

    /// Create a configuration that will create a socket from the given address.
    pub fn with_address(config: FlowConfig, address: SocketAddr) -> Self {
        Self {
            socket: None,
            address: Some(address),
            config,
        }
    }
}

/// Builder for constructing a `ClientSocket`.
pub struct ClientSocketBuilder<T: IdentityType + Clone, AE: AsyncExecutor + 'static, DP, CC: ClientConnectionHandler> {
    settings: Option<Arc<Settings<AE>>>,
    flow_configs: Vec<FlowManagerConfiguration>,
    certificate: Certificate,
    initial_data_generator: CC,
    _phantom: PhantomData<(T, DP)>,
}

impl<T: IdentityType + Clone + 'static, AE: AsyncExecutor + 'static, DP: DecoyCommunicationMode<T, AE, ClientFlowManager<T, AE, DP>> + 'static, CC: ClientConnectionHandler + 'static> ClientSocketBuilder<T, AE, DP, CC> {
    /// Create a new builder with the given certificate and client connection handler.
    pub fn new(certificate: Certificate, initial_data_generator: CC) -> Self {
        Self {
            settings: None,
            flow_configs: Vec::new(),
            certificate,
            initial_data_generator,
            _phantom: PhantomData,
        }
    }

    /// Set custom settings to use for the socket.
    pub fn with_settings(mut self, settings: Arc<Settings<AE>>) -> Self {
        self.settings = Some(settings);
        self
    }

    /// Append a single flow manager configuration.
    pub fn add_flow(mut self, config: FlowManagerConfiguration) -> Self {
        self.flow_configs.push(config);
        self
    }

    /// Set all flow manager configurations at once.
    pub fn with_flows(mut self, configs: Vec<FlowManagerConfiguration>) -> Self {
        self.flow_configs = configs;
        self
    }

    /// Build the client socket, validating all flow configs and creating underlying managers.
    pub async fn build(mut self) -> Result<ClientSocket<T, AE, DP, CC>, ClientSocketError> {
        if self.flow_configs.is_empty() {
            return Err(ClientSocketError::NoFlows);
        }

        let settings = self.settings.take().unwrap_or_else(|| Arc::new(Settings::default()));
        let mut flows = Vec::with_capacity(self.flow_configs.len());

        let identity_bytes = T::from_bytes(&self.initial_data_generator.version(T::length()));
        let static_key = get_rng().random_byte_buffer::<KEY_LENGTH>();
        let cipher = SharedValue::new(ClientCryptoTool::new(self.certificate, identity_bytes, &static_key));

        for flow_config in self.flow_configs.drain(..) {
            flow_config.config.assert(settings.mtu()).map_err(ClientSocketError::FlowError)?;

            let sock = match flow_config.socket {
                Some(socket) => socket,
                None => {
                    let address = flow_config.address.expect("FlowManagerConfiguration must have either socket or address");
                    Socket::new(address, None).await.map_err(ClientSocketError::SocketError)?
                }
            };

            let cipher_cache = cipher.create_cache().await;
            let flow = ClientFlowManager::new(flow_config.config, cipher_cache, settings.clone(), sock).await.map_err(ClientSocketError::FlowError)?;
            flows.push(flow);
        }

        let session = ClientSessionManager::new(cipher, flows, settings.clone(), self.initial_data_generator).await.map_err(ClientSocketError::SessionError)?;

        let buffer_size = settings.get(&keys::RECEIVE_BUFFER_SIZE) as usize;
        let (data_tx, data_rx) = create_channel(buffer_size);

        // Spawn the background receive loop BEFORE the handshake so that
        // handshake responses from the server can be received and routed.
        let receive_session = session.clone();
        settings.executor().spawn(async move {
            loop {
                match receive_session.receive_packet().await {
                    Ok(buffer) => {
                        if !data_tx.send(buffer).await {
                            break;
                        }
                    }
                    Err(err) => {
                        debug!("background receive loop terminated: {}", err);
                        break;
                    }
                }
            }
        });

        // Now perform the handshake and start the health check timer.
        session.start().await.map_err(ClientSocketError::SessionError)?;

        Ok(ClientSocket {
            session,
            receiver: Mutex::new(data_rx),
            settings,
        })
    }
}

/// Client-side TYPHOON socket providing send/receive operations.
pub struct ClientSocket<T: IdentityType + Clone + 'static, AE: AsyncExecutor + 'static, DP: DecoyCommunicationMode<T, AE, ClientFlowManager<T, AE, DP>> + Send + Sync + 'static, CC: ClientConnectionHandler + 'static> {
    session: Arc<ClientSessionManager<T, AE, Arc<ClientFlowManager<T, AE, DP>>, CC>>,
    receiver: Mutex<ChannelReceiver<DynamicByteBuffer>>,
    settings: Arc<Settings<AE>>,
}

impl<T: IdentityType + Clone + 'static, AE: AsyncExecutor + 'static, DP: DecoyCommunicationMode<T, AE, ClientFlowManager<T, AE, DP>> + 'static, CC: ClientConnectionHandler + 'static> ClientSocket<T, AE, DP, CC> {
    /// Send a packet using a pre-allocated buffer.
    pub async fn send(&self, packet: DynamicByteBuffer) -> Result<(), ClientSocketError> {
        self.session.send_packet(packet, false).await.map_err(ClientSocketError::SessionError)
    }

    /// Send a byte slice, allocating a buffer from the pool.
    pub async fn send_bytes(&self, data: &[u8]) -> Result<(), ClientSocketError> {
        let buffer = self.settings.pool().allocate_precise_from_slice_with_capacity(data, 0, 0);
        self.send(buffer).await
    }

    /// Receive a packet, returning the decrypted payload as a buffer.
    pub async fn receive(&self) -> Result<DynamicByteBuffer, ClientSocketError> {
        self.receiver.lock().await.recv().await.ok_or(ClientSocketError::ChannelClosed)
    }

    /// Receive a packet, returning the decrypted payload as a byte vector.
    pub async fn receive_bytes(&self) -> Result<Vec<u8>, ClientSocketError> {
        let buffer = self.receive().await?;
        Ok(buffer.slice().to_vec())
    }
}
