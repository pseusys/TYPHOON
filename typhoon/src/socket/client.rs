use std::marker::PhantomData;
use std::net::SocketAddr;
use std::sync::Arc;
use std::vec;

use crate::bytes::{ByteBuffer, DynamicByteBuffer};
use crate::cache::SharedValue;
use crate::crypto::{Certificate, ClientCryptoTool, KEY_LENGTH};
use crate::flow::FlowConfig;
use crate::flow::client::ClientFlowManager;
use crate::flow::decoy::DecoyCommunicationMode;
use crate::session::{ClientSessionManager, SessionManager};
use crate::settings::Settings;
use crate::socket::error::ClientSocketError;
use crate::tailor::IdentityType;
use crate::utils::random::{SupportRng, get_rng};
use crate::utils::socket::Socket;
use crate::utils::sync::AsyncExecutor;

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
pub struct ClientSocketBuilder<T: IdentityType + Clone, AE: AsyncExecutor + 'static, DP> {
    settings: Option<Arc<Settings<AE>>>,
    flow_configs: Vec<FlowManagerConfiguration>,
    certificate: Certificate,
    _phantom: PhantomData<(T, DP)>,
}

impl<T: IdentityType + Clone + 'static, AE: AsyncExecutor + 'static, DP: DecoyCommunicationMode<AE, ClientFlowManager<T, AE, DP>> + 'static> ClientSocketBuilder<T, AE, DP> {
    /// Create a new builder with the given cipher and settings.
    pub fn new(certificate: Certificate) -> Self {
        Self {
            settings: None,
            flow_configs: Vec::new(),
            certificate,
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

    /// Read package version into a fixed-size byte array for use in the protocol.
    fn get_version_bytes() -> Vec<u8> {
        let version = env!("CARGO_PKG_VERSION").as_bytes();
        let mut version_vec = vec![0u8; T::length()];
        let version_slice = version_vec.as_mut_slice();
        version_slice[T::length() - version.len()..].copy_from_slice(version);
        version_vec
    }

    /// Build the client socket, validating all flow configs and creating underlying managers.
    pub async fn build(mut self) -> Result<ClientSocket<T, AE, DP>, ClientSocketError> {
        if self.flow_configs.is_empty() {
            return Err(ClientSocketError::NoFlows);
        }

        let settings = self.settings.take().unwrap_or_else(|| Arc::new(Settings::default()));
        let mut flows = Vec::with_capacity(self.flow_configs.len());

        let identity_bytes = T::from_bytes(Self::get_version_bytes().as_slice());
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

        let session = ClientSessionManager::new(cipher, flows, settings.clone()).await.map_err(ClientSocketError::SessionError)?;

        Ok(ClientSocket {
            session,
            settings,
        })
    }
}

/// Client-side TYPHOON socket providing send/receive operations.
pub struct ClientSocket<T: IdentityType + Clone + 'static, AE: AsyncExecutor + 'static, DP: DecoyCommunicationMode<AE, ClientFlowManager<T, AE, DP>> + Send + Sync + 'static> {
    session: Arc<ClientSessionManager<T, AE, Arc<ClientFlowManager<T, AE, DP>>>>,
    settings: Arc<Settings<AE>>,
}

impl<T: IdentityType + Clone + 'static, AE: AsyncExecutor + 'static, DP: DecoyCommunicationMode<AE, ClientFlowManager<T, AE, DP>> + 'static> ClientSocket<T, AE, DP> {
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
        self.session.receive_packet().await.map_err(ClientSocketError::SessionError)
    }

    /// Receive a packet, returning the decrypted payload as a byte vector.
    pub async fn receive_bytes(&self) -> Result<Vec<u8>, ClientSocketError> {
        let buffer = self.receive().await?;
        Ok(buffer.slice().to_vec())
    }
}
