use std::collections::HashMap;
use std::marker::PhantomData;
use std::net::SocketAddr;
use std::sync::Arc;

use log::{debug, info};
use rand::Rng;
use rand::seq::SliceRandom;

use crate::bytes::{ByteBuffer, ByteBufferMut, DynamicByteBuffer};
use crate::cache::SharedValue;
use crate::certificate::{CertificateError, ClientCertificate};
use crate::crypto::{ClientCryptoTool, KEY_LENGTH};
use crate::crypto::PAYLOAD_CRYPTO_OVERHEAD;
use crate::flow::{FlowConfig};
use crate::flow::client::ClientFlowManager;
use crate::flow::decoy::DecoyCommunicationMode;
use crate::session::{ClientSessionManager, SessionManager};
use crate::settings::Settings;
use crate::socket::error::ClientSocketError;
use crate::tailor::{ClientConnectionHandler, IdentityType};
use crate::utils::random::{SupportRng, get_rng};
use crate::utils::socket::Socket;
use crate::utils::sync::{AsyncExecutor, Mutex, NotifyQueueReceiver, create_notify_queue};

/// Builder for constructing a `ClientSocket`.
pub struct ClientSocketBuilder<T: IdentityType + Clone, AE: AsyncExecutor + 'static, DP, CC: ClientConnectionHandler> {
    settings: Option<Arc<Settings<AE>>>,
    /// Per-address flow config overrides. Only populated when the caller adds at least one
    /// explicit flow config via [`with_flow_config`](Self::with_flow_config).
    flow_overrides: HashMap<SocketAddr, FlowConfig>,
    /// When `true` (the default), a random subset of the certificate's addresses is chosen
    /// automatically and each gets a random [`FlowConfig`].  Set to `false` the first time
    /// [`with_flow_config`](Self::with_flow_config) is called, after which only the explicitly
    /// configured addresses are used.
    auto_fill_flows: bool,
    certificate: ClientCertificate,
    initial_data_generator: CC,
    _phantom: PhantomData<(T, DP)>,
}

impl<T: IdentityType + Clone + 'static, AE: AsyncExecutor + 'static, DP: DecoyCommunicationMode<T, AE> + 'static, CC: ClientConnectionHandler + 'static> ClientSocketBuilder<T, AE, DP, CC> {
    /// Create a new builder with the given certificate and client connection handler.
    ///
    /// The certificate must contain at least one server address; otherwise `build` will return
    /// [`CertificateError::NoAddresses`](crate::certificate::CertificateError::NoAddresses).
    ///
    /// By default, a random number of addresses (1 to the total in the certificate) is selected
    /// automatically, each with a random [`FlowConfig`].  Call
    /// [`with_flow_config`](Self::with_flow_config) one or more times to opt out of
    /// auto-selection and configure exactly which flows to open.
    pub fn new(certificate: ClientCertificate, initial_data_generator: CC) -> Self {
        Self {
            settings: None,
            flow_overrides: HashMap::new(),
            auto_fill_flows: true,
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

    /// Set an explicit [`FlowConfig`] for a specific server address.
    ///
    /// Calling this method at least once disables auto-flow-selection: only the addresses
    /// configured via this method will be connected.  The address must be present in the
    /// certificate; otherwise `build` will return
    /// [`ClientSocketError::AddressNotInCertificate`].
    pub fn with_flow_config(mut self, addr: SocketAddr, config: FlowConfig) -> Self {
        self.auto_fill_flows = false;
        self.flow_overrides.insert(addr, config);
        self
    }

    /// Build the client socket, validating all flow configs and creating underlying managers.
    pub async fn build(mut self) -> Result<ClientSocket<T, AE, DP, CC>, ClientSocketError> {
        let cert_addrs = self.certificate.addresses();
        if cert_addrs.is_empty() {
            return Err(ClientSocketError::CertificateError(CertificateError::NoAddresses));
        }

        let settings = self.settings.take().unwrap_or_else(|| Arc::new(Settings::default()));

        // Validate that all override addresses are in the certificate.
        for addr in self.flow_overrides.keys() {
            if !cert_addrs.contains(addr) {
                return Err(ClientSocketError::AddressNotInCertificate(*addr));
            }
        }

        // Determine which (address, config) pairs to connect to.
        // Auto-fill: pick a random number of addresses (1..=total) with random configs.
        // Manual: use exactly the addresses that were passed to with_flow_config.
        let addr_configs: Vec<(SocketAddr, FlowConfig)> = if self.auto_fill_flows {
            let mut rng = get_rng();
            let n = rng.gen_range(1..=cert_addrs.len());
            let chosen: Vec<SocketAddr> = cert_addrs.choose_multiple(&mut rng, n).copied().collect();
            chosen.into_iter().map(|addr| (addr, FlowConfig::random(&settings))).collect()
        } else {
            self.flow_overrides.drain().collect()
        };

        let identity_bytes = T::from_bytes(self.initial_data_generator.version(T::length()).slice());
        let static_key = get_rng().random_byte_buffer::<KEY_LENGTH>();
        let cipher = SharedValue::new(ClientCryptoTool::new(self.certificate.clone(), identity_bytes, &static_key));

        let tailor_wire_len = T::length() + ClientCryptoTool::<T>::tailor_overhead();
        let mut max_data_payload = usize::MAX;

        let mut flows = Vec::with_capacity(addr_configs.len());
        for (addr, config) in addr_configs {
            config.assert(settings.mtu()).map_err(ClientSocketError::FlowError)?;

            let flow_overhead = config.max_overhead()
                + PAYLOAD_CRYPTO_OVERHEAD
                + tailor_wire_len;
            max_data_payload = max_data_payload.min(settings.mtu().saturating_sub(flow_overhead));

            let sock = Socket::new(addr, None).await.map_err(ClientSocketError::SocketError)?;
            let cipher_cache = cipher.create_cache();
            let flow = ClientFlowManager::new(config, cipher_cache, settings.clone(), sock).await.map_err(ClientSocketError::FlowError)?;
            flows.push(flow);
        }
        let max_data_payload = if max_data_payload == usize::MAX { settings.mtu() } else { max_data_payload };
        info!("client socket built: max_data_payload={}B (mtu={}B, {} flow(s))", max_data_payload, settings.mtu(), flows.len());

        let session = ClientSessionManager::new(cipher, flows, settings.clone(), self.initial_data_generator).map_err(ClientSocketError::SessionError)?;

        let (incoming_tx, incoming_rx) = create_notify_queue::<DynamicByteBuffer>();

        // Spawn the background receive loop BEFORE the handshake so that
        // handshake responses from the server can be received and routed.
        let receive_session = session.clone();
        settings.executor().spawn(async move {
            loop {
                match receive_session.receive_packet().await {
                    Ok(buffer) => {
                        incoming_tx.push(buffer);
                    }
                    Err(err) => {
                        debug!("client bg-recv: terminated: {err}");
                        break;
                    }
                }
            }
            // incoming_tx dropped — receive() will see None and return ChannelClosed.
        });

        // Now perform the handshake and start the health check timer.
        session.start().await.map_err(ClientSocketError::SessionError)?;

        Ok(ClientSocket {
            session,
            incoming_rx: Mutex::new(incoming_rx),
            max_data_payload,
            settings,
        })
    }
}

/// Client-side TYPHOON socket providing send/receive operations.
pub struct ClientSocket<T: IdentityType + Clone + 'static, AE: AsyncExecutor + 'static, DP: DecoyCommunicationMode<T, AE> + Send + Sync + 'static, CC: ClientConnectionHandler + 'static> {
    session: Arc<ClientSessionManager<T, AE, Arc<ClientFlowManager<T, AE, DP>>, CC>>,
    incoming_rx: Mutex<NotifyQueueReceiver<DynamicByteBuffer>>,
    /// Maximum user-data bytes per packet so the wire packet fits within MTU.
    max_data_payload: usize,
    settings: Arc<Settings<AE>>,
}

impl<T: IdentityType + Clone + 'static, AE: AsyncExecutor + 'static, DP: DecoyCommunicationMode<T, AE> + 'static, CC: ClientConnectionHandler + 'static> ClientSocket<T, AE, DP, CC> {
    /// Send a packet using a pre-allocated buffer.
    pub async fn send(&self, packet: DynamicByteBuffer) -> Result<(), ClientSocketError> {
        self.session.send_packet(packet, false).await.map_err(ClientSocketError::SessionError)
    }

    /// Send a byte slice, splitting into payload-sized chunks so each wire packet fits within MTU.
    pub async fn send_bytes(&self, data: &[u8]) -> Result<(), ClientSocketError> {
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
    pub async fn receive(&self) -> Result<DynamicByteBuffer, ClientSocketError> {
        let buf = self.incoming_rx.lock().await.recv().await.ok_or(ClientSocketError::ChannelClosed)?;
        Ok(buf)
    }

    /// Receive a packet, returning the decrypted payload as a byte vector.
    pub async fn receive_bytes(&self) -> Result<Vec<u8>, ClientSocketError> {
        let buffer = self.receive().await?;
        Ok(buffer.slice().to_vec())
    }
}
