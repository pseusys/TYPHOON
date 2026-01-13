use std::net::SocketAddr;
use std::sync::Arc;

use tokio::net::UdpSocket;
use tokio::sync::RwLock;

use crate::bytes::ByteBuffer;
use crate::error::{TyphoonError, TyphoonResult};
use crate::flow::decoy::DecoyProvider;
use crate::flow::envelope::Envelope;
use crate::flow::fake_body::FakeBodyGenerator;
use crate::flow::fake_header::FakeHeaderGenerator;
use crate::tailor::ENCRYPTED_TAILOR_SIZE;

/// Configuration for a flow.
#[derive(Debug, Clone)]
pub struct FlowConfig {
    /// Local address to bind to.
    pub local_addr: SocketAddr,
    /// Maximum packet size.
    pub max_packet_size: usize,
    /// Whether to use fake headers.
    pub use_fake_header: bool,
    /// Whether to use fake bodies.
    pub use_fake_body: bool,
}

impl FlowConfig {
    /// Create a new flow configuration.
    pub fn new(local_addr: SocketAddr) -> Self {
        Self {
            local_addr,
            max_packet_size: 65535,
            use_fake_header: true,
            use_fake_body: true,
        }
    }

    /// Create a minimal configuration (no obfuscation).
    pub fn minimal(local_addr: SocketAddr) -> Self {
        Self {
            local_addr,
            max_packet_size: 65535,
            use_fake_header: false,
            use_fake_body: false,
        }
    }
}

/// Flow controller trait.
///
/// Manages UDP socket operations and packet envelope handling.
pub trait FlowController: Send + Sync {
    /// Send a packet to the specified address.
    fn send(
        &self,
        packet: ByteBuffer,
        target: SocketAddr,
    ) -> impl std::future::Future<Output = TyphoonResult<()>> + Send;

    /// Receive a packet from the socket.
    ///
    /// Returns: (packet_data, source_address)
    fn recv(&self)
        -> impl std::future::Future<Output = TyphoonResult<(ByteBuffer, SocketAddr)>> + Send;

    /// Get the local address of the socket.
    fn local_addr(&self) -> TyphoonResult<SocketAddr>;

    /// Wrap a payload with envelope (fake header, tailor, fake body).
    fn wrap_envelope(
        &self,
        encrypted_payload: ByteBuffer,
        encrypted_tailor: ByteBuffer,
    ) -> TyphoonResult<ByteBuffer>;

    /// Unwrap an envelope to extract payload and tailor.
    ///
    /// Returns: (body_with_payload, encrypted_tailor)
    fn unwrap_envelope(&self, packet: ByteBuffer) -> TyphoonResult<(ByteBuffer, ByteBuffer)>;
}

/// Base flow manager implementation.
pub struct BaseFlowManager {
    /// UDP socket.
    socket: Arc<UdpSocket>,
    /// Configuration.
    config: FlowConfig,
    /// Fake header generator.
    header_generator: RwLock<Option<FakeHeaderGenerator>>,
    /// Fake body generator.
    body_generator: RwLock<Option<FakeBodyGenerator>>,
    /// Decoy provider (optional).
    decoy_provider: RwLock<Option<Box<dyn DecoyProvider>>>,
}

impl BaseFlowManager {
    /// Create a new base flow manager.
    pub async fn new(config: FlowConfig) -> TyphoonResult<Self> {
        let socket = UdpSocket::bind(config.local_addr)
            .await
            .map_err(TyphoonError::NetworkError)?;

        let header_generator = if config.use_fake_header {
            Some(FakeHeaderGenerator::default_random())
        } else {
            None
        };

        let body_generator = if config.use_fake_body {
            Some(FakeBodyGenerator::default())
        } else {
            None
        };

        Ok(Self {
            socket: Arc::new(socket),
            config,
            header_generator: RwLock::new(header_generator),
            body_generator: RwLock::new(body_generator),
            decoy_provider: RwLock::new(None),
        })
    }

    /// Create a flow manager from an existing socket.
    pub fn from_socket(socket: UdpSocket, config: FlowConfig) -> Self {
        let header_generator = if config.use_fake_header {
            Some(FakeHeaderGenerator::default_random())
        } else {
            None
        };

        let body_generator = if config.use_fake_body {
            Some(FakeBodyGenerator::default())
        } else {
            None
        };

        Self {
            socket: Arc::new(socket),
            config,
            header_generator: RwLock::new(header_generator),
            body_generator: RwLock::new(body_generator),
            decoy_provider: RwLock::new(None),
        }
    }

    /// Get a reference to the socket.
    pub fn socket(&self) -> &UdpSocket {
        &self.socket
    }

    /// Get the configuration.
    pub fn config(&self) -> &FlowConfig {
        &self.config
    }

    /// Set a custom header generator.
    pub async fn set_header_generator(&self, generator: Option<FakeHeaderGenerator>) {
        *self.header_generator.write().await = generator;
    }

    /// Set a custom body generator.
    pub async fn set_body_generator(&self, generator: Option<FakeBodyGenerator>) {
        *self.body_generator.write().await = generator;
    }

    /// Set the decoy provider.
    pub async fn set_decoy_provider(&self, provider: Option<Box<dyn DecoyProvider>>) {
        *self.decoy_provider.write().await = provider;
    }

    /// Generate a fake header if enabled.
    async fn generate_header(&self) -> Option<ByteBuffer> {
        let mut guard = self.header_generator.write().await;
        guard.as_mut().and_then(|g| g.generate())
    }

    /// Generate a fake body if enabled.
    async fn generate_body(&self) -> Option<ByteBuffer> {
        let guard = self.body_generator.read().await;
        guard.as_ref().and_then(|g| g.generate())
    }
}

impl FlowController for BaseFlowManager {
    async fn send(&self, packet: ByteBuffer, target: SocketAddr) -> TyphoonResult<()> {
        self.socket
            .send_to(packet.slice(), target)
            .await
            .map_err(TyphoonError::NetworkError)?;
        Ok(())
    }

    async fn recv(&self) -> TyphoonResult<(ByteBuffer, SocketAddr)> {
        let mut buf = vec![0u8; self.config.max_packet_size];
        let (len, addr) = self
            .socket
            .recv_from(&mut buf)
            .await
            .map_err(TyphoonError::NetworkError)?;

        buf.truncate(len);
        Ok((ByteBuffer::from(buf), addr))
    }

    fn local_addr(&self) -> TyphoonResult<SocketAddr> {
        self.socket
            .local_addr()
            .map_err(TyphoonError::NetworkError)
    }

    fn wrap_envelope(
        &self,
        encrypted_payload: ByteBuffer,
        encrypted_tailor: ByteBuffer,
    ) -> TyphoonResult<ByteBuffer> {
        // For sync envelope wrapping, we can't use async header/body generation
        // Use direct envelope creation without generators
        let envelope = Envelope::payload_only(encrypted_payload, encrypted_tailor)?;
        Ok(envelope.into_buffer())
    }

    fn unwrap_envelope(&self, packet: ByteBuffer) -> TyphoonResult<(ByteBuffer, ByteBuffer)> {
        Envelope::extract_tailor_from_end(packet)
    }
}

impl BaseFlowManager {
    /// Wrap envelope with async header/body generation.
    pub async fn wrap_envelope_async(
        &self,
        encrypted_payload: ByteBuffer,
        encrypted_tailor: ByteBuffer,
    ) -> TyphoonResult<ByteBuffer> {
        let header = self.generate_header().await;
        let body = self.generate_body().await;

        let envelope = Envelope::new(header, encrypted_payload, encrypted_tailor, body)?;
        Ok(envelope.into_buffer())
    }

    /// Send with async envelope wrapping.
    pub async fn send_wrapped(
        &self,
        encrypted_payload: ByteBuffer,
        encrypted_tailor: ByteBuffer,
        target: SocketAddr,
    ) -> TyphoonResult<()> {
        let packet = self
            .wrap_envelope_async(encrypted_payload, encrypted_tailor)
            .await?;
        self.send(packet, target).await
    }

    /// Notify decoy provider of packet activity.
    pub async fn notify_packet_sent(&self, bytes: usize) {
        let guard = self.decoy_provider.read().await;
        if let Some(provider) = guard.as_ref() {
            provider.on_packet_sent(bytes);
        }
    }

    /// Notify decoy provider of packet received.
    pub async fn notify_packet_received(&self, bytes: usize) {
        let guard = self.decoy_provider.read().await;
        if let Some(provider) = guard.as_ref() {
            provider.on_packet_received(bytes);
        }
    }

    /// Check if decoy should be sent and generate one.
    pub async fn maybe_generate_decoy(&self) -> Option<ByteBuffer> {
        let guard = self.decoy_provider.read().await;
        guard.as_ref().and_then(|p| p.maybe_generate_decoy())
    }
}

#[cfg(test)]
#[path = "../../tests/flow/controller.rs"]
mod tests;
