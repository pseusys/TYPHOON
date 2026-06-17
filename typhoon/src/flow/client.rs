/// Client-side flow manager implementation.
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::AtomicU32;
use std::sync::{Arc, Weak};

use crate::bytes::{ByteBuffer, ByteBufferMut, DynamicByteBuffer};
use crate::cache::CachedValue;
use crate::capture::{CaptureContext, record_flow_config};
use crate::crypto::ClientCryptoTool;
use crate::defaults::NoopProbeHandler;
use crate::flow::common::{FlowManager, FlowReceiveInternal, FlowSendInternal, ProcessIncomingResult};
use crate::flow::config::FlowConfig;
use crate::flow::decoy::{DecoyFactory, DecoyFlowSender, DecoyProvider};
use crate::flow::error::FlowControllerError;
use crate::flow::probe::{ActiveProbeHandler, ProbeFactory, ProbeFlowSender};
use crate::settings::Settings;
use crate::tailor::{IdentityType, Tailor};
use crate::utils::socket::{Socket, SocketError};
use crate::utils::sync::{AsyncExecutor, Mutex};

/// Client-side flow manager that handles packet encryption, decoy traffic, and socket I/O.
pub struct ClientFlowManager<T: IdentityType + Clone, AE: AsyncExecutor> {
    decoy_provider: Box<dyn DecoyProvider>,
    send_internal: Mutex<FlowSendInternal<T>>,
    receive_internal: Mutex<FlowReceiveInternal<T>>,
    sock: Socket,
    mtu: usize,
    settings: Arc<Settings<AE>>,
    probe_handler: Mutex<Box<dyn ActiveProbeHandler<AE>>>,
}

impl<T: IdentityType + Clone + 'static, AE: AsyncExecutor + 'static> ClientFlowManager<T, AE> {
    /// Create a new client flow manager.
    pub(crate) async fn new(config: FlowConfig, cipher: CachedValue<ClientCryptoTool<T>>, settings: Arc<Settings<AE>>, sock: Socket, probe_factory: Option<&ProbeFactory<AE>>, decoy_factory: &DecoyFactory<T, AE>, counter: Arc<AtomicU32>, addr: SocketAddr) -> Result<Arc<Self>, FlowControllerError> {
        let identity = cipher.derive(ClientCryptoTool::<T>::identity).map_err(FlowControllerError::MissingCache)?;
        let send_provider = cipher.create_sibling().map_err(FlowControllerError::MissingCache)?;
        let receive_provider = cipher.create_sibling().map_err(FlowControllerError::MissingCache)?;
        let handler_factory = probe_factory.cloned();
        let settings_for_start = Arc::clone(&settings);

        let manager_ref = Arc::new_cyclic(|m: &Weak<ClientFlowManager<T, AE>>| {
            let mgr: Weak<dyn DecoyFlowSender> = m.clone();
            let decoy = decoy_factory(mgr, settings.clone(), identity, counter);
            let probe_handler: Box<dyn ActiveProbeHandler<AE>> = match &handler_factory {
                Some(f) => f(),
                None => Box::new(NoopProbeHandler),
            };
            let mtu = settings.mtu();
            record_flow_config(addr, "c2s", || (config.fake_body_mode.description(), config.fake_header_mode.len(), decoy.name()));
            ClientFlowManager {
                decoy_provider: decoy,
                send_internal: Mutex::new(FlowSendInternal {
                    provider: send_provider,
                    config,
                    capture: CaptureContext::new(addr),
                }),
                receive_internal: Mutex::new(FlowReceiveInternal {
                    provider: receive_provider,
                }),
                sock,
                mtu,
                settings,
                probe_handler: Mutex::new(probe_handler),
            }
        });
        manager_ref.decoy_provider.start().await;
        let weak: Weak<dyn ProbeFlowSender> = Arc::downgrade(&manager_ref) as Weak<dyn ProbeFlowSender>;
        manager_ref.probe_handler.lock().await.start(weak, settings_for_start).await;
        Ok(manager_ref)
    }
}

impl<T: IdentityType + Clone + 'static, AE: AsyncExecutor + 'static> ProbeFlowSender for ClientFlowManager<T, AE> {
    fn send_raw<'a>(&'a self, packet: DynamicByteBuffer, _target: SocketAddr) -> Pin<Box<dyn Future<Output = Result<(), SocketError>> + Send + 'a>> {
        Box::pin(async move { self.sock.send(packet).await.map(|_| ()) })
    }
}

impl<T: IdentityType + Clone + 'static, AE: AsyncExecutor + 'static> DecoyFlowSender for ClientFlowManager<T, AE> {
    fn send_decoy_packet<'a>(&'a self, packet: DynamicByteBuffer, fallthrough: bool, is_maintenance: bool) -> Pin<Box<dyn Future<Output = Result<(), FlowControllerError>> + Send + 'a>> {
        Box::pin(<Self as FlowManager>::send_packet(self, packet, fallthrough, is_maintenance))
    }
}

impl<T: IdentityType + Clone + 'static, AE: AsyncExecutor + 'static> FlowManager for ClientFlowManager<T, AE> {
    async fn send_packet(&self, packet: DynamicByteBuffer, fallthrough: bool, is_maintenance: bool) -> Result<(), FlowControllerError> {
        let tailor_len = Tailor::<T>::len();
        let (body, tailor_buf) = packet.split_buf_end(tailor_len);

        let notified_body = match self.decoy_provider.feed_output(body, tailor_buf.clone()).await {
            None => return Ok(()),
            Some(b) => b,
        };

        let mut lock = self.send_internal.lock().await;
        let full_packet = lock.prepare_outgoing(notified_body.expand_end(tailor_buf.len()), self.mtu, self.settings.pool(), fallthrough, is_maintenance)?;
        if full_packet.len() > 0 {
            self.sock.send(full_packet).await.map_err(FlowControllerError::SocketError)?;
        }
        Ok(())
    }

    async fn receive_packet(&self, packet: DynamicByteBuffer) -> Result<DynamicByteBuffer, FlowControllerError> {
        loop {
            let wire_packet = self.sock.recv(packet.clone()).await.map_err(FlowControllerError::SocketError)?;

            let (body, tailor_buf) = {
                let mut lock = self.receive_internal.lock().await;
                match lock.deobfuscate_incoming(wire_packet.clone(), self.settings.pool())? {
                    None => {
                        self.probe_handler.lock().await.process(wire_packet, None).await;
                        continue;
                    }
                    Some(pair) => pair,
                }
            };

            let notified_body = match self.decoy_provider.feed_input(body.clone(), tailor_buf.clone()).await {
                None => continue,
                Some(b) => b,
            };

            let incoming_packet = {
                let lock = self.receive_internal.lock().await;
                lock.process_with_tailor(notified_body, tailor_buf)
            };
            match incoming_packet {
                ProcessIncomingResult::Decoy => {}
                ProcessIncomingResult::Valid(result) => return Ok(result),
            }
        }
    }
}
