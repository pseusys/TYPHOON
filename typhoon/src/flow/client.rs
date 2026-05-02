/// Client-side flow manager implementation.
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Weak};

use crate::bytes::DynamicByteBuffer;
use crate::cache::CachedValue;
use crate::crypto::ClientCryptoTool;
use crate::defaults::NoopProbeHandler;
use crate::flow::common::{FlowManager, FlowReceiveInternal, FlowSendInternal, ProcessIncomingResult};
use crate::flow::config::FlowConfig;
use crate::flow::decoy::{DecoyFactory, DecoyFlowSender, DecoyProvider};
use crate::flow::error::FlowControllerError;
use crate::flow::probe::{ActiveProbeHandler, ProbeFactory, ProbeFlowSender};
use crate::settings::Settings;
use crate::tailor::IdentityType;
use crate::utils::socket::{Socket, SocketError};
use crate::utils::sync::{AsyncExecutor, Mutex};

/// Client-side flow manager that handles packet encryption, decoy traffic, and socket I/O.
pub struct ClientFlowManager<T: IdentityType + Clone, AE: AsyncExecutor> {
    decoy_provider: Mutex<Box<dyn DecoyProvider>>,
    send_internal: Mutex<FlowSendInternal<ClientCryptoTool<T>>>,
    receive_internal: Mutex<FlowReceiveInternal<ClientCryptoTool<T>>>,
    sock: Socket,
    mtu: usize,
    settings: Arc<Settings<AE>>,
    /// Handler for unidentified packets. Locked only for rare unexpected arrivals.
    probe_handler: Mutex<Box<dyn ActiveProbeHandler<AE>>>,
}

impl<T: IdentityType + Clone + 'static, AE: AsyncExecutor + 'static> ClientFlowManager<T, AE> {
    /// Create a new client flow manager.
    pub(crate) async fn new(config: FlowConfig, probe_factory: Option<&ProbeFactory<AE>>, mut cipher: CachedValue<ClientCryptoTool<T>>, settings: Arc<Settings<AE>>, sock: Socket, factory: &DecoyFactory<T, AE>) -> Result<Arc<Self>, FlowControllerError> {
        let identity = cipher.get_mut().map_err(FlowControllerError::MissingCache)?.identity();
        let send_provider = cipher.create_sibling().map_err(FlowControllerError::MissingCache)?;
        let receive_provider = cipher.create_sibling().map_err(FlowControllerError::MissingCache)?;
        let handler_factory = probe_factory.cloned();
        let settings_for_start = Arc::clone(&settings);

        let manager_ref = Arc::new_cyclic(|m: &Weak<ClientFlowManager<T, AE>>| {
            let mgr: Weak<dyn DecoyFlowSender> = m.clone();
            let decoy = factory(mgr, settings.clone(), identity);
            let probe_handler: Box<dyn ActiveProbeHandler<AE>> = match &handler_factory {
                Some(f) => f(),
                None => Box::new(NoopProbeHandler),
            };
            let mtu = settings.mtu();
            ClientFlowManager {
                decoy_provider: Mutex::new(decoy),
                send_internal: Mutex::new(FlowSendInternal {
                    provider: send_provider,
                    config,
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
        manager_ref.decoy_provider.lock().await.start().await;
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

impl<T: IdentityType + Clone + 'static, AE: AsyncExecutor + 'static> FlowManager for ClientFlowManager<T, AE> {
    async fn send_packet(&self, packet: DynamicByteBuffer, generated: bool) -> Result<(), FlowControllerError> {
        let notified_packet = {
            let mut lock = self.decoy_provider.lock().await;
            let notified_packet = lock.feed_output(packet, generated).await;
            if notified_packet.is_none() {
                return Ok(());
            }
            notified_packet
        };

        let mut lock = self.send_internal.lock().await;
        let full_packet = lock.prepare_outgoing(notified_packet.unwrap(), self.mtu, self.settings.pool())?;
        self.sock.send(full_packet).await.map_err(FlowControllerError::SocketError)?;
        Ok(())
    }

    async fn receive_packet(&self, packet: DynamicByteBuffer) -> Result<DynamicByteBuffer, FlowControllerError> {
        loop {
            let packet = self.sock.recv(packet.clone()).await.map_err(FlowControllerError::SocketError)?;
            let notified_packet = {
                let mut lock = self.decoy_provider.lock().await;
                let notified_packet = lock.feed_input(packet).await;
                if notified_packet.is_none() {
                    continue;
                }
                notified_packet.unwrap()
            };

            {
                let mut lock = self.receive_internal.lock().await;
                match lock.process_incoming(notified_packet, self.settings.pool())? {
                    ProcessIncomingResult::Valid(result) => return Ok(result),
                    ProcessIncomingResult::Decoy => continue,
                    ProcessIncomingResult::Unexpected(pkt) => {
                        drop(lock);
                        self.probe_handler.lock().await.process(pkt, None).await;
                    }
                }
            }
        }
    }
}
