/// Client-side flow manager implementation.
use std::sync::Arc;

use crate::bytes::DynamicByteBuffer;
use crate::cache::CachedValue;
use crate::crypto::ClientCryptoTool;
use crate::flow::common::{FlowManager, FlowReceiveInternal, FlowSendInternal};
use crate::flow::config::FlowConfig;
use crate::flow::decoy::{DecoyFlowSender, DecoyCommunicationMode};
use crate::flow::error::FlowControllerError;
use crate::settings::Settings;
use crate::tailor::IdentityType;
use crate::utils::socket::Socket;
use crate::utils::sync::{AsyncExecutor, Mutex};

/// Client-side flow manager that handles packet encryption, decoy traffic, and socket I/O.
pub struct ClientFlowManager<T: IdentityType + Clone, AE: AsyncExecutor, DP: Send + Sync> {
    decoy_provider: Mutex<DP>,
    send_internal: Mutex<FlowSendInternal<ClientCryptoTool<T>>>,
    receive_internal: Mutex<FlowReceiveInternal<ClientCryptoTool<T>>>,
    sock: Socket,
    mtu: usize,
    settings: Arc<Settings<AE>>,
}

impl<T: IdentityType + Clone + 'static, AE: AsyncExecutor + 'static, DP: DecoyCommunicationMode<T, AE> + 'static> ClientFlowManager<T, AE, DP> {
    /// Create a new client flow manager.
    pub(crate) async fn new(config: FlowConfig, mut cipher: CachedValue<ClientCryptoTool<T>>, settings: Arc<Settings<AE>>, sock: Socket) -> Result<Arc<Self>, FlowControllerError> {
        let identity = cipher.get_mut().map_err(FlowControllerError::MissingCache)?.identity();
        let send_provider = cipher.create_sibling().map_err(FlowControllerError::MissingCache)?;
        let receive_provider = cipher.create_sibling().map_err(FlowControllerError::MissingCache)?;
        let value = Arc::new_cyclic(|m: &std::sync::Weak<Self>| {
            let mgr: std::sync::Weak<dyn DecoyFlowSender> = m.clone();
            ClientFlowManager {
                decoy_provider: Mutex::new(DP::new(mgr, settings.clone(), identity)),
                send_internal: Mutex::new(FlowSendInternal {
                    provider: send_provider,
                    config,
                }),
                receive_internal: Mutex::new(FlowReceiveInternal {
                    provider: receive_provider,
                }),
                sock,
                mtu: settings.mtu(),
                settings,
            }
        });
        value.decoy_provider.lock().await.start().await;
        Ok(value)
    }
}

impl<T: IdentityType + Clone + 'static, AE: AsyncExecutor + 'static, DP: DecoyCommunicationMode<T, AE> + 'static> FlowManager for ClientFlowManager<T, AE, DP> {
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
                notified_packet
            };

            let mut lock = self.receive_internal.lock().await;
            match lock.process_incoming(notified_packet.unwrap(), self.settings.pool())? {
                Some(result) => return Ok(result),
                None => continue,
            }
        }
    }
}
