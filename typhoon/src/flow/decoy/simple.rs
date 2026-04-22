/// Simple mode: no-op decoy provider that passes packets through without generating any decoy traffic.
use std::sync::{Arc, Weak};

use async_trait::async_trait;

use crate::bytes::DynamicByteBuffer;
use crate::flow::decoy::common::{DecoyProvider, DecoyCommunicationMode, DecoyFlowSender};
use crate::settings::Settings;
use crate::tailor::IdentityType;
use crate::utils::sync::AsyncExecutor;

/// Simple mode does not spawn any coroutines and does not send any packets.
pub struct SimpleDecoyProvider;

#[async_trait]
impl DecoyProvider for SimpleDecoyProvider {
    async fn start(&mut self) {}

    async fn feed_input(&mut self, packet: DynamicByteBuffer) -> Option<DynamicByteBuffer> {
        Some(packet)
    }

    async fn feed_output(&mut self, packet: DynamicByteBuffer, _generated: bool) -> Option<DynamicByteBuffer> {
        Some(packet)
    }
}

impl<T: IdentityType + Clone, AE: AsyncExecutor> DecoyCommunicationMode<T, AE> for SimpleDecoyProvider {
    fn new(_manager: Weak<dyn DecoyFlowSender>, _settings: Arc<Settings<AE>>, _identity: T) -> Self {
        Self
    }
}
