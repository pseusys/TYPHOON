/// Simple mode: no-op decoy provider that passes packets through without generating any decoy traffic.
use std::sync::{Arc, Weak};

use async_trait::async_trait;

use crate::bytes::DynamicByteBuffer;
use crate::flow::decoy::common::{DecoyCommunicationMode, DecoyFlowSender, DecoyProvider};
use crate::settings::Settings;
use crate::tailor::IdentityType;
use crate::utils::sync::AsyncExecutor;

/// Simple mode does not spawn any coroutines and does not send any packets.
pub struct SimpleDecoyProvider;

#[async_trait]
impl DecoyProvider for SimpleDecoyProvider {
    #[inline]
    fn name(&self) -> &'static str {
        "SimpleDecoyProvider"
    }

    async fn start(&mut self) {}

    async fn feed_input(&mut self, packet: DynamicByteBuffer, _tailor_buf: DynamicByteBuffer) -> Option<DynamicByteBuffer> {
        Some(packet)
    }

    async fn feed_output(&mut self, body: DynamicByteBuffer, _tailor_buf: DynamicByteBuffer) -> Option<DynamicByteBuffer> {
        Some(body)
    }
}

impl<T: IdentityType + Clone, AE: AsyncExecutor> DecoyCommunicationMode<T, AE> for SimpleDecoyProvider {
    fn new(_manager: Weak<dyn DecoyFlowSender>, _settings: Arc<Settings<AE>>, _identity: T, _fallthrough_probability: Option<f64>) -> Self {
        Self
    }
}
