/// Simple mode: no-op decoy provider that passes packets through without generating any decoy traffic.
use std::sync::atomic::AtomicU32;
use std::sync::{Arc, Weak};

use async_trait::async_trait;

use crate::bytes::DynamicByteBuffer;
use crate::cache::DerivedValue;
use crate::flow::decoy::common::{DecoyCommunicationMode, DecoyFlowSender, DecoyProvider};
use crate::settings::Settings;
use crate::tailer::IdentityType;
use crate::utils::sync::AsyncExecutor;

/// Simple mode does not spawn any coroutines and does not send any packets.
pub struct SimpleDecoyProvider;

#[async_trait]
impl DecoyProvider for SimpleDecoyProvider {
    #[inline]
    fn name(&self) -> &'static str {
        "SimpleDecoyProvider"
    }

    async fn start(&self) {}

    async fn feed_input(&self, packet: DynamicByteBuffer, _tailer_buf: DynamicByteBuffer) -> Option<DynamicByteBuffer> {
        Some(packet)
    }

    async fn feed_output(&self, body: DynamicByteBuffer, _tailer_buf: DynamicByteBuffer) -> Option<DynamicByteBuffer> {
        Some(body)
    }
}

impl<T: IdentityType + Clone, AE: AsyncExecutor> DecoyCommunicationMode<T, AE> for SimpleDecoyProvider {
    fn new(_manager: Weak<dyn DecoyFlowSender>, _settings: Arc<Settings<AE>>, _identity: DerivedValue<T>, _counter: Arc<AtomicU32>, _fallthrough_probability: Option<f64>) -> Self {
        Self
    }
}
