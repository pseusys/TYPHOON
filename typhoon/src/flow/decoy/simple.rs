/// Simple mode: no-op decoy provider that passes packets through without generating any decoy traffic.
use std::sync::{Arc, Weak};

use crate::bytes::DynamicByteBuffer;
use crate::flow::common::FlowManager;
use crate::flow::decoy::common::DecoyCommunicationMode;
use crate::settings::Settings;

/// Simple mode does not spawn any coroutines and does not send any packets.
pub struct SimpleDecoyProvider<FM: FlowManager> {
    _manager: Weak<FM>,
}

impl<FM: FlowManager + Send + Sync + 'static> DecoyCommunicationMode for SimpleDecoyProvider<FM> {
    type FlowManagerT = FM;

    fn new(manager: Weak<Self::FlowManagerT>, _settings: Arc<Settings>, _tailor: usize) -> Self {
        Self {
            _manager: manager,
        }
    }

    async fn start(&mut self) {}

    async fn feed_input(&mut self, packet: DynamicByteBuffer) -> Option<DynamicByteBuffer> {
        Some(packet)
    }

    async fn feed_output(&mut self, packet: DynamicByteBuffer, _generated: bool) -> Option<DynamicByteBuffer> {
        Some(packet)
    }
}
