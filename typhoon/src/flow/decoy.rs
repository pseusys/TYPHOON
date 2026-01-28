use std::sync::Weak;

use crate::bytes::ByteBuffer;
use crate::flow::common::FlowManager;

pub trait DecoyCommunicationMode: Sized {
    type FlowManagerT: FlowManager;

    fn new(manager: Weak<Self::FlowManagerT>) -> Self;
    fn feed(&self, packet: ByteBuffer, tailor_len: usize) -> Option<(ByteBuffer, usize)>;
}
