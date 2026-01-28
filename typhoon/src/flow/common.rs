use crate::{bytes::ByteBuffer, flow::error::FlowControllerError};

pub trait FlowManager {
    async fn send_packet(&self, packet: ByteBuffer, tailor_len: usize) -> Result<(), FlowControllerError>;
    async fn receive_packet(&self, packet: ByteBuffer, tailor_len: usize) -> Result<ByteBuffer, FlowControllerError>;
}
