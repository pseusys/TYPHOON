//! [`ClientHandle`]: the per-connection send/receive handle produced by [`super::server::Listener`].

use std::hash::Hash;
use std::sync::Arc;

use futures::future::{Either, select};
use futures::pin_mut;

use crate::bytes::{ByteBuffer, ByteBufferMut, DynamicByteBuffer};
use crate::flow::FlowControllerError;
use crate::session::SessionControllerError;
use crate::session::server::{OutgoingRouter, ServerSessionManager};
use crate::settings::{Settings, keys};
use crate::socket::error::ServerSocketError;
use crate::tailer::{IdentityType, ReturnCode, Tailer};
use crate::utils::random::jittered_chunk_size;
use crate::utils::sync::{AsyncExecutor, Mutex, NotifyQueueReceiver, WatchReceiver};
use crate::utils::unix_timestamp_ms;

/// Handle to a connected client, providing send/receive operations.
/// Not cloneable — only one handle per connection.
pub struct ClientHandle<T: IdentityType + Clone + Eq + Hash + Send + ToString + 'static, AE: AsyncExecutor + 'static> {
    pub(super) session: Arc<ServerSessionManager<T, AE>>,
    pub(super) identity: T,
    pub(super) incoming_rx: Mutex<NotifyQueueReceiver<DynamicByteBuffer>>,
    /// Fired once the session is removed from the router for any reason, so `receive()` can stop waiting on `incoming_rx` instead of hanging forever.
    pub(super) end_rx: Mutex<WatchReceiver<()>>,
    /// Maximum user-data bytes per packet so the wire packet fits within MTU.
    pub(super) max_data_payload: usize,
    pub(super) settings: Arc<Settings<AE>>,
    pub(super) router: Arc<dyn OutgoingRouter<T>>,
}

impl<T: IdentityType + Clone + Eq + Hash + Send + ToString, AE: AsyncExecutor> ClientHandle<T, AE> {
    /// The identity this handle is registered under.
    #[inline]
    pub fn identity(&self) -> &T {
        &self.identity
    }

    /// Send a packet using a pre-allocated buffer.
    ///
    /// # Errors
    ///
    /// Returns [`ServerSocketError::Session`] if encryption fails or no flow could deliver
    /// the packet.
    pub async fn send(&self, packet: DynamicByteBuffer) -> Result<(), ServerSocketError> {
        let wire = self.session.prepare_outgoing(packet, false).await.map_err(ServerSocketError::Session)?;
        if !self.router.route_packet(wire, &self.identity).await {
            return Err(ServerSocketError::Session(SessionControllerError::Flow(FlowControllerError::UserNotFound {
                identity: self.identity.to_string(),
            })));
        }
        Ok(())
    }

    /// Send a byte slice, splitting into payload-sized chunks so each wire packet fits within MTU.
    ///
    /// See `ClientSocket::send_bytes` — same fragmentation-only-when-needed +
    /// `TYPHOON_SEND_BYTES_JITTER`-driven per-chunk length sampling applies
    /// here for s2c traffic.
    ///
    /// # Errors
    ///
    /// Returns [`ServerSocketError::Session`] if encryption fails or no flow could deliver
    /// the packet.
    pub async fn send_bytes(&self, data: &[u8]) -> Result<(), ServerSocketError> {
        let jitter = self.settings.get(&keys::SEND_BYTES_JITTER);
        let chunk = self.settings.get(&keys::SEND_BYTES_CHUNK) as usize;
        let mut offset = 0;
        while offset < data.len() {
            let remaining = data.len() - offset;
            let chunk_size = if remaining <= self.max_data_payload {
                remaining
            } else {
                jittered_chunk_size(self.max_data_payload, chunk, jitter)
            };
            let buffer = self.settings.pool().allocate(Some(chunk_size));
            buffer.slice_mut().copy_from_slice(&data[offset..offset + chunk_size]);
            self.send(buffer).await?;
            offset += chunk_size;
        }
        Ok(())
    }

    /// Maximum user-data bytes per `send` call so the wire packet fits within MTU.
    pub fn max_data_payload(&self) -> usize {
        self.max_data_payload
    }

    /// Receive a packet, returning the decrypted payload as a buffer.
    ///
    /// # Errors
    ///
    /// Returns [`ServerSocketError::ChannelClosed`] once the session has ended for any reason,
    /// including being displaced by a re-handshake.
    pub async fn receive(&self) -> Result<DynamicByteBuffer, ServerSocketError> {
        let mut incoming = self.incoming_rx.lock().await;
        let mut ended = self.end_rx.lock().await;
        let recv_fut = incoming.recv();
        let end_fut = ended.recv();
        pin_mut!(recv_fut, end_fut);
        match select(recv_fut, end_fut).await {
            Either::Left((Some(buf), _)) => Ok(buf),
            _ => Err(ServerSocketError::ChannelClosed),
        }
    }

    /// Receive a packet, returning the decrypted payload as a byte vector.
    ///
    /// # Errors
    ///
    /// Returns [`ServerSocketError::ChannelClosed`] once the session has ended for any reason,
    /// including being displaced by a re-handshake.
    pub async fn receive_bytes(&self) -> Result<Vec<u8>, ServerSocketError> {
        let buffer = self.receive().await?;
        Ok(buffer.slice().to_vec())
    }

    /// Send a TERMINATION packet and remove the session, unless a re-handshake has already replaced it. Shared by `Drop` and `ClientPool::disconnect`.
    pub(crate) async fn terminate(&self) {
        let handshake_pn = self.session.handshake_pn();
        let pn = (unix_timestamp_ms() / 1000) as u64;
        let buf = self.settings.pool().allocate(Some(Tailer::<T>::len()));
        let termination = Tailer::termination(buf, &self.identity, ReturnCode::Success, pn).into_buffer();
        if self.router.is_current_session(&self.identity, handshake_pn).await {
            self.router.route_packet(termination, &self.identity).await;
            self.router.remove_session(&self.identity, handshake_pn).await;
        }
    }
}

impl<T: IdentityType + Clone + Eq + Hash + Send + ToString + 'static, AE: AsyncExecutor + 'static> Drop for ClientHandle<T, AE> {
    /// Run `terminate()` synchronously before the handle is released.
    fn drop(&mut self) {
        let executor = self.settings.executor().clone();
        executor.block_on(self.terminate());
    }
}
