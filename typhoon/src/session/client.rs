#[cfg(all(test, feature = "tokio", feature = "client", feature = "server"))]
#[path = "../../tests/session/client.rs"]
mod tests;

/// Client-side session manager implementation.
use std::future::Future;
use std::mem::take;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

use log::{debug, warn};

use crate::bytes::{ByteBuffer, ByteBufferMut, DynamicByteBuffer};
use crate::cache::SharedValue;
use crate::crypto::ClientCryptoTool;
use crate::flow::{FlowControllerError, FlowManager};
use crate::session::client_health::ClientHealthProvider;
use crate::session::common::SessionManager;
use crate::session::error::SessionControllerError;
use crate::settings::Settings;
use crate::tailer::{ClientConnectionHandler, IdentityType, PacketFlags, Tailer};
use crate::utils::random::{SupportRng, get_rng};
use crate::utils::sync::{AsyncExecutor, Mutex, create_watch};
use crate::utils::unix_timestamp_ms;

type RecvFut = Pin<Box<dyn Future<Output = Result<DynamicByteBuffer, FlowControllerError>> + Send>>;

struct ClientSessionManagerInternalSend<T: IdentityType + Clone> {
    cipher: SharedValue<ClientCryptoTool<T>>,
}

struct ClientSessionManagerInternalReceive<T: IdentityType + Clone> {
    cipher: SharedValue<ClientCryptoTool<T>>,
}

/// Client-side session manager that encrypts data and manages health checking.
pub struct ClientSessionManager<T: IdentityType + Clone + 'static, AE: AsyncExecutor + 'static, FM: FlowManager + Clone + Send + Sync + 'static, CC: ClientConnectionHandler + 'static> {
    health_provider: ClientHealthProvider<T, AE, Self, CC>,
    send_internal: Mutex<ClientSessionManagerInternalSend<T>>,
    receive_internal: Mutex<ClientSessionManagerInternalReceive<T>>,
    /// Per-session monotonic packet-number counter; shared with the health-check provider and every flow manager's decoy provider so the PN stream is single-sequence across data, health-check, handshake, decoy, and termination packets.
    counter: Arc<AtomicU32>,
    flows: Vec<FM>,
    settings: Arc<Settings<AE>>,
    /// Persistent per-flow receive futures and their flow indices, reused across `receive_packet` calls.
    recv_state: Mutex<Option<(Vec<RecvFut>, Vec<usize>)>>,
}

impl<T: IdentityType + Clone, AE: AsyncExecutor, FM: FlowManager + Clone + Send + Sync, CC: ClientConnectionHandler + 'static> ClientSessionManager<T, AE, FM, CC> {
    /// Create a new client session manager without starting the handshake.
    /// Call `start()` after the background receive loop is running.
    pub fn new(cipher: SharedValue<ClientCryptoTool<T>>, flows: Vec<FM>, settings: Arc<Settings<AE>>, counter: Arc<AtomicU32>, initial_data_generator: CC) -> Result<Arc<Self>, SessionControllerError> {
        let send_cipher = cipher.create_sibling();
        let receive_cipher = cipher.create_sibling();
        let health_state_crypto = cipher.create_sibling();

        let (response_tx, response_rx) = create_watch();
        let (shadowride_tx, _) = create_watch();

        let value = Arc::new_cyclic(|weak| {
            let health_provider = ClientHealthProvider::new(weak.clone(), settings.clone(), health_state_crypto, Arc::clone(&counter), response_tx, shadowride_tx, response_rx, initial_data_generator);

            ClientSessionManager {
                health_provider,
                send_internal: Mutex::new(ClientSessionManagerInternalSend {
                    cipher: send_cipher,
                }),
                receive_internal: Mutex::new(ClientSessionManagerInternalReceive {
                    cipher: receive_cipher,
                }),
                counter,
                flows,
                settings,
                recv_state: Mutex::new(None),
            }
        });

        Ok(value)
    }

    /// Perform the initial handshake and start the background health check timer.
    /// Must be called after the background receive loop is running so that
    /// handshake responses can be received and fed back to the health provider.
    pub async fn start(&self) -> Result<(), SessionControllerError> {
        self.health_provider.perform_handshake().await
    }

    /// Select a random flow manager.
    fn select_flow(&self) -> &FM {
        get_rng().random_item(&self.flows).expect("at least one flow manager required")
    }

    /// Compute the next packet number: `(incremental << 32) | unix_timestamp_seconds`.
    /// The counter is kept in the dominant half so raw `PN` ordering is immune to clock adjustments.
    fn next_packet_number(&self) -> u64 {
        let counter = self.counter.fetch_add(1, Ordering::Relaxed).wrapping_add(1);
        let timestamp = (unix_timestamp_ms() / 1000) as u32;
        ((counter as u64) << 32) | (timestamp as u64)
    }
}

impl<T: IdentityType + Clone, AE: AsyncExecutor, FM: FlowManager + Clone + Send + Sync + 'static, CC: ClientConnectionHandler + 'static> SessionManager for ClientSessionManager<T, AE, FM, CC> {
    async fn send_packet(&self, packet: DynamicByteBuffer, generated: bool) -> Result<(), SessionControllerError> {
        let full_packet = if generated {
            packet
        } else {
            let (encrypted_payload, payload_length, identity) = {
                let mut send_lock = self.send_internal.lock().await;
                // Single get_mut() covers both encrypt_payload and identity() — one lock acquire.
                let cipher = send_lock.cipher.get_mut();
                let encrypted_payload = cipher.encrypt_payload(packet, None).map_err(SessionControllerError::Crypto)?;
                let payload_length = encrypted_payload.len() as u16;
                let identity = cipher.identity();
                (encrypted_payload, payload_length, identity)
                // send_lock released here
            };
            let packet_number = self.next_packet_number();

            let encrypted_payload_len = encrypted_payload.len();
            let tailer_buf = encrypted_payload.expand_end(T::length()).rebuffer_start(encrypted_payload_len);
            let tailer = Tailer::data(tailer_buf, &identity, payload_length, packet_number);

            // Let health provider potentially attach a shadowride.
            // Clone is cheap (Arc), and writes are visible through the shared buffer.
            self.health_provider.feed_output(tailer.clone()).await?;

            encrypted_payload.expand_end(Tailer::<T>::len())
        };

        self.select_flow().send_packet(full_packet, false, false).await.map_err(SessionControllerError::Flow)
    }

    async fn receive_packet(&self) -> Result<DynamicByteBuffer, SessionControllerError> {
        loop {
            // Poll all flows concurrently so responses arriving on any flow are received.
            // For a single flow the fast path avoids the allocation overhead of select_all.
            let packet = if self.flows.len() == 1 {
                let recv_buf = self.settings.pool().allocate_for_recv();
                self.flows[0].receive_packet(recv_buf).await.map_err(SessionControllerError::Flow)?
            } else {
                // Take the persistent future state (releasing the lock before awaiting).
                let (futs, mut flow_indices) = {
                    let mut guard = self.recv_state.lock().await;
                    guard.take().unwrap_or_else(|| {
                        let mut futs: Vec<RecvFut> = Vec::with_capacity(self.flows.len());
                        let mut indices: Vec<usize> = Vec::with_capacity(self.flows.len());
                        for (i, flow) in self.flows.iter().enumerate() {
                            let f = flow.clone();
                            let buf = self.settings.pool().allocate_for_recv();
                            futs.push(Box::pin(async move { f.receive_packet(buf).await }));
                            indices.push(i);
                        }
                        (futs, indices)
                    })
                };

                let (result, completed_pos, mut remaining_futs) = futures::future::select_all(futs).await;
                let completed_flow_idx = flow_indices.remove(completed_pos);

                // Replenish a new future for the flow that just completed.
                let f = self.flows[completed_flow_idx].clone();
                let buf = self.settings.pool().allocate_for_recv();
                remaining_futs.push(Box::pin(async move { f.receive_packet(buf).await }));
                flow_indices.push(completed_flow_idx);

                *self.recv_state.lock().await = Some((remaining_futs, flow_indices));

                result.map_err(SessionControllerError::Flow)?
            };

            // The flow manager returns: encrypted_payload || plaintext_tailer (full Tailer::<T>::len() bytes).
            let (payload_part, tailer_part) = packet.split_buf_end(Tailer::<T>::len());
            let tailer = Tailer::<T>::new(tailer_part);

            debug!("client session: received {:?} packet", tailer.flags());

            if tailer.flags().is_termination() {
                debug!("client session: connection terminated by server (code={})", tailer.code());
                return Err(SessionControllerError::ConnectionTerminated(tailer.code()));
            }

            if tailer.flags().contains(PacketFlags::HANDSHAKE) {
                self.health_provider.feed_handshake_input(tailer.clone(), payload_part.clone()).await?;
            }

            if tailer.flags().contains(PacketFlags::HEALTH_CHECK) {
                self.health_provider.feed_input(tailer.clone()).await?;
            }

            if tailer.flags().has_payload() {
                let mut recv_lock = self.receive_internal.lock().await;
                match recv_lock.cipher.get_mut().decrypt_payload(payload_part, None) {
                    Ok(decrypted) => return Ok(decrypted),
                    Err(err) => warn!("client session: payload decryption failed: {err}"),
                }
            }
        }
    }
}

impl<T: IdentityType + Clone, AE: AsyncExecutor, FM: FlowManager + Clone + Send + Sync + 'static, CC: ClientConnectionHandler + 'static> Drop for ClientSessionManager<T, AE, FM, CC> {
    /// Emit a TERMINATION packet through the regular async flow path before the session is released.
    fn drop(&mut self) {
        if self.flows.is_empty() {
            return;
        }
        let pn = self.next_packet_number();
        let executor = self.settings.executor().clone();
        executor.block_on(async {
            let (identity, code) = self.health_provider.termination_snapshot().await;
            let buf = self.settings.pool().allocate(Some(Tailer::<T>::len()));
            let tailer = Tailer::termination(buf, &identity, code, pn);
            let _ = self.select_flow().send_packet(tailer.into_buffer(), false, false).await;
        });
        drop(take(&mut self.flows));
    }
}
