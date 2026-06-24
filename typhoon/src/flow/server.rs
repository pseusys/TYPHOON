//! Server-side flow manager implementation.

use std::collections::HashMap;
use std::future::Future;
use std::hash::Hash;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::AtomicU32;
use std::sync::{Arc, Weak};

use log::{debug, warn};
use rand::Rng;

use crate::bytes::{ByteBuffer, ByteBufferMut, DynamicByteBuffer};
use crate::cache::DerivedValue;
use crate::capture::{record_flow_config, record_server_send};
use crate::crypto::{ObfuscationTranscript, ServerCryptoTool};
use crate::defaults::NoopProbeHandler;
use crate::flow::config::{FakeBodyMode, FakeHeaderConfig, FlowConfig};
use crate::flow::decoy::{DecoyFactory, DecoyFlowSender, DecoyProvider};
use crate::flow::error::FlowControllerError;
use crate::flow::probe::{ActiveProbeHandler, ProbeFactory, ProbeFlowSender};
use crate::settings::Settings;
use crate::tailer::{IdentityType, PacketFlags, Tailer};
use crate::utils::random::get_rng;
use crate::utils::socket::{Socket, SocketError};
use crate::utils::sync::{AsyncExecutor, Mutex, RwLock};

/// Raw received packet from the server flow manager before session-level processing.
pub(crate) struct RawReceivedPacket<T: IdentityType> {
    pub(crate) body: DynamicByteBuffer,
    pub(crate) tailer: Tailer<T>,
    pub(crate) source_addr: SocketAddr,
    pub(crate) handshake_transcript: Option<ObfuscationTranscript>,
    pub(crate) original_wire_packet: Option<DynamicByteBuffer>,
}

/// Per-(flow, identity) path-binding state: the current return source address
/// for this client on this flow, and the latest PN we have seen.
///
/// Path-rebinding gate: the stored `addr` is updated only when an authenticated
/// non-handshake packet arrives with `pn > latest_pn` on this flow.  Out-of-order
/// data packets are still accepted into session processing — they just don't
/// move the binding.  Out-of-order decoys are dropped at the usual discardable
/// exit point.  See PROTOCOL.md §Identification and rebinding.
struct PathBinding {
    addr: SocketAddr,
    latest_pn: u64,
}

/// Server-side flow manager that handles per-user packet encryption, decoy traffic, and socket I/O.
/// Per-user crypto state is in the global `SharedMap` (accessed via `ServerCryptoTool`).
/// Send and receive crypto are split into independent instances so their locks never contend.
/// Per-user source addresses and decoy providers are local to each flow manager instance.
/// When built with multiple sockets (`SO_REUSEPORT` on Linux), each socket is polled by its own
/// drain task in the listener; the kernel distributes incoming datagrams across all sockets.
pub struct ServerFlowManager<T: IdentityType + Clone + Eq + Hash + Send + ToString, AE: AsyncExecutor> {
    user_bindings: RwLock<HashMap<T, RwLock<PathBinding>>>,
    decoy_providers: RwLock<HashMap<T, Arc<dyn DecoyProvider>>>,
    decoy_factory: DecoyFactory<T, AE>,
    crypto_send: Mutex<ServerCryptoTool<T>>,
    crypto_recv: Mutex<ServerCryptoTool<T>>,
    fake_body_mode: FakeBodyMode,
    fake_header_mode: Mutex<FakeHeaderConfig>,
    max_overhead: usize,
    socks: Vec<Arc<Socket>>,
    mtu: usize,
    settings: Arc<Settings<AE>>,
    probe_handler: Mutex<Box<dyn ActiveProbeHandler<AE>>>,
}

impl<T: IdentityType + Clone + Eq + Hash + Send + ToString + 'static, AE: AsyncExecutor + 'static> ServerFlowManager<T, AE> {
    /// Create a new server flow manager.
    /// `crypto_send` and `crypto_recv` must be independent instances (e.g. two `create_cache()` calls
    /// on the same `SharedMap`) so their mutexes never contend between the send and receive paths.
    /// `socks` must contain at least one socket; on Linux with `SO_REUSEPORT` multiple sockets may be
    /// supplied so that the listener can spawn one drain task per socket.
    pub(crate) async fn new(config: FlowConfig, probe_factory: Option<&ProbeFactory<AE>>, crypto_send: ServerCryptoTool<T>, crypto_recv: ServerCryptoTool<T>, settings: Arc<Settings<AE>>, socks: Vec<Arc<Socket>>, decoy_factory: DecoyFactory<T, AE>) -> Arc<Self> {
        let max_overhead = config.max_overhead();
        let handler_factory = probe_factory.cloned();
        let settings_for_start = Arc::clone(&settings);

        let manager = Arc::new_cyclic(|_: &Weak<ServerFlowManager<T, AE>>| {
            let handler: Box<dyn ActiveProbeHandler<AE>> = match &handler_factory {
                Some(f) => f(),
                None => Box::new(NoopProbeHandler),
            };
            let mtu = settings.mtu();
            ServerFlowManager {
                user_bindings: RwLock::new(HashMap::new()),
                decoy_providers: RwLock::new(HashMap::new()),
                decoy_factory,
                crypto_send: Mutex::new(crypto_send),
                crypto_recv: Mutex::new(crypto_recv),
                fake_body_mode: config.fake_body_mode,
                fake_header_mode: Mutex::new(config.fake_header_mode),
                max_overhead,
                socks,
                mtu,
                settings,
                probe_handler: Mutex::new(handler),
            }
        });
        let weak: Weak<dyn ProbeFlowSender> = Arc::downgrade(&manager) as Weak<dyn ProbeFlowSender>;
        manager.probe_handler.lock().await.start(weak, settings_for_start).await;
        manager
    }

    /// Return the slice of sockets owned by this flow manager.
    /// The listener spawns one drain task per socket so that all sockets are polled concurrently.
    pub(crate) fn recv_socks(&self) -> &[Arc<Socket>] {
        &self.socks
    }

    /// Forward a wire packet to this flow's active probe handler.
    /// Used by the listener to route handshake-flagged packets whose deferred HMAC verification failed.
    pub(crate) async fn forward_to_probe(&self, packet: DynamicByteBuffer, source_addr: SocketAddr) {
        self.probe_handler.lock().await.process(packet, Some(source_addr)).await;
    }

    /// Insert (or replace) the path binding for a user on this flow.
    pub async fn register_user_binding(&self, id: T, addr: SocketAddr, latest_pn: u64) {
        self.user_bindings.write().await.insert(
            id,
            RwLock::new(PathBinding {
                addr,
                latest_pn,
            }),
        );
    }

    /// Register a per-user decoy provider and start its background timer.
    /// The user's crypto state must already be in the global `SharedMap`.
    pub async fn register_user(self: &Arc<Self>, id: T, counter: Arc<AtomicU32>) {
        let weak: Weak<Self> = Arc::downgrade(self);
        let mgr: Weak<dyn DecoyFlowSender> = weak;
        let dp = (self.decoy_factory)(mgr, self.settings.clone(), DerivedValue::constant(id.clone()), counter);
        dp.start().await;
        let decoy_name = dp.name();
        self.decoy_providers.write().await.insert(id.clone(), Arc::from(dp));
        if let Some(binding) = self.user_bindings.read().await.get(&id) {
            let addr = binding.read().await.addr;
            let header_len = self.max_overhead - self.fake_body_mode.max_len();
            record_flow_config(addr, "s2c", || (self.fake_body_mode.description(), header_len, decoy_name));
        }
    }

    /// Lazily register the per-user decoy provider on this flow if not already
    /// present.  Called from the route task when a non-handshake packet from a
    /// known session arrives on a flow that has not yet seen this user; the
    /// path binding has already been anchored by `receive_raw`'s first-packet
    /// branch by the time we get here.
    pub async fn ensure_user(self: &Arc<Self>, id: T, counter: Arc<AtomicU32>) {
        if !self.decoy_providers.read().await.contains_key(&id) {
            self.register_user(id, counter).await;
        }
    }

    /// Remove a user's decoy provider and path binding from this flow manager.
    pub async fn remove_user(&self, id: &T) {
        self.decoy_providers.write().await.remove(id);
        self.user_bindings.write().await.remove(id);
    }

    /// Receive a raw packet, deobfuscating the tailer but returning the full body + tailer view.
    /// For handshake packets, per-user verification is skipped (user not registered yet).
    /// Decoy packets are filtered. Non-handshake packets are verified per-user and fed to decoy providers.
    /// `sock` is the specific socket to read from; the caller (drain task) owns one socket per task.
    pub(crate) async fn receive_raw(&self, packet: DynamicByteBuffer, sock: &Socket) -> Result<RawReceivedPacket<T>, FlowControllerError> {
        let encrypted_tailer_len = Tailer::<T>::encrypted_len_c2s();

        loop {
            let (packet, source_addr) = sock.recv_from(packet.clone()).await.map_err(FlowControllerError::Socket)?;

            // Undersized wire packets (shorter than the encrypted tailer) can't be valid Typhoon; forward to the probe handler and keep draining.
            if packet.len() < encrypted_tailer_len {
                warn!("server flow: undersized wire packet from {source_addr} ({} < {})", packet.len(), encrypted_tailer_len);
                self.probe_handler.lock().await.process(packet, Some(source_addr)).await;
                continue;
            }

            let (encrypted_packet, encrypted_tailer) = packet.split_buf_end(encrypted_tailer_len);

            // Deobfuscate tailer; for non-handshake packets verify immediately, for handshake packets defer the HMAC check until the listener has decapsulated the body and can recompute the initial-data encryption key.
            let (tailer, handshake_transcript) = {
                let mut crypto = self.crypto_recv.lock().await;
                let (tailer_buf, transcript) = match crypto.deobfuscate_tailer(encrypted_tailer, self.settings.pool()) {
                    Ok(result) => result,
                    Err(err) => {
                        warn!("server flow: tailer decryption failed from {source_addr}: {err}");
                        self.probe_handler.lock().await.process(encrypted_packet.expand_end(encrypted_tailer_len), Some(source_addr)).await;
                        continue;
                    }
                };
                let Some(tailer) = Tailer::<T>::validated(tailer_buf, encrypted_packet.len()) else {
                    warn!("server flow: malformed tailer from {source_addr} (size, flags or payload_length out of range)");
                    self.probe_handler.lock().await.process(encrypted_packet.expand_end(encrypted_tailer_len), Some(source_addr)).await;
                    continue;
                };
                if tailer.flags().contains(PacketFlags::HANDSHAKE) {
                    (tailer, Some(transcript))
                } else {
                    let identity = tailer.identity();
                    if let Err(err) = crypto.verify_tailer(&identity, transcript).await {
                        debug!("error verifying packet tailer: {err}");
                        self.probe_handler.lock().await.process(encrypted_packet.expand_end(encrypted_tailer_len), Some(source_addr)).await;
                        continue;
                    }
                    (tailer, None)
                }
            };

            let packet_flags = tailer.flags();
            let identity = tailer.identity();

            // For non-handshake packets, refresh the path binding for this
            // identity on this flow and feed the decoy provider if one has
            // already been instantiated locally.
            if !packet_flags.contains(PacketFlags::HANDSHAKE) {
                let pn = tailer.packet_number();
                let bindings = self.user_bindings.read().await;
                if let Some(binding_rw) = bindings.get(&identity) {
                    let latest = binding_rw.read().await.latest_pn;
                    if pn > latest {
                        let mut binding = binding_rw.write().await;
                        if pn > binding.latest_pn {
                            binding.latest_pn = pn;
                            if binding.addr != source_addr {
                                binding.addr = source_addr;
                            }
                        }
                    }
                } else {
                    drop(bindings);
                    self.user_bindings.write().await.entry(identity.clone()).or_insert_with(|| {
                        RwLock::new(PathBinding {
                            addr: source_addr,
                            latest_pn: pn,
                        })
                    });
                }

                let dp = self.decoy_providers.read().await.get(&identity).cloned();
                if let Some(dp) = dp {
                    let notified = dp.feed_input(encrypted_packet.clone(), tailer.buffer().clone()).await;
                    if notified.is_none() {
                        continue;
                    }
                }
            }

            // Decoy packets are always discarded at flow level.
            if packet_flags.is_discardable() {
                continue;
            }

            // Preserve a view over the original wire bytes so a failed deferred handshake verification can route the packet to the flow's probe handler.
            let original_wire_packet = packet_flags.contains(PacketFlags::HANDSHAKE).then(|| encrypted_packet.expand_end(encrypted_tailer_len));

            // For handshake packets, strip fake header/body using payload_length so the
            // session layer receives only the raw handshake data.
            let body = if packet_flags.contains(PacketFlags::HANDSHAKE) {
                let payload_len = tailer.payload_length() as usize;
                encrypted_packet.rebuffer_start(encrypted_packet.len().saturating_sub(payload_len))
            } else {
                encrypted_packet
            };

            debug!("server flow: received {packet_flags:?} packet from {source_addr}");
            return Ok(RawReceivedPacket {
                body,
                tailer,
                source_addr,
                handshake_transcript,
                original_wire_packet,
            });
        }
    }
}

impl<T: IdentityType + Clone + Eq + Hash + Send + ToString + 'static, AE: AsyncExecutor + 'static> ProbeFlowSender for ServerFlowManager<T, AE> {
    fn send_raw<'a>(&'a self, packet: DynamicByteBuffer, target: SocketAddr) -> Pin<Box<dyn Future<Output = Result<(), SocketError>> + Send + 'a>> {
        Box::pin(async move { self.socks[0].send_to(packet, target).await.map(|_| ()) })
    }
}

impl<T: IdentityType + Clone + Eq + Hash + Send + ToString + 'static, AE: AsyncExecutor + 'static> DecoyFlowSender for ServerFlowManager<T, AE> {
    fn send_decoy_packet<'a>(&'a self, packet: DynamicByteBuffer, fallthrough: bool, is_maintenance: bool) -> Pin<Box<dyn Future<Output = Result<(), FlowControllerError>> + Send + 'a>> {
        Box::pin(self.send_packet(packet, fallthrough, is_maintenance))
    }
}

impl<T: IdentityType + Clone + Eq + Hash + Send + ToString + 'static, AE: AsyncExecutor + 'static> ServerFlowManager<T, AE> {
    /// Send a packet through this flow.
    pub(crate) async fn send_packet(&self, packet: DynamicByteBuffer, fallthrough: bool, is_maintenance: bool) -> Result<(), FlowControllerError> {
        let tailer_len = Tailer::<T>::len();
        let (body, tailer_buf) = packet.split_buf_end(tailer_len);
        let identity = ServerCryptoTool::<T>::extract_identity(&tailer_buf);

        // Feed decoy provider for rate tracking.
        let notified_packet = {
            let dp = self.decoy_providers.read().await.get(&identity).cloned();
            if let Some(dp) = dp {
                let notified = dp.feed_output(body, tailer_buf.clone()).await;
                match notified {
                    None => return Ok(()),
                    Some(b) => b.expand_end(tailer_len),
                }
            } else {
                body.expand_end(tailer_len)
            }
        };

        let addr = {
            let bindings = self.user_bindings.read().await;
            let binding = bindings.get(&identity).ok_or_else(|| FlowControllerError::UserNotFound {
                identity: identity.to_string(),
            })?;
            binding.read().await.addr
        };

        // Fallthrough decoys: drop the plaintext tailer, skip encryption, treat the remaining body as opaque random bytes.  Non-fallthrough path is unchanged.
        let (encrypted_packet, packet_flags, data_len, tailer_overhead) = if fallthrough {
            let body_only = notified_packet.rebuffer_end(notified_packet.len() - tailer_len);
            let body_len = body_only.len();
            (body_only, PacketFlags::DECOY, body_len, 0_usize)
        } else {
            let (packet_data, packet_tailer) = notified_packet.split_buf_end(tailer_len);
            let flags = PacketFlags::from_bits_truncate(*packet_tailer.get(0));
            let data_len = packet_data.len();
            let encrypted_tailer = {
                let mut crypto = self.crypto_send.lock().await;
                crypto.obfuscate_tailer(packet_tailer, self.settings.pool()).await.map_err(FlowControllerError::TailerEncryption)?
            };
            let tailer_overhead = crate::crypto::TAILER_S2C_OVERHEAD;
            let encrypted = packet_data.expand_end(encrypted_tailer.len());
            (encrypted, flags, data_len, tailer_overhead)
        };

        // Add fake header and body (single lock scope: len + fill must be consistent).
        let (full_packet, cap_header, cap_body) = {
            let mut mode = self.fake_header_mode.lock().await;
            let fake_header_len = mode.len();
            let body_len = self.fake_body_mode.get_length(self.mtu, fake_header_len + encrypted_packet.len(), is_maintenance);
            let full_packet_len = fake_header_len + body_len;
            let full_packet = encrypted_packet.expand_start(full_packet_len);
            mode.fill(full_packet.rebuffer_end(fake_header_len));
            get_rng().fill(&mut full_packet.rebuffer_both(fake_header_len, full_packet_len));
            (full_packet, fake_header_len, body_len)
        };

        if full_packet.len() == 0 {
            return Ok(());
        }
        debug!("server flow: sending {packet_flags:?} packet to {addr}");
        self.socks[0].send_to(full_packet, addr).await.map_err(FlowControllerError::Socket)?;
        record_server_send(addr, || {
            let kind = if fallthrough {
                "DecoyFallthrough"
            } else if is_maintenance {
                "DecoyMaintenance"
            } else if packet_flags.is_discardable() {
                "Decoy"
            } else {
                "Data"
            };
            let tailer_len = if fallthrough {
                0
            } else {
                Tailer::<T>::len()
            };
            (kind, tailer_len, tailer_overhead, cap_header, data_len, cap_body)
        });
        Ok(())
    }
}
