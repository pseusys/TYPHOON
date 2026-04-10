/// Server-side flow manager implementation.
use std::collections::HashMap;
use std::hash::Hash;
use std::net::SocketAddr;
use std::sync::Arc;

use log::{debug, warn};
use rand::Rng;

use crate::bytes::{ByteBuffer, ByteBufferMut, DynamicByteBuffer};
use crate::crypto::ServerCryptoTool;
use crate::flow::common::FlowManager;
use crate::flow::config::{FakeBodyMode, FakeHeaderConfig, FlowConfig};
use crate::flow::decoy::{DecoyFlowSender, DecoyCommunicationMode};
use crate::flow::error::FlowControllerError;
use crate::settings::Settings;
use crate::settings::consts::TAILOR_LENGTH;
use crate::tailor::{IdentityType, PacketFlags, Tailor};
use crate::utils::random::get_rng;
use crate::utils::socket::Socket;
use crate::utils::sync::{AsyncExecutor, Mutex, RwLock};


/// Raw received packet from the server flow manager before session-level processing.
pub struct RawReceivedPacket<T: IdentityType> {
    /// The encrypted payload portion of the packet.
    pub body: DynamicByteBuffer,
    /// The decrypted tailor.
    pub tailor: Tailor<T>,
    /// The source address of the packet.
    pub source_addr: SocketAddr,
}

/// Server-side flow manager that handles per-user packet encryption, decoy traffic, and socket I/O.
/// Per-user crypto state is in the global SharedMap (accessed via ServerCryptoTool).
/// Send and receive crypto are split into independent instances so their locks never contend.
/// Per-user source addresses and decoy providers are local to each flow manager instance.
/// When built with multiple sockets (SO_REUSEPORT on Linux), each socket is polled by its own
/// drain task in the listener; the kernel distributes incoming datagrams across all sockets.
pub struct ServerFlowManager<T: IdentityType + Clone + Eq + Hash + Send + ToString, AE: AsyncExecutor, DP: Send + Sync> {
    user_addrs: RwLock<HashMap<T, SocketAddr>>,
    /// Per-user decoy providers behind individual locks so concurrent users don't contend.
    decoy_providers: RwLock<HashMap<T, Arc<Mutex<DP>>>>,
    crypto_send: Mutex<ServerCryptoTool<T>>,
    crypto_recv: Mutex<ServerCryptoTool<T>>,
    fake_body_mode: FakeBodyMode,
    fake_header_mode: Mutex<FakeHeaderConfig>,
    /// Precomputed worst-case prefix length: fake_header.len() + fake_body.max_len().
    /// Used to guard expand_start without locking fake_header_mode on every send.
    max_overhead: usize,
    socks: Vec<Arc<Socket>>,
    mtu: usize,
    settings: Arc<Settings<AE>>,
}

impl<T: IdentityType + Clone + Eq + Hash + Send + ToString + 'static, AE: AsyncExecutor + 'static, DP: DecoyCommunicationMode<T, AE> + 'static> ServerFlowManager<T, AE, DP> {
    /// Create a new server flow manager.
    /// `crypto_send` and `crypto_recv` must be independent instances (e.g. two `create_cache()` calls
    /// on the same `SharedMap`) so their mutexes never contend between the send and receive paths.
    /// `socks` must contain at least one socket; on Linux with SO_REUSEPORT multiple sockets may be
    /// supplied so that the listener can spawn one drain task per socket.
    pub fn new(config: FlowConfig, crypto_send: ServerCryptoTool<T>, crypto_recv: ServerCryptoTool<T>, settings: Arc<Settings<AE>>, socks: Vec<Arc<Socket>>) -> Arc<Self> {
        let max_overhead = config.max_overhead();
        Arc::new(ServerFlowManager {
            user_addrs: RwLock::new(HashMap::new()),
            decoy_providers: RwLock::new(HashMap::new()),
            crypto_send: Mutex::new(crypto_send),
            crypto_recv: Mutex::new(crypto_recv),
            fake_body_mode: config.fake_body_mode,
            fake_header_mode: Mutex::new(config.fake_header_mode),
            max_overhead,
            socks,
            mtu: settings.mtu(),
            settings,
        })
    }

    /// Return the slice of sockets owned by this flow manager.
    /// The listener spawns one drain task per socket so that all sockets are polled concurrently.
    pub(crate) fn recv_socks(&self) -> &[Arc<Socket>] {
        &self.socks
    }

    /// Register a user's source address for this flow manager.
    pub async fn register_user_addr(&self, id: T, addr: SocketAddr) {
        self.user_addrs.write().await.insert(id, addr);
    }

    /// Register a per-user decoy provider and start its background timer.
    /// The user's crypto state must already be in the global SharedMap.
    pub async fn register_user(self: &Arc<Self>, id: T) {
        let weak: std::sync::Weak<Self> = Arc::downgrade(self);
        let mgr: std::sync::Weak<dyn DecoyFlowSender> = weak;
        let mut dp = DP::new(mgr, self.settings.clone(), id.clone());
        dp.start().await;
        self.decoy_providers.write().await.insert(id, Arc::new(Mutex::new(dp)));
    }

    /// Remove a user's decoy provider from this flow manager.
    pub async fn remove_user(&self, id: &T) {
        self.decoy_providers.write().await.remove(id);
    }

    /// Receive a raw packet, deobfuscating the tailor but returning the full body + tailor view.
    /// For handshake packets, per-user verification is skipped (user not registered yet).
    /// Decoy packets are filtered. Non-handshake packets are verified per-user and fed to decoy providers.
    /// `sock` is the specific socket to read from; the caller (drain task) owns one socket per task.
    pub async fn receive_raw(&self, packet: DynamicByteBuffer, sock: &Socket) -> Result<RawReceivedPacket<T>, FlowControllerError> {
        let identity_len = T::length();
        let tailor_overhead = ServerCryptoTool::<T>::tailor_overhead();

        loop {
            let (packet, source_addr) = sock.recv_from(packet.clone()).await.map_err(FlowControllerError::SocketError)?;

            // Strip encrypted tailor from the end.
            let (encrypted_packet, encrypted_tailor) = packet.split_buf(packet.len() - identity_len - tailor_overhead);

            // Deobfuscate tailor, verify immediately for non-handshake packets (single lock scope).
            let tailor = {
                let mut crypto = self.crypto_recv.lock().await;
                let (tailor_buf, transcript) = match crypto.deobfuscate_tailor(encrypted_tailor, self.settings.pool()) {
                    Ok(result) => result,
                    Err(err) => {
                        warn!("server flow: tailor decryption failed from {}: {}", source_addr, err);
                        continue;
                    }
                };
                let tailor = Tailor::<T>::new(tailor_buf);
                if !tailor.flags().is_discardable() && !tailor.flags().contains(PacketFlags::HANDSHAKE) {
                    let identity = tailor.identity();
                    if let Err(err) = crypto.verify_tailor(&identity, transcript).await {
                        debug!("error verifying packet tailor: {}", err);
                        continue;
                    }
                }
                tailor
            };

            let packet_flags = tailor.flags();

            // Decoy packets are always discarded at flow level.
            if packet_flags.is_discardable() {
                continue;
            }

            let identity = tailor.identity();

            // For non-handshake packets, update address and feed decoy providers.
            if !packet_flags.contains(PacketFlags::HANDSHAKE) {
                // Update source address only if changed (NAT rebinding). Read-first avoids a
                // write lock on every packet, which would block concurrent send_packet reads.
                if self.user_addrs.read().await.get(&identity).copied() != Some(source_addr) {
                    self.user_addrs.write().await.insert(identity.clone(), source_addr);
                }

                // Feed the user's decoy provider (per-user lock, not global).
                let dp = self.decoy_providers.read().await.get(&identity).cloned();
                if let Some(dp) = dp {
                    let notified = dp.lock().await.feed_input(packet.clone()).await;
                    if notified.is_none() {
                        continue;
                    }
                }
            }

            // For handshake packets, strip fake header/body using payload_length so the
            // session layer receives only the raw handshake data.
            let body = if packet_flags.contains(PacketFlags::HANDSHAKE) {
                let payload_len = tailor.payload_length() as usize;
                encrypted_packet.rebuffer_start(encrypted_packet.len().saturating_sub(payload_len))
            } else {
                encrypted_packet
            };

            debug!("server flow: received {:?} packet from {}", packet_flags, source_addr);
            return Ok(RawReceivedPacket {
                body,
                tailor,
                source_addr,
            });
        }
    }
}

impl<T: IdentityType + Clone + Eq + Hash + Send + ToString + 'static, AE: AsyncExecutor + 'static, DP: DecoyCommunicationMode<T, AE> + 'static> FlowManager for ServerFlowManager<T, AE, DP> {
    async fn send_packet(&self, packet: DynamicByteBuffer, generated: bool) -> Result<(), FlowControllerError> {
        let identity_len = T::length();

        // Extract identity from the plaintext tailor at the end of the packet.
        let tailor_buf = packet.rebuffer_start(packet.len() - identity_len - TAILOR_LENGTH);
        let identity = ServerCryptoTool::<T>::extract_identity(&tailor_buf);

        // Feed decoy provider for rate tracking (per-user lock).
        let notified_packet = {
            let dp = self.decoy_providers.read().await.get(&identity).cloned();
            if let Some(dp) = dp {
                let notified = dp.lock().await.feed_output(packet, generated).await;
                match notified {
                    None => return Ok(()),
                    Some(p) => p,
                }
            } else {
                packet
            }
        };

        // Look up user address from this flow manager's local mapping.
        let addr = {
            let addrs = self.user_addrs.read().await;
            *addrs.get(&identity).ok_or_else(|| FlowControllerError::UserNotFound {
                identity: identity.to_string(),
            })?
        };

        // Ensure before_capacity for expand_start — same guard as prepare_outgoing in client flow.
        // Decoy packets use allocate_precise with subheader_len before_capacity (can be 0).
        let notified_packet = if notified_packet.before_capacity() < self.max_overhead {
            let staged = self.settings.pool().allocate_precise(
                notified_packet.len(), self.max_overhead, ServerCryptoTool::<T>::tailor_overhead());
            staged.slice_mut().copy_from_slice(notified_packet.slice());
            staged
        } else {
            notified_packet
        };

        // Split into data + tailor, encrypt tailor.
        let (packet_data, packet_tailor) = notified_packet.split_buf(notified_packet.len() - identity_len - TAILOR_LENGTH);
        let packet_flags = PacketFlags::from_bits_truncate(*packet_tailor.get(0));

        let encrypted_tailor = {
            let mut crypto = self.crypto_send.lock().await;
            crypto.obfuscate_tailor(packet_tailor, self.settings.pool()).await.map_err(FlowControllerError::TailorEncryption)?
        };
        let encrypted_packet = packet_data.expand_end(encrypted_tailor.len());

        // Add fake header and body (single lock scope: len + fill must be consistent).
        let full_packet = {
            let mut mode = self.fake_header_mode.lock().await;
            let fake_header_len = mode.len();
            let full_packet_len = fake_header_len + self.fake_body_mode.get_length(self.mtu, fake_header_len + encrypted_packet.len(), packet_flags.is_service());
            let full_packet = encrypted_packet.expand_start(full_packet_len);
            mode.fill(full_packet.rebuffer_end(fake_header_len));
            get_rng().fill(&mut full_packet.rebuffer_both(fake_header_len, full_packet_len));
            full_packet
        };

        debug!("server flow: sending {:?} packet to {}", packet_flags, addr);
        self.socks[0].send_to(full_packet, addr).await.map_err(FlowControllerError::SocketError)?;
        Ok(())
    }

    async fn receive_packet(&self, packet: DynamicByteBuffer) -> Result<DynamicByteBuffer, FlowControllerError> {
        let identity_len = T::length();
        // receive_raw handles decoy filtering, tailor verification, source-address updates,
        // and decoy-provider feeding. Loop only to skip the unlikely handshake case.
        loop {
            let raw = self.receive_raw(packet.clone(), &self.socks[0]).await?;
            if raw.tailor.flags().contains(PacketFlags::HANDSHAKE) {
                continue;
            }
            let payload_len = raw.tailor.payload_length() as usize;
            return Ok(raw.body.rebuffer_start(raw.body.len() - payload_len).expand_end(identity_len));
        }
    }
}
