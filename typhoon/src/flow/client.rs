use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use log::{debug, info};
use rand::Rng;

use crate::bytes::ByteBuffer;
use crate::cache::CachedValue;
use crate::crypto::ClientCryptoTool;
use crate::flow::common::{FlowCommand, FlowHandle, FlowSpawnResult, ReceivedPacket};
use crate::flow::config::FlowConfig;
use crate::flow::decoy::{DecoyHandle, DecoyCommunicationMode, DecoyPacketSender};
use crate::flow::error::FlowControllerError;
use crate::tailor::{PacketFlags, Tailor};
use crate::utils::random::get_rng;
use crate::utils::socket::Socket;
use crate::utils::sync::{channel, spawn, Receiver, Sender};

/// Client-side flow controller that runs separate send and receive loops.
pub struct ClientFlowController<'a> {
    provider: CachedValue<ClientCryptoTool<'a>>,
    config: FlowConfig,
    sock: Arc<Socket>,
    mtu: usize,
    tailor_len: usize,
    decoy: DecoyHandle,
}

impl<'a: 'static> ClientFlowController<'a> {
    /// Spawn a new client flow controller and return the handle and packet receiver.
    pub async fn spawn<DP: DecoyCommunicationMode>(
        config: FlowConfig,
        cipher: CachedValue<ClientCryptoTool<'a>>,
        mtu: usize,
        sock: Socket,
        tailor_len: usize,
    ) -> Result<FlowSpawnResult, FlowControllerError> {
        let (cmd_tx, cmd_rx) = channel(32);
        let handle = FlowHandle::new(cmd_tx);

        let (packet_tx, packet_rx) = channel(32);

        let (decoy_cmd_tx, decoy_cmd_rx) = channel(32);
        let (decoy_packet_tx, decoy_packet_rx) = channel(32);
        let decoy_handle = DecoyHandle::new(decoy_cmd_tx);
        let decoy_packet_sender = DecoyPacketSender::new(decoy_packet_tx);

        let decoy_mode = DP::new(decoy_cmd_rx, decoy_packet_sender);
        spawn(decoy_mode.run());

        let sock = Arc::new(sock);

        let recv_cipher = cipher
            .create_sibling()
            .await
            .map_err(|e| FlowControllerError::MissingCache(e))?;

        let controller = Self {
            provider: cipher,
            config,
            sock,
            mtu,
            tailor_len,
            decoy: decoy_handle,
        };

        let shutdown_flag = Arc::new(AtomicBool::new(false));

        let recv_sock = controller.sock.clone();
        let recv_mtu = controller.mtu;
        let recv_tailor_len = controller.tailor_len;

        spawn(controller.run_send_loop(cmd_rx, decoy_packet_rx, shutdown_flag.clone()));

        spawn(Self::run_receive_loop(
            recv_sock,
            recv_cipher,
            recv_mtu,
            recv_tailor_len,
            packet_tx,
            shutdown_flag,
        ));

        Ok(FlowSpawnResult { handle, packet_rx })
    }

    async fn run_send_loop(
        mut self,
        mut cmd_rx: Receiver<FlowCommand>,
        mut decoy_packet_rx: Receiver<(ByteBuffer, usize)>,
        shutdown_flag: Arc<AtomicBool>,
    ) {
        loop {
            tokio::select! {
                cmd = cmd_rx.recv() => {
                    match cmd {
                        Some(FlowCommand::SendPacket { packet, tailor_len, response_tx }) => {
                            let result = self.handle_send_packet(packet, tailor_len).await;
                            let _ = response_tx.send(result);
                        }
                        Some(FlowCommand::Shutdown) => {
                            debug!("flow controller received shutdown command");
                            break;
                        }
                        None => {
                            debug!("flow controller command channel closed");
                            break;
                        }
                    }
                }
                decoy = decoy_packet_rx.recv() => {
                    if let Some((packet, tailor_len)) = decoy {
                        let _ = self.handle_send_packet_internal(packet, tailor_len).await;
                    }
                }
            }
        }

        shutdown_flag.store(true, Ordering::SeqCst);
        self.decoy.shutdown().await;
    }

    async fn run_receive_loop(
        sock: Arc<Socket>,
        mut provider: CachedValue<ClientCryptoTool<'a>>,
        mtu: usize,
        tailor_len: usize,
        packet_tx: Sender<ReceivedPacket>,
        shutdown_flag: Arc<AtomicBool>,
    ) {
        let recv_buffer = ByteBuffer::empty_with_capacity(mtu, 0, 0);
        let tailor_overhead = ClientCryptoTool::tailor_overhead();

        loop {
            if shutdown_flag.load(Ordering::SeqCst) {
                debug!("flow receive loop: shutdown flag set");
                break;
            }

            match sock.recv(recv_buffer.clone()).await {
                Ok(packet) => {
                    if let Some(received) =
                        Self::process_received_packet(&mut provider, packet, tailor_len, tailor_overhead).await
                    {
                        if packet_tx.send(received).await.is_err() {
                            debug!("flow receive loop: packet receiver closed");
                            break;
                        }
                    }
                }
                Err(err) => {
                    debug!("flow receive loop: socket receive error: {}", err);
                }
            }
        }
    }

    async fn process_received_packet(
        provider: &mut CachedValue<ClientCryptoTool<'a>>,
        packet: ByteBuffer,
        tailor_len: usize,
        tailor_overhead: usize,
    ) -> Option<ReceivedPacket> {
        if packet.len() < tailor_len + tailor_overhead {
            debug!("received packet too short");
            return None;
        }

        let (encrypted_packet, encrypted_tailor) =
            packet.split_buf(packet.len() - tailor_len - tailor_overhead);

        let cipher = provider.get_mut().await;
        let tailor = match cipher.deobfuscate_tailor(encrypted_tailor) {
            Ok((tailor, transcript)) => match cipher.verify_tailor(transcript) {
                Ok(_) => tailor,
                Err(err) => {
                    debug!("error verifying packet tailor: {}", err);
                    return None;
                }
            },
            Err(err) => {
                debug!("error decrypting packet tailor: {}", err);
                return None;
            }
        };

        let packet_flags = PacketFlags::from_bits_truncate(tailor.get(0).clone());
        if packet_flags.is_discardable() {
            info!("decoy packet received, skipping...");
            return None;
        }

        let payload_len = Tailor::get_payload_length(&tailor) as usize;
        let result_packet = encrypted_packet
            .rebuffer_start(encrypted_packet.len() - payload_len)
            .expand_end(tailor_len);

        Some(ReceivedPacket {
            packet: result_packet,
            tailor_len,
        })
    }

    async fn handle_send_packet(
        &mut self,
        packet: ByteBuffer,
        tailor_len: usize,
    ) -> Result<(), FlowControllerError> {
        let notified = self.decoy.feed(packet, tailor_len).await;
        if notified.is_none() {
            return Ok(());
        }

        let (packet, tailor_len) = notified.unwrap();
        self.handle_send_packet_internal(packet, tailor_len).await
    }

    async fn handle_send_packet_internal(
        &mut self,
        packet: ByteBuffer,
        tailor_len: usize,
    ) -> Result<(), FlowControllerError> {
        let (packet_data, packet_tailor) = packet.split_buf(packet.len() - tailor_len);
        let packet_flags = PacketFlags::from_bits_truncate(packet_tailor.get(0).clone());

        let cipher = self.provider.get_mut().await;
        let encrypted_packet = match cipher.obfuscate_tailor(packet_tailor) {
            Ok(res) => packet_data.expand_end(res.len()),
            Err(err) => return Err(FlowControllerError::TailorEncryption(err)),
        };

        let fake_header_len = self.config.fake_header_mode.len();
        let full_packet_len = fake_header_len
            + self.config.fake_body_mode.get_length(
                self.mtu,
                fake_header_len + encrypted_packet.len(),
                packet_flags.is_service(),
            );
        let full_packet = encrypted_packet.expand_start(full_packet_len);

        self.config
            .fake_header_mode
            .fill(full_packet.rebuffer_end(fake_header_len));
        get_rng().fill(&mut full_packet.rebuffer_both(fake_header_len, full_packet_len));

        match self.sock.send(full_packet).await {
            Ok(_) => Ok(()),
            Err(err) => Err(FlowControllerError::SocketError(err)),
        }
    }
}
