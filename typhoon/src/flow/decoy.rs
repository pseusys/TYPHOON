use crate::bytes::ByteBuffer;
use crate::utils::sync::{channel, Receiver, Sender};

/// Commands sent to a decoy communication mode's event loop.
pub enum DecoyCommand {
    /// Feed a packet to the decoy mode for observation/interception.
    Feed {
        packet: ByteBuffer,
        tailor_len: usize,
        /// Response channel: Some((packet, tailor_len)) to proceed, None to suppress.
        response_tx: Sender<Option<(ByteBuffer, usize)>>,
    },
    /// Graceful shutdown.
    Shutdown,
}

/// Handle for communicating with a decoy mode.
/// Used by the flow controller to interact with the decoy.
#[derive(Clone)]
pub struct DecoyHandle {
    cmd_tx: Sender<DecoyCommand>,
}

impl DecoyHandle {
    pub(crate) fn new(cmd_tx: Sender<DecoyCommand>) -> Self {
        Self { cmd_tx }
    }

    /// Feed a packet to the decoy mode and wait for decision.
    /// Returns Some((packet, tailor_len)) to proceed with sending, None to suppress.
    pub async fn feed(&self, packet: ByteBuffer, tailor_len: usize) -> Option<(ByteBuffer, usize)> {
        let (response_tx, mut response_rx) = channel(1);
        if self.cmd_tx
            .send(DecoyCommand::Feed { packet, tailor_len, response_tx })
            .await
            .is_err()
        {
            return None;
        }
        response_rx.recv().await.flatten()
    }

    /// Request graceful shutdown of the decoy mode.
    pub async fn shutdown(&self) {
        let _ = self.cmd_tx.send(DecoyCommand::Shutdown).await;
    }
}

/// Sender for decoy packets to the flow controller.
/// Allows the decoy mode to inject packets into the flow.
pub struct DecoyPacketSender {
    packet_tx: Sender<(ByteBuffer, usize)>,
}

impl DecoyPacketSender {
    pub(crate) fn new(packet_tx: Sender<(ByteBuffer, usize)>) -> Self {
        Self { packet_tx }
    }

    /// Send a decoy packet to the flow controller.
    pub async fn send_decoy(&self, packet: ByteBuffer, tailor_len: usize) {
        let _ = self.packet_tx.send((packet, tailor_len)).await;
    }
}

/// Trait for decoy communication modes.
/// Implementations run their own event loop and communicate via channels.
///
/// TODO(decoy): Implement actual decoy traffic generation modes:
/// - `ConstantRateDecoyMode`: Send decoy packets at fixed intervals
/// - `AdaptiveDecoyMode`: Adjust decoy rate based on real traffic patterns
/// - `BurstDecoyMode`: Send bursts of decoys to mask traffic patterns
///
/// TODO(decoy): Decoy modes should use `DecoyPacketSender::send_decoy()` to inject
/// packets into the flow. Currently only `NoopDecoyMode` is implemented.
pub trait DecoyCommunicationMode: Sized + Send + 'static {
    /// Create a new decoy mode instance.
    /// - `cmd_rx`: Receiver for commands from the flow controller.
    /// - `decoy_packet_tx`: Sender to inject decoy packets into the flow.
    fn new(cmd_rx: Receiver<DecoyCommand>, decoy_packet_tx: DecoyPacketSender) -> Self;

    /// Run the decoy communication mode event loop. This should be spawned as a separate task.
    fn run(self) -> impl std::future::Future<Output = ()> + Send;
}

/// A simple pass-through decoy mode that does nothing.
/// All packets pass through unmodified, no decoy packets are generated.
pub struct NoopDecoyMode {
    cmd_rx: Receiver<DecoyCommand>,
    #[allow(dead_code)]
    decoy_packet_tx: DecoyPacketSender,
}

impl DecoyCommunicationMode for NoopDecoyMode {
    fn new(cmd_rx: Receiver<DecoyCommand>, decoy_packet_tx: DecoyPacketSender) -> Self {
        Self { cmd_rx, decoy_packet_tx }
    }

    async fn run(mut self) {
        loop {
            match self.cmd_rx.recv().await {
                Some(DecoyCommand::Feed { packet, tailor_len, response_tx }) => {
                    // Pass through all packets unmodified
                    let _ = response_tx.send(Some((packet, tailor_len))).await;
                }
                Some(DecoyCommand::Shutdown) | None => {
                    break;
                }
            }
        }
    }
}
