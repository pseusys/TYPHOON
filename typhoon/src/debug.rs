//! Debug diagnostic tools: flow reachability, round-trip time, and throughput measurement.
//!
//! Available with the `debug` feature flag.
//!
//! Probe payload layout (first 16 bytes, followed by optional padding):
//!
//! | Offset | Size | Field | Description |
//! |--------|------|-------|-------------|
//! | 0      | 4    | sequence  | Global probe sequence number (big-endian u32) |
//! | 4      | 4    | phase_id  | Debug phase: 0=reachability, 1=rtt, 2=throughput (big-endian u32) |
//! | 8      | 8    | send_time | Send timestamp in milliseconds (big-endian u64) |
//! | 16     | …    | padding   | Random-length zero padding (throughput phase only) |

use std::sync::Arc;
use std::time::Duration;

use futures::future::{Either, select};
use log::{debug, info, trace};
use std::pin::pin;

use crate::bytes::StaticByteBuffer;
use crate::certificate::ClientCertificate;
use crate::defaults::{DefaultExecutor, DefaultSettings};
use crate::flow::config::{FakeBodyMode, FakeHeaderConfig, FlowConfig};
use crate::flow::decoy::SimpleDecoyProvider;
use crate::settings::keys;
use crate::socket::{ClientSocket, ClientSocketBuilder};
use crate::tailor::ClientConnectionHandler;
use crate::utils::sync::sleep;
use crate::utils::unix_timestamp_ms;

/// Phase identifier constants embedded in the lower 32 bits of the debug PN field.
pub const PHASE_REACHABILITY: u32 = 0;
pub const PHASE_RETURN_TIME: u32 = 1;
pub const PHASE_THROUGHPUT: u32 = 2;

/// Probe payload header size in bytes.
const PROBE_HEADER_SIZE: usize = 16;

// ── DebugMode ─────────────────────────────────────────────────────────────────

/// Selects which diagnostic phases `run_debug` executes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DebugMode {
    /// Verify that the handshake completes and one echo round-trip succeeds.
    Reachability,
    /// Measure round-trip time with a single small probe.
    ReturnTime,
    /// Measure throughput with `TYPHOON_DEBUG_PROBE_COUNT` large probes.
    Throughput,
    /// Run all three phases in sequence.
    All,
}

impl DebugMode {
    #[inline]
    fn run_reachability(self) -> bool {
        matches!(self, Self::Reachability | Self::All)
    }

    #[inline]
    fn run_rtt(self) -> bool {
        matches!(self, Self::ReturnTime | Self::All)
    }

    #[inline]
    fn run_throughput(self) -> bool {
        matches!(self, Self::Throughput | Self::All)
    }
}

// ── DebugResult ───────────────────────────────────────────────────────────────

/// Results from a `run_debug` call.
///
/// Fields are `None` for phases that were not selected or could not complete.
#[derive(Debug, Clone)]
pub struct DebugResult {
    /// Whether the handshake and one echo round-trip completed within the timeout.
    /// `None` if the reachability phase was not requested.
    pub reachable: Option<bool>,
    /// Measured round-trip time in milliseconds.
    /// `None` if the return-time phase was not requested or timed out.
    pub rtt_ms: Option<f64>,
    /// Measured throughput in bytes per second.
    /// `None` if the throughput phase was not requested.
    pub throughput_bps: Option<f64>,
    /// Total probe packets sent across all phases.
    pub packets_sent: usize,
    /// Total probe echo packets received across all phases.
    pub packets_received: usize,
}

// ── DebugClientConnectionHandler ─────────────────────────────────────────────

/// Client connection handler for debug probes.
///
/// Sends no initial data and uses a zero-filled version field.
pub struct DebugClientConnectionHandler;

impl ClientConnectionHandler for DebugClientConnectionHandler {
    fn initial_data(&self) -> StaticByteBuffer {
        StaticByteBuffer::from_slice(&[])
    }

    fn version(&self, length: usize) -> StaticByteBuffer {
        StaticByteBuffer::empty(length)
    }
}

// ── DebugServerConnectionHandler ─────────────────────────────────────────────

/// Server connection handler for debug mode.
///
/// Accepts every client regardless of version and generates a random identity.
/// Wire this up with a server-side echo loop — see `example/debug_probe.rs`.
#[cfg(feature = "server")]
pub struct DebugServerConnectionHandler;

#[cfg(feature = "server")]
impl crate::tailor::ServerConnectionHandler<StaticByteBuffer> for DebugServerConnectionHandler {
    fn generate(&self, _initial_data: &[u8]) -> StaticByteBuffer {
        use crate::bytes::ByteBuffer;
        use crate::settings::consts::DEFAULT_TYPHOON_ID_LENGTH;
        use crate::utils::random::{SupportRng, get_rng};
        StaticByteBuffer::from_slice(get_rng().random_byte_buffer::<DEFAULT_TYPHOON_ID_LENGTH>().slice())
    }

    fn initial_data(&self, _identity: &StaticByteBuffer) -> StaticByteBuffer {
        StaticByteBuffer::from_slice(&[])
    }

    fn verify_version(&self, _version_bytes: &[u8]) -> bool {
        true
    }
}

// ── Internal helpers ──────────────────────────────────────────────────────────

type DebugSocket = ClientSocket<StaticByteBuffer, DefaultExecutor, SimpleDecoyProvider, DebugClientConnectionHandler>;

/// Build a probe payload: 16-byte header + `extra` zero bytes of padding.
fn make_probe(phase: u32, sequence: u32, extra: usize) -> Vec<u8> {
    let mut buf = vec![0u8; PROBE_HEADER_SIZE + extra];
    buf[0..4].copy_from_slice(&sequence.to_be_bytes());
    buf[4..8].copy_from_slice(&phase.to_be_bytes());
    buf[8..16].copy_from_slice(&(unix_timestamp_ms() as u64).to_be_bytes());
    buf
}

/// Refresh the send timestamp in an already-allocated probe buffer and return it.
fn stamp_probe(buf: &mut Vec<u8>, sequence: u32) {
    buf[0..4].copy_from_slice(&sequence.to_be_bytes());
    buf[8..16].copy_from_slice(&(unix_timestamp_ms() as u64).to_be_bytes());
}

/// Parse send timestamp from an echo response (same offset as the probe).
fn parse_send_time(data: &[u8]) -> Option<u64> {
    data.get(8..16).and_then(|s| s.try_into().ok()).map(u64::from_be_bytes)
}

/// Receive one packet or time out after `timeout_ms` milliseconds.
async fn recv_or_timeout(socket: &DebugSocket, timeout_ms: u64) -> Option<Vec<u8>> {
    let recv_fut = pin!(socket.receive_bytes());
    let sleep_fut = pin!(sleep(Duration::from_millis(timeout_ms)));
    match select(recv_fut, sleep_fut).await {
        Either::Left((Ok(data), _)) => Some(data),
        _ => None,
    }
}

// ── run_debug ─────────────────────────────────────────────────────────────────

/// Run the debug diagnostic against a server described by `certificate`.
///
/// The server must echo all received data verbatim (use `DebugServerConnectionHandler`
/// together with a per-client echo loop — see `example/debug_probe.rs`).
///
/// Phases are executed in order: reachability → return time → throughput.
/// If connecting fails, all phases are skipped and `reachable` is set to `false`.
pub async fn run_debug(certificate: ClientCertificate, mode: DebugMode, settings: Arc<DefaultSettings>) -> DebugResult {
    let timeout_ms = settings.get(&keys::DEBUG_PROBE_TIMEOUT);
    let mut result = DebugResult {
        reachable: None,
        rtt_ms: None,
        throughput_bps: None,
        packets_sent: 0,
        packets_received: 0,
    };

    // Build client socket — if this fails the server is unreachable.
    // Use empty flow config for all addresses: fake body/header would prepend bytes that the
    // server's handshake parser cannot strip, causing a crypto overflow on decapsulation.
    let empty_config = FlowConfig::new(FakeBodyMode::Empty, FakeHeaderConfig::new(vec![]));
    let mut builder = ClientSocketBuilder::<StaticByteBuffer, DefaultExecutor, SimpleDecoyProvider, DebugClientConnectionHandler>::new(
        certificate.clone(),
        DebugClientConnectionHandler,
    )
    .with_settings(settings.clone());
    for &addr in certificate.addresses() {
        builder = builder.with_flow_config(addr, empty_config.clone());
    }
    let socket = match builder.build().await {
        Ok(s) => s,
        Err(_) => {
            if mode.run_reachability() {
                result.reachable = Some(false);
            }
            return result;
        }
    };

    // ── Reachability ─────────────────────────────────────────────────────────
    if mode.run_reachability() {
        info!("debug probe: reachability phase");
        let probe = make_probe(PHASE_REACHABILITY, 0, 0);
        result.packets_sent += 1;
        trace!("debug probe: sent reachability probe ({} bytes)", probe.len());
        if socket.send_bytes(&probe).await.is_ok() {
            if recv_or_timeout(&socket, timeout_ms).await.is_some() {
                result.packets_received += 1;
                result.reachable = Some(true);
                debug!("debug probe: reachability OK");
            } else {
                result.reachable = Some(false);
                debug!("debug probe: reachability timeout");
            }
        } else {
            result.reachable = Some(false);
        }
    }

    // ── Return time ───────────────────────────────────────────────────────────
    if mode.run_rtt() {
        info!("debug probe: return-time phase");
        let probe = make_probe(PHASE_RETURN_TIME, 0, 0);
        result.packets_sent += 1;
        trace!("debug probe: sent rtt probe ({} bytes)", probe.len());
        if socket.send_bytes(&probe).await.is_ok() {
            if let Some(response) = recv_or_timeout(&socket, timeout_ms).await {
                result.packets_received += 1;
                if let Some(send_time) = parse_send_time(&response) {
                    let rtt = unix_timestamp_ms().saturating_sub(send_time as u128);
                    result.rtt_ms = Some(rtt as f64);
                    debug!("debug probe: RTT={:.1}ms", rtt);
                }
            } else {
                debug!("debug probe: RTT probe timed out");
            }
        }
    }

    // ── Throughput ────────────────────────────────────────────────────────────
    if mode.run_throughput() {
        let probe_count = settings.get(&keys::DEBUG_PROBE_COUNT) as usize;
        let probe_size = settings.get(&keys::DEBUG_PROBE_SIZE) as usize;
        let max_data_payload = socket.max_data_payload();

        // send_bytes chunks each probe by max_data_payload; calculate expected echo count.
        let probe_payload_size = PROBE_HEADER_SIZE + probe_size;
        let chunks_per_probe = probe_payload_size.div_ceil(max_data_payload);
        let total_echo_packets = probe_count * chunks_per_probe;

        info!("debug probe: throughput phase — {} probe(s) × {}B payload, max_data_payload={}B → {} echo packet(s) expected",
            probe_count, probe_payload_size, max_data_payload, total_echo_packets);

        let mut probe_buf = make_probe(PHASE_THROUGHPUT, 0, probe_size);
        let start_ms = unix_timestamp_ms();

        for seq in 0..probe_count as u32 {
            stamp_probe(&mut probe_buf, seq);
            // packets_sent counts UDP wire packets (chunks), not logical probes, so it is
            // comparable to packets_received which also counts individual UDP echo packets.
            result.packets_sent += chunks_per_probe;
            trace!("debug probe: sending throughput probe seq={} ({} UDP packet(s))", seq, chunks_per_probe);
            if socket.send_bytes(&probe_buf).await.is_err() {
                debug!("debug probe: send error on seq={}, aborting", seq);
                break;
            }
        }

        let mut received_bytes: usize = 0;
        for i in 0..total_echo_packets {
            if let Some(response) = recv_or_timeout(&socket, timeout_ms).await {
                result.packets_received += 1;
                received_bytes += response.len();
                trace!("debug probe: echo {}/{} ({} bytes, total {}B)", i + 1, total_echo_packets, response.len(), received_bytes);
            } else {
                debug!("debug probe: echo {}/{} timed out", i + 1, total_echo_packets);
            }
        }

        let elapsed_ms = unix_timestamp_ms().saturating_sub(start_ms);
        info!("debug probe: throughput summary — sent {} UDP packet(s), received {} / {} echo(s) ({:.1}% delivery)",
            result.packets_sent, result.packets_received, total_echo_packets,
            100.0 * result.packets_received as f64 / total_echo_packets as f64);
        if elapsed_ms > 0 && received_bytes > 0 {
            let bps = received_bytes as f64 / (elapsed_ms as f64 / 1000.0);
            result.throughput_bps = Some(bps);
            info!("debug probe: throughput={}B/s ({} bytes in {}ms)", bps as u64, received_bytes, elapsed_ms);
        }
    }

    result
}
