/// Flat-IAT decoy example: a custom decoy provider that intentionally breaks
/// PROTOCOL.md §"data best-effort delivery" to demonstrate the custom-provider
/// re-injection capability documented in §458-459.
///
/// The provider holds real DATA packets in an internal FIFO queue and a
/// background timer task drains the queue at a fixed inter-arrival time —
/// emitting exactly one queued real packet per tick, or a fresh random decoy
/// when the queue is empty.  The resulting wire flow has a perfectly flat
/// per-direction IAT regardless of when the application actually called
/// `send_bytes`, at the cost of added latency for each real packet.
///
/// This shows two things at once:
///   1. The `feed_output` → `None` + `send_decoy_packet` chain is the
///      sanctioned way to defer real traffic.  The plaintext tailor is
///      preserved across the round-trip, so the re-injected packet's DATA
///      flag survives and the receiver processes it as data, not as a decoy.
///   2. The flat-IAT pattern is *visible* in the per-flow plot: the
///      client-side bursty c2s sends (40 ms cadence) get serialised into a
///      strict 100 ms-spaced server-side queue, with the queue depth
///      bleeding off across the run.
///
/// Layout: server runs `FlatIatDecoyProvider`, client runs the built-in
/// `SparseDecoyProvider` (timer-driven decoys with no queueing).  The
/// asymmetry highlights how a single side can unilaterally re-shape its
/// outgoing IAT distribution without protocol-level coordination.
///
/// To generate the flow plot:
///   poe plot --example flat_iat_decoy
use std::collections::{HashSet, VecDeque};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[cfg(feature = "async-std")]
use async_io::Timer;
use async_trait::async_trait;
use env_logger::init;
use futures::channel::oneshot::channel;
#[cfg(not(feature = "tokio"))]
use futures::executor::block_on;
use log::warn;
use rand::Rng;
#[cfg(feature = "tokio")]
use tokio::runtime::Runtime;
#[cfg(feature = "tokio")]
use tokio::time::sleep;
use typhoon::bytes::{ByteBuffer, ByteBufferMut, DynamicByteBuffer};
use typhoon::certificate::ServerKeyPair;
use typhoon::defaults::{AsyncExecutor, DefaultClientConnectionHandler, DefaultExecutor, DefaultServerConnectionHandler};
use typhoon::flow::decoy::{DecoyCommunicationMode, DecoyFlowSender, DecoyProvider, IdentityType, PacketFlags, SparseDecoyProvider, Tailor, decoy_factory};
use typhoon::flow::{FakeBodyMode, FakeHeaderConfig, FlowConfig};
use typhoon::settings::consts::{FG_OFFSET, PN_OFFSET};
use typhoon::settings::{Settings, SettingsBuilder};
use typhoon::socket::{ClientSocketBuilder, ListenerBuilder, ServerFlowConfiguration};

const SERVER_ADDR: &str = "127.0.0.1:19993";

const MSG_COUNT: usize = 30;
const PAYLOAD_SIZE: usize = 512;
/// Client send cadence — bursty by demo standards, exercises the queue.
const INTER_MSG_MS: u64 = 40;
/// Server-side flat IAT — slower than the client's send rate so real packets
/// visibly queue up before being drained at this fixed pace.
const FLAT_IAT_MS: u64 = 100;
/// Length of a synthesised random decoy when the queue is empty at tick time.
const RANDOM_DECOY_BODY_LEN: usize = 96;

type Ident = typhoon::bytes::StaticByteBuffer;
type Exec = DefaultExecutor;

// ── Custom decoy provider ─────────────────────────────────────────────────────

/// Queues real DATA packets and emits at a strict fixed rate from a timer task.
/// When the queue is empty at tick time, emits a fresh random decoy instead.
///
/// Shared mutable state (`queue` + `packet_number`) lives behind an
/// `Arc<Mutex<…>>` because the timer task and `feed_output` run on
/// independent task contexts.  `DynamicByteBuffer` is `Send + !Sync`, so
/// `Mutex<VecDeque<DynamicByteBuffer>>` is the right primitive: the mutex
/// enforces single-thread access while letting the contained buffers move
/// between the producer (feed_output) and consumer (timer task).
struct FlatIatDecoyProvider<T: IdentityType + Clone, AE: AsyncExecutor> {
    manager: Weak<dyn DecoyFlowSender>,
    settings: Arc<Settings<AE>>,
    identity: T,
    state: Arc<Mutex<FlatIatState>>,
}

struct FlatIatState {
    /// FIFO of (PN, body || plaintext-tailor) entries held back from immediate
    /// send.  Re-injection preserves the original tailor (including the DATA
    /// flag), so the receiver still processes each entry as a real data
    /// packet.  The PN is stashed alongside the buffer so the timer task can
    /// mark it in `reinjected` without re-parsing the tailor.
    queue: VecDeque<(u64, DynamicByteBuffer)>,
    /// PNs of real packets currently being re-injected via `send_decoy_packet`.
    /// `feed_output` consults this set to distinguish a re-injection (pass
    /// straight through) from a fresh app-level send (queue and drop).
    /// Without this guard, every re-injection would loop back into the queue.
    reinjected: HashSet<u64>,
    counter: Arc<AtomicU32>,
    fallthrough_probability: f64,
}

impl FlatIatState {
    fn next_packet_number(&self) -> u64 {
        let counter = self.counter.fetch_add(1, Ordering::Relaxed).wrapping_add(1);
        let now_millis = SystemTime::now().duration_since(UNIX_EPOCH).expect("Time went backwards").as_millis();
        let timestamp = (now_millis / 1000) as u32;
        ((timestamp as u64) << 32) | counter as u64
    }

    fn should_fallthrough(&self) -> bool {
        if self.fallthrough_probability <= 0.0 {
            false
        } else if self.fallthrough_probability >= 1.0 {
            true
        } else {
            rand::thread_rng().r#gen::<f64>() < self.fallthrough_probability
        }
    }
}

impl<T: IdentityType + Clone + 'static, AE: AsyncExecutor + 'static> FlatIatDecoyProvider<T, AE> {
    async fn timer_task(manager: Weak<dyn DecoyFlowSender>, settings: Arc<Settings<AE>>, identity: T, state: Arc<Mutex<FlatIatState>>) {
        loop {
            sleep_ms(FLAT_IAT_MS).await;
            let Some(manager_arc) = manager.upgrade() else {
                warn!("FlatIatDecoyProvider: manager dropped, stopping timer");
                break;
            };

            // Either pop one held-back real packet, or synthesise a fresh decoy.
            // The lock is dropped before the await so the producer (feed_output)
            // can keep pushing during the network send.  For real packets the
            // PN is recorded in `reinjected` *before* send_decoy_packet runs,
            // so the re-entrant feed_output call later sees the marker and
            // passes the packet through instead of looping it back into the queue.
            let (packet, fallthrough) = {
                let mut guard = state.lock().expect("FlatIatDecoyProvider mutex poisoned");
                let packet = if let Some((pn, real_packet)) = guard.queue.pop_front() {
                    guard.reinjected.insert(pn);
                    real_packet
                } else {
                    let body_len = RANDOM_DECOY_BODY_LEN;
                    let total = body_len + Tailor::<T>::len();
                    let buf = settings.pool().allocate(Some(total));
                    rand::thread_rng().fill(buf.slice_end_mut(body_len));
                    Tailor::decoy(buf.rebuffer_start(body_len), &identity, guard.next_packet_number());
                    buf
                };
                (packet, guard.should_fallthrough())
            };

            if let Err(err) = manager_arc.send_decoy_packet(packet, fallthrough, false).await {
                warn!("FlatIatDecoyProvider: send failed: {err:?}");
            }
        }
    }
}

#[async_trait]
impl<T: IdentityType + Clone + 'static, AE: AsyncExecutor + 'static> DecoyProvider for FlatIatDecoyProvider<T, AE> {
    fn name(&self) -> &'static str {
        "FlatIatDecoyProvider"
    }

    async fn start(&mut self) {
        let executor = self.settings.executor().clone();
        let manager = self.manager.clone();
        let settings = self.settings.clone();
        let identity = self.identity.clone();
        let state = self.state.clone();
        executor.spawn(Self::timer_task(manager, settings, identity, state));
    }

    async fn feed_input(&mut self, packet: DynamicByteBuffer, _tailor_buf: DynamicByteBuffer) -> Option<DynamicByteBuffer> {
        Some(packet)
    }

    async fn feed_output(&mut self, body: DynamicByteBuffer, tailor_buf: DynamicByteBuffer) -> Option<DynamicByteBuffer> {
        let flags = PacketFlags::from_bits_truncate(*tailor_buf.get(FG_OFFSET));
        // Pass decoy / termination packets through unchanged; only
        // buffer real DATA.  Terminations especially must not queue: the
        // session-cleanup task sends termination then removes the user, so a
        // queued termination would be stranded when the next timer tick fires.
        if flags.is_discardable() || flags.is_termination() {
            return Some(body);
        }
        let pn_bytes: [u8; 8] = tailor_buf.slice()[PN_OFFSET..PN_OFFSET + 8].try_into().expect("8-byte PN");
        let pn = u64::from_be_bytes(pn_bytes);
        let mut state = self.state.lock().expect("FlatIatDecoyProvider mutex poisoned");
        // Re-injection from the timer task — the PN was marked just before
        // send_decoy_packet was called.  Drop the marker and forward the body
        // unchanged so send_packet can encrypt and ship it.
        if state.reinjected.remove(&pn) {
            return Some(body);
        }
        // Fresh app-level send: stash (body || plaintext-tailor) for the timer.
        // `body` and `tailor_buf` are two adjacent views into the same backing
        // allocation (split by `prepare_outgoing`).  Stretching body's end by
        // `tailor_buf.len()` re-covers the tailor in place — no copy, no
        // self-overlap UB that `append_buf` would trigger.
        let combined = body.expand_end(tailor_buf.len());
        state.queue.push_back((pn, combined));
        None
    }
}

impl<T: IdentityType + Clone + 'static, AE: AsyncExecutor + 'static> DecoyCommunicationMode<T, AE> for FlatIatDecoyProvider<T, AE> {
    fn new(manager: Weak<dyn DecoyFlowSender>, settings: Arc<Settings<AE>>, identity: T, counter: Arc<AtomicU32>, fallthrough_probability: Option<f64>) -> Self {
        Self {
            manager,
            settings,
            identity,
            state: Arc::new(Mutex::new(FlatIatState {
                queue: VecDeque::new(),
                reinjected: HashSet::new(),
                counter,
                fallthrough_probability: fallthrough_probability.unwrap_or(0.5),
            })),
        }
    }
}

// ── Runtime boilerplate ───────────────────────────────────────────────────────

#[cfg(feature = "tokio")]
fn main() {
    Runtime::new().expect("tokio runtime").block_on(run());
}

#[cfg(not(feature = "tokio"))]
fn main() {
    block_on(run());
}

#[cfg(feature = "tokio")]
async fn sleep_ms(ms: u64) {
    sleep(Duration::from_millis(ms)).await;
}

#[cfg(feature = "async-std")]
async fn sleep_ms(ms: u64) {
    Timer::after(Duration::from_millis(ms)).await;
}

async fn run() {
    init();

    let settings = Arc::new(SettingsBuilder::<Exec>::new().build().expect("settings"));
    let server_addr = SERVER_ADDR.parse().expect("valid address");

    let flow_config = FlowConfig::new(
        FakeBodyMode::Random {
            min_length: 64,
            max_length: 256,
            service: true,
        },
        FakeHeaderConfig::new(vec![]),
    );

    // Server uses the custom FlatIatDecoyProvider: queue real data, drip at FLAT_IAT_MS.
    let server_decoy = decoy_factory::<Ident, Exec, FlatIatDecoyProvider<Ident, Exec>>();
    // Client uses the built-in SparseDecoyProvider: timer-driven decoys, no queueing.
    let client_decoy = decoy_factory::<Ident, Exec, SparseDecoyProvider<Ident, Exec>>();

    let key_pair = ServerKeyPair::generate();
    let certificate = key_pair.to_client_certificate(vec![server_addr]);

    let server_flow = ServerFlowConfiguration::<Ident, Exec>::with_address(flow_config.clone(), server_addr).with_decoy_factory(server_decoy);

    let listener: Arc<_> = Arc::new(ListenerBuilder::<Ident, Exec, DefaultServerConnectionHandler>::new(key_pair, DefaultServerConnectionHandler).add_flow(server_flow).with_settings(settings.clone()).build().await.expect("listener"));
    listener.start().await;

    let (done_tx, done_rx) = channel::<usize>();
    let listener_handle = listener.clone();
    settings.executor().spawn(async move {
        let conn = listener_handle.accept().await.expect("accept");
        let mut count = 0;
        while count < MSG_COUNT {
            let data = conn.receive_bytes().await.expect("recv");
            conn.send_bytes(&data).await.expect("echo");
            count += 1;
        }
        // Hold `conn` alive long enough for the flat-IAT queue to drain its
        // last few echoes.  Dropping `conn` here would immediately spawn the
        // session-cleanup task, which removes the user from `user_addrs`
        // before the timer task can re-inject the tail of the queue.
        sleep_ms(FLAT_IAT_MS * 4).await;
        let _ = done_tx.send(count);
    });

    let socket = ClientSocketBuilder::<Ident, Exec, DefaultClientConnectionHandler>::new(certificate, DefaultClientConnectionHandler).with_settings(settings.clone()).with_decoy_factory(client_decoy).with_flow_config(server_addr, flow_config).build().await.expect("client socket");

    let payload = vec![0xABu8; PAYLOAD_SIZE];
    for _ in 0..MSG_COUNT {
        socket.send_bytes(&payload).await.expect("send");
        socket.receive_bytes().await.expect("receive echo");
        sleep_ms(INTER_MSG_MS).await;
    }

    done_rx.await.expect("server task");
    println!("flat_iat_decoy done: {MSG_COUNT} round-trips complete.");
}
