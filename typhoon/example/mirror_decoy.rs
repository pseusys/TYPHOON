use std::sync::atomic::{AtomicU32, Ordering};
/// Mirror-decoy example: asymmetric decoy strategies on client and server.
///
/// Demonstrates how to wire a **custom** `DecoyProvider` server-side while the client
/// uses a built-in provider.  Here:
///
///   server — `MirrorDecoyProvider`: a user-defined provider that sends one small decoy
///             for every incoming decoy packet it receives.
///   client — `SparseDecoyProvider`: generates sparse decoy traffic on a timer.
///
/// The asymmetry shows up in the per-flow plot: client-side decoy packets arrive
/// sporadically (timer-driven), while server-side decoy packets appear in tight
/// correspondence with each incoming packet (reaction-driven).
///
/// `MirrorDecoyProvider` is intentionally defined in this file rather than the library
/// to illustrate how users can build their own custom decoy strategies using only the
/// public API.
///
/// To generate the flow plot:
///   poe plot --example mirror_decoy
use std::sync::{Arc, Weak};
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
use typhoon::flow::decoy::{DecoyCommunicationMode, DecoyFlowSender, DecoyProvider, DerivedValue, IdentityType, PacketFlags, SparseDecoyProvider, Tailer, decoy_factory};
use typhoon::flow::{FakeBodyMode, FakeHeaderConfig, FlowConfig};
use typhoon::settings::consts::FG_OFFSET;
use typhoon::settings::keys::DECOY_LENGTH_MIN;
use typhoon::settings::{Settings, SettingsBuilder};
use typhoon::socket::{ClientSocketBuilder, ListenerBuilder, ServerFlowConfiguration};

const SERVER_ADDR: &str = "127.0.0.1:19992";

const MSG_COUNT: usize = 30;
const PAYLOAD_SIZE: usize = 512;
const INTER_MSG_MS: u64 = 40;

type Ident = typhoon::bytes::StaticByteBuffer;
type Exec = DefaultExecutor;

// ── Custom decoy provider ─────────────────────────────────────────────────────

/// Reaction-based decoy provider: sends one decoy packet back for every incoming decoy packet.  Intended for server-side use alongside a timer-driven client strategy such as `SparseDecoyProvider`.
/// `feed_input` calls `send_decoy_packet` synchronously and inline — this is safe.
struct MirrorDecoyProvider<T: IdentityType + Clone, AE: AsyncExecutor> {
    manager: Weak<dyn DecoyFlowSender>,
    settings: Arc<Settings<AE>>,
    identity: DerivedValue<T>,
    counter: Arc<AtomicU32>,
    fallthrough_probability: f64,
}

impl<T: IdentityType + Clone, AE: AsyncExecutor> MirrorDecoyProvider<T, AE> {
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

#[async_trait]
impl<T: IdentityType + Clone + 'static, AE: AsyncExecutor + 'static> DecoyProvider for MirrorDecoyProvider<T, AE> {
    fn name(&self) -> &'static str {
        "MirrorDecoyProvider"
    }

    async fn start(&self) {}

    async fn feed_input(&self, packet: DynamicByteBuffer, tailer_buf: DynamicByteBuffer) -> Option<DynamicByteBuffer> {
        let flags = PacketFlags::from_bits_truncate(*tailer_buf.get(FG_OFFSET));
        if flags.is_discardable() {
            let len = self.settings.get(&DECOY_LENGTH_MIN) as usize;
            let total = len + Tailer::<T>::len();
            let buf = self.settings.pool().allocate(Some(total));
            rand::thread_rng().fill(buf.slice_end_mut(len));
            Tailer::decoy(buf.rebuffer_start(len), &self.identity.get(), self.next_packet_number());
            if let Some(mgr) = self.manager.upgrade() {
                if let Err(err) = mgr.send_decoy_packet(buf, self.should_fallthrough(), false).await {
                    warn!("MirrorDecoyProvider: send failed: {err:?}");
                }
            }
        }
        Some(packet)
    }

    async fn feed_output(&self, body: DynamicByteBuffer, _tailer_buf: DynamicByteBuffer) -> Option<DynamicByteBuffer> {
        Some(body)
    }
}

impl<T: IdentityType + Clone + 'static, AE: AsyncExecutor + 'static> DecoyCommunicationMode<T, AE> for MirrorDecoyProvider<T, AE> {
    fn new(manager: Weak<dyn DecoyFlowSender>, settings: Arc<Settings<AE>>, identity: DerivedValue<T>, counter: Arc<AtomicU32>, fallthrough_probability: Option<f64>) -> Self {
        Self {
            manager,
            settings,
            identity,
            counter,
            fallthrough_probability: fallthrough_probability.unwrap_or(0.5),
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

    // Server uses the custom MirrorDecoyProvider: reacts to each incoming decoy with a decoy.
    let server_decoy = decoy_factory::<Ident, Exec, MirrorDecoyProvider<Ident, Exec>>();
    // Client uses the built-in SparseDecoyProvider: generates decoys on its own timer.
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
    println!("mirror_decoy done: {MSG_COUNT} round-trips complete.");
}
