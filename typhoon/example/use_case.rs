/// Use-case example: demonstrates five TYPHOON traffic profiles via TYPHOON_USE_CASE env var.
///
/// throughput  — Empty body, Simple decoy:    minimal overhead, maximum throughput
/// interactive — Small random body, Sparse decoy: light padding for interactive traffic
/// transparent — Constant 1024B body + HTTP-like header, Smooth decoy: constant-rate mimicry
/// security    — Large random body + 32B random header, Heavy decoy: entropy-first
/// default     — Random config drawn from the distribution (mirrors normal TYPHOON behaviour)
///
/// Traffic shape is controlled by two independent env flags:
///   TYPHOON_RANDOM_PAYLOAD — randomise each message size between PAYLOAD_MIN and PAYLOAD_MAX
///   TYPHOON_RANDOM_WAIT    — randomise the inter-cluster pause (otherwise fixed INTER_CLUSTER_MS)
///
/// Messages are sent in clusters of CLUSTER_SIZE with INTRA_CLUSTER_MS delay between messages
/// inside a cluster and a longer inter-cluster pause, forming realistic burst-and-pause traffic.
use std::sync::Arc;
use std::time::Duration;

#[cfg(feature = "async-std")]
use async_io::Timer;
use env_logger::init;
use futures::channel::oneshot::channel;
#[cfg(not(feature = "tokio"))]
use futures::executor::block_on;
use rand::Rng;
#[cfg(feature = "tokio")]
use tokio::runtime::Runtime;
#[cfg(feature = "tokio")]
use tokio::time::sleep;
use typhoon::bytes::StaticByteBuffer;
use typhoon::certificate::ServerKeyPair;
use typhoon::defaults::{AsyncExecutor, DefaultClientConnectionHandler, DefaultExecutor, DefaultServerConnectionHandler};
use typhoon::flow::decoy::{DecoyFactory, HeavyDecoyProvider, SimpleDecoyProvider, SmoothDecoyProvider, SparseDecoyProvider, decoy_factory, random_decoy_factory};
use typhoon::flow::{FakeBodyMode, FakeHeaderConfig, FieldType, FieldTypeHolder, FlowConfig};
use typhoon::settings::SettingsBuilder;
use typhoon::socket::{ClientSocketBuilder, ServerBuilder, ServerFlowConfiguration};

const SERVER_ADDR: &str = "127.0.0.1:19991";

/// Total number of application messages (data round-trips).
const MSG_COUNT: usize = 100;
/// Number of messages sent in one burst before the inter-cluster pause.
const CLUSTER_SIZE: usize = 10;
/// Fixed delay between consecutive messages inside a cluster when TYPHOON_RANDOM_WAIT is not set (ms).
const INTRA_CLUSTER_MS: u64 = 5;
/// Minimum per-packet delay inside a cluster used when TYPHOON_RANDOM_WAIT is set (ms).
const INTRA_CLUSTER_MIN_MS: u64 = 5;
/// Maximum per-packet delay inside a cluster used when TYPHOON_RANDOM_WAIT is set (ms).
const INTRA_CLUSTER_MAX_MS: u64 = 50;
/// Fixed inter-cluster pause used when TYPHOON_RANDOM_WAIT is not set (ms).
const INTER_CLUSTER_MS: u64 = 200;

/// Fixed payload size when TYPHOON_RANDOM_PAYLOAD is not set.
const PAYLOAD_FIXED: usize = 1024;
/// Minimum random payload size.
const PAYLOAD_MIN: usize = 64;
/// Maximum random payload size (capped further by socket.max_data_payload()).
const PAYLOAD_MAX: usize = 2048;

type Ident = StaticByteBuffer;
type Exec = DefaultExecutor;

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

    let use_case = std::env::var("TYPHOON_USE_CASE").unwrap_or_else(|_| "default".to_string());
    let random_payload = std::env::var("TYPHOON_RANDOM_PAYLOAD").is_ok();
    let random_wait = std::env::var("TYPHOON_RANDOM_WAIT").is_ok();

    let (flow_config, decoy): (FlowConfig, DecoyFactory<Ident, Exec>) = match use_case.as_str() {
        "throughput" => (FlowConfig::new(FakeBodyMode::Empty, FakeHeaderConfig::new(vec![])), decoy_factory::<Ident, Exec, SimpleDecoyProvider>()),
        "interactive" => (
            FlowConfig::new(
                FakeBodyMode::Random {
                    min_length: 8,
                    max_length: 64,
                    service: true,
                },
                FakeHeaderConfig::new(vec![]),
            ),
            decoy_factory::<Ident, Exec, SparseDecoyProvider<Ident, Exec>>(),
        ),
        "transparent" => (
            FlowConfig::new(
                FakeBodyMode::Constant {
                    packet_length: 1024,
                },
                FakeHeaderConfig::new(vec![
                    FieldTypeHolder::U32(FieldType::Constant {
                        value: 0x48545450u32,
                    }),
                    FieldTypeHolder::U32(FieldType::Incremental {
                        value: 0u32,
                    }),
                ]),
            ),
            decoy_factory::<Ident, Exec, SmoothDecoyProvider<Ident, Exec>>(),
        ),
        "security" => (
            FlowConfig::new(
                FakeBodyMode::Random {
                    min_length: 256,
                    max_length: 1024,
                    service: false,
                },
                FakeHeaderConfig::new(vec![FieldTypeHolder::U64(FieldType::Random), FieldTypeHolder::U64(FieldType::Random), FieldTypeHolder::U64(FieldType::Random), FieldTypeHolder::U64(FieldType::Random)]),
            ),
            decoy_factory::<Ident, Exec, HeavyDecoyProvider<Ident, Exec>>(),
        ),
        _ => (FlowConfig::random(&settings), random_decoy_factory::<Ident, Exec>()),
    };

    let key_pair = ServerKeyPair::generate();
    let certificate = key_pair.to_client_certificate(vec![server_addr]);

    let server_flow = ServerFlowConfiguration::<Ident, Exec>::with_address(flow_config.clone(), server_addr).with_decoy_factory(decoy.clone());

    let listener: Arc<_> = Arc::new(ServerBuilder::<Ident, Exec, DefaultServerConnectionHandler>::new(key_pair, DefaultServerConnectionHandler).add_flow(server_flow).with_settings(settings.clone()).build_listener().await.expect("listener"));
    listener.start().await;

    let (done_tx, done_rx) = channel::<usize>();
    let listener_handle = listener.clone();
    let server_random_wait = random_wait;
    settings.executor().spawn(async move {
        let conn = listener_handle.accept().await.expect("accept");
        let mut count = 0;
        while count < MSG_COUNT {
            let data = conn.receive_bytes().await.expect("recv");
            if server_random_wait {
                let delay = rand::thread_rng().gen_range(INTRA_CLUSTER_MIN_MS..=INTRA_CLUSTER_MAX_MS);
                sleep_ms(delay).await;
            }
            conn.send_bytes(&data).await.expect("echo");
            count += 1;
        }
        let _ = done_tx.send(count);
    });

    let socket = ClientSocketBuilder::<Ident, Exec, DefaultClientConnectionHandler>::new(certificate, DefaultClientConnectionHandler).with_settings(settings.clone()).with_decoy_factory(decoy).with_flow_config(server_addr, flow_config).build().await.expect("client socket");

    let max_payload = socket.max_data_payload();
    let cap = if random_payload {
        max_payload.min(PAYLOAD_MAX)
    } else {
        PAYLOAD_FIXED.min(max_payload)
    };
    let mut rng = rand::thread_rng();

    let clusters = MSG_COUNT / CLUSTER_SIZE;
    for cluster_idx in 0..clusters {
        for msg_idx in 0..CLUSTER_SIZE {
            let size = if random_payload {
                rng.gen_range(PAYLOAD_MIN..=cap)
            } else {
                cap
            };
            let payload: Vec<u8> = (0..size).map(|j| (j % 256) as u8).collect();
            socket.send_bytes(&payload).await.expect("send");
            socket.receive_bytes().await.expect("receive echo");
            if random_wait {
                sleep_ms(rng.gen_range(INTRA_CLUSTER_MIN_MS..=INTRA_CLUSTER_MAX_MS)).await;
            } else if msg_idx + 1 < CLUSTER_SIZE {
                sleep_ms(INTRA_CLUSTER_MS).await;
            }
        }
        if !random_wait && cluster_idx + 1 < clusters {
            sleep_ms(INTER_CLUSTER_MS).await;
        }
    }

    done_rx.await.expect("server task");
    println!("use_case={use_case} random_payload={random_payload} random_wait={random_wait} done.");
}
