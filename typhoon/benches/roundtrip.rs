/// End-to-end round-trip benchmarks:
///   "batch" — 20 pipelined 1400 B messages under realistic flow obfuscation (mirrors heavy_traffic).
///   "single" — random-sized single-packet round trips with no data-packet overhead; measures raw
///               per-packet protocol cost (crypto, tailor, socket I/O).
use std::net::UdpSocket;
use std::sync::Arc;

use criterion::{BatchSize, Criterion, Throughput, criterion_group, criterion_main};
use rand::Rng;
use tokio::runtime::Runtime;
use typhoon::bytes::StaticByteBuffer;
use typhoon::certificate::ServerKeyPair;
use typhoon::defaults::{DefaultClientConnectionHandler, DefaultExecutor, DefaultServerConnectionHandler};
use typhoon::flow::config::{FakeBodyMode, FakeHeaderConfig};
use typhoon::flow::FlowConfig;
use typhoon::settings::SettingsBuilder;
use typhoon::socket::{ClientSocketBuilder, ListenerBuilder, ServerFlowConfiguration};

#[cfg(any(feature = "fast_software", feature = "fast_hardware"))]
const KEY_ENV_VAR: &str = "TYPHOON_TEST_SERVER_KEY_FAST";

#[cfg(any(feature = "full_software", feature = "full_hardware"))]
const KEY_ENV_VAR: &str = "TYPHOON_TEST_SERVER_KEY_FULL";

const BATCH_DEPTH: usize = 20;
const BATCH_PAYLOAD: usize = 1400;

// Upper bound for random single-packet payloads. With service-only fake body (max_length = 128)
// and max header overhead (FAKE_HEADER_LENGTH_MAX = 32 B) and fast_software protocol overhead
// (~160 B), the wire packet stays within the 1400-byte MTU:
//   max_data_payload = 1400 - 128 - 32 - 160 = 1080 ≥ SINGLE_PAYLOAD_MAX.
const SINGLE_PAYLOAD_MAX: usize = 1024;

fn free_addr() -> std::net::SocketAddr {
    UdpSocket::bind("127.0.0.1:0").expect("OS should assign a free port").local_addr().unwrap()
}

fn load_or_generate_key() -> ServerKeyPair {
    if let Ok(path) = std::env::var(KEY_ENV_VAR) {
        let p = std::path::Path::new(&path);
        if p.exists() {
            if let Ok(kp) = ServerKeyPair::load(p) {
                return kp;
            }
        }
        let kp = ServerKeyPair::generate();
        let _ = kp.save(p);
        kp
    } else {
        ServerKeyPair::generate()
    }
}

/// Pipelined throughput under realistic traffic obfuscation (mirrors heavy_traffic example).
fn bench_batch(c: &mut Criterion) {
    let rt = Runtime::new().expect("tokio runtime");
    let settings = Arc::new(SettingsBuilder::<DefaultExecutor>::new().build().expect("settings"));

    let addr = free_addr();
    let key_pair = load_or_generate_key();
    let certificate = key_pair.to_client_certificate(vec![addr]);

    let listener = Arc::new(rt.block_on(async {
        ListenerBuilder::<StaticByteBuffer, DefaultExecutor, DefaultServerConnectionHandler>::new(key_pair, DefaultServerConnectionHandler)
            .add_flow(ServerFlowConfiguration::with_address(FlowConfig::random(&settings), addr))
            .with_settings(settings.clone())
            .build()
            .await
            .expect("listener")
    }));
    rt.block_on(async { listener.start().await });

    let listener_echo = listener.clone();
    rt.spawn(async move {
        let client = listener_echo.accept().await.expect("accept");
        loop {
            match client.receive_bytes().await {
                Ok(data) => { let _ = client.send_bytes(&data).await; }
                Err(_) => break,
            }
        }
    });

    let socket = rt.block_on(async {
        ClientSocketBuilder::<StaticByteBuffer, DefaultExecutor, DefaultClientConnectionHandler>::new(certificate, DefaultClientConnectionHandler)
            .with_flow_config(addr, FlowConfig::random(&settings))
            .with_settings(settings.clone())
            .build()
            .await
            .expect("socket")
    });

    let payload: Vec<u8> = (0..BATCH_PAYLOAD).map(|i| (i % 256) as u8).collect();
    let mut group = c.benchmark_group("batch");
    group.throughput(Throughput::Bytes((BATCH_DEPTH * BATCH_PAYLOAD) as u64));
    group.bench_function("echo", |b| {
        b.to_async(&rt).iter(|| async {
            for _ in 0..BATCH_DEPTH {
                socket.send_bytes(&payload).await.expect("send");
            }
            for _ in 0..BATCH_DEPTH {
                socket.receive_bytes().await.expect("receive");
            }
        });
    });
    group.finish();
}

/// Single-packet round-trip latency with randomly-sized payloads.
/// `FakeBodyMode::Random { service: true }` skips fake body for data packets, so the wire packet
/// carries only user payload + fixed protocol overhead — no padding copies, no packet splitting.
fn bench_single(c: &mut Criterion) {
    let rt = Runtime::new().expect("tokio runtime");
    let settings = Arc::new(SettingsBuilder::<DefaultExecutor>::new().build().expect("settings"));

    let addr = free_addr();
    let key_pair = load_or_generate_key();
    let certificate = key_pair.to_client_certificate(vec![addr]);

    // service: true — data packets carry no fake body; random body only on health-check packets.
    // max_length = 128 keeps max_data_payload above SINGLE_PAYLOAD_MAX for all feature sets.
    let flow_config = FlowConfig::new(
        FakeBodyMode::Random { min_length: 0, max_length: 128, service: true },
        FakeHeaderConfig::random(&settings),
    );

    let listener = Arc::new(rt.block_on(async {
        ListenerBuilder::<StaticByteBuffer, DefaultExecutor, DefaultServerConnectionHandler>::new(key_pair, DefaultServerConnectionHandler)
            .add_flow(ServerFlowConfiguration::with_address(flow_config.clone(), addr))
            .with_settings(settings.clone())
            .build()
            .await
            .expect("listener")
    }));
    rt.block_on(async { listener.start().await });

    let listener_echo = listener.clone();
    rt.spawn(async move {
        let client = listener_echo.accept().await.expect("accept");
        loop {
            match client.receive_bytes().await {
                Ok(data) => { let _ = client.send_bytes(&data).await; }
                Err(_) => break,
            }
        }
    });

    let socket = Arc::new(rt.block_on(async {
        ClientSocketBuilder::<StaticByteBuffer, DefaultExecutor, DefaultClientConnectionHandler>::new(certificate, DefaultClientConnectionHandler)
            .with_flow_config(addr, flow_config)
            .with_settings(settings.clone())
            .build()
            .await
            .expect("socket")
    }));

    let mut group = c.benchmark_group("single");
    group.bench_function("rtt", |b| {
        b.to_async(&rt).iter_batched(
            || {
                let size = rand::thread_rng().gen_range(1..=SINGLE_PAYLOAD_MAX);
                (vec![0xABu8; size], socket.clone())
            },
            |(payload, socket)| async move {
                socket.send_bytes(&payload).await.expect("send");
                socket.receive_bytes().await.expect("receive");
            },
            BatchSize::SmallInput,
        )
    });
    group.finish();
}

criterion_group!(benches, bench_batch, bench_single);
criterion_main!(benches);
