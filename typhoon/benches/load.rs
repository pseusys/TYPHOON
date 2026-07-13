/// One-way send-throughput benchmark: how fast the client can encrypt and emit bytes across
/// `flows` flow sockets under random `FlowConfig` obfuscation. This isolates the client send
/// pipeline — the throughput ceiling — which the load test showed to be the bottleneck (the
/// serialized per-packet send cost, not the server, limits the flood; that is also why localhost
/// sees no loss). The evaluation harness (`poe load-test`) also flamegraphs this bench for the
/// send/recv hot path.
///
/// One-way by design: the client hands `size` bytes to the socket and the iteration ends there; the
/// server drains and discards in the background. There is no echo to wait on, so a dropped packet
/// (TYPHOON is unreliable) can never wedge the loop — end-to-end loss / memory is the dockerized
/// flood's job. `readers` (`SO_REUSEPORT`, server side) does not affect one-way send throughput, so
/// it is fixed to a single value here rather than swept.
use std::net::{SocketAddr, UdpSocket};
use std::sync::Arc;

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use tokio::runtime::Runtime;
use typhoon::bytes::StaticByteBuffer;
use typhoon::certificate::ServerKeyPair;
use typhoon::defaults::{DefaultClientConnectionHandler, DefaultExecutor, DefaultServerConnectionHandler};
use typhoon::flow::FlowConfig;
use typhoon::settings::SettingsBuilder;
use typhoon::socket::{ClientSocket, ClientSocketBuilder, ServerBuilder, ServerFlowConfiguration};

#[cfg(any(feature = "fast_software", feature = "fast_hardware"))]
const KEY_ENV_VAR: &str = "TYPHOON_TEST_SERVER_KEY_FAST";

#[cfg(any(feature = "full_software", feature = "full_hardware"))]
const KEY_ENV_VAR: &str = "TYPHOON_TEST_SERVER_KEY_FULL";

const DEFAULT_FLOW_COUNTS: &[usize] = &[1, 2, 4];
const DEFAULT_READER_COUNTS: &[usize] = &[1, 2];
const DEFAULT_TRANSFER_SIZES: &[usize] = &[8 * 1024, 32 * 1024];

type LoadClient = ClientSocket<StaticByteBuffer, DefaultExecutor, DefaultClientConnectionHandler>;

/// Parse a comma-separated list of counts from `env_var`, falling back to `default`.
/// Lets the harness align the bench grid with the process-level load test.
fn grid_from_env(env_var: &str, default: &[usize]) -> Vec<usize> {
    match std::env::var(env_var) {
        Ok(raw) => {
            let parsed: Vec<usize> = raw.split(',').filter_map(|v| v.trim().parse().ok()).filter(|&n| n > 0).collect();
            if parsed.is_empty() { default.to_vec() } else { parsed }
        }
        Err(_) => default.to_vec(),
    }
}

fn free_addr() -> SocketAddr {
    UdpSocket::bind("127.0.0.1:0").expect("OS should assign a free port").local_addr().unwrap()
}

fn load_or_generate_key() -> ServerKeyPair {
    if let Ok(path) = std::env::var(KEY_ENV_VAR) {
        let p = std::path::Path::new(&path);
        if p.exists()
            && let Ok(kp) = ServerKeyPair::load(p)
        {
            return kp;
        }
        let kp = ServerKeyPair::generate();
        let _ = kp.save(p);
        kp
    } else {
        ServerKeyPair::generate()
    }
}

/// Build a live client+server with `flows` ports (each with `readers` reader sockets) and spawn a
/// server-side drain task that receives and discards. Returns the client socket; the listener is
/// kept alive by the drain task for the benchmark's duration.
fn setup(rt: &Runtime, flows: usize, readers: usize) -> Arc<LoadClient> {
    let settings = Arc::new(SettingsBuilder::<DefaultExecutor>::new().build().expect("settings"));
    let key_pair = load_or_generate_key();
    let addrs: Vec<SocketAddr> = (0..flows).map(|_| free_addr()).collect();
    let certificate = key_pair.to_client_certificate(addrs.clone());

    let mut server = ServerBuilder::<StaticByteBuffer, DefaultExecutor, DefaultServerConnectionHandler>::new(key_pair, DefaultServerConnectionHandler);
    for addr in &addrs {
        server = server.add_flow(ServerFlowConfiguration::with_address(FlowConfig::random(&settings), *addr).with_reader_count(readers));
    }
    let listener = Arc::new(rt.block_on(async { server.with_settings(settings.clone()).build_listener().await.expect("listener") }));
    rt.block_on(async { listener.start().await });

    let drain_listener = listener.clone();
    rt.spawn(async move {
        let client = drain_listener.accept().await.expect("accept");
        while client.receive_bytes().await.is_ok() {}
    });

    let mut client = ClientSocketBuilder::<StaticByteBuffer, DefaultExecutor, DefaultClientConnectionHandler>::new(certificate, DefaultClientConnectionHandler);
    for addr in &addrs {
        client = client.with_flow_config(*addr, FlowConfig::random(&settings));
    }
    Arc::new(rt.block_on(async { client.with_settings(settings.clone()).build().await.expect("socket") }))
}

/// Encrypt and emit `payload` one-way across the flow sockets, splitting into MTU-sized packets.
/// The iteration ends when the last packet is handed to the socket — delivery is not awaited, so a
/// dropped packet cannot stall the measurement.
async fn send_transfer(socket: &LoadClient, payload: &[u8]) {
    socket.send_bytes(payload).await.expect("send");
}

fn bench_load(c: &mut Criterion) {
    let flow_counts = grid_from_env("TYPHOON_LOAD_BENCH_FLOWS", DEFAULT_FLOW_COUNTS);
    // One-way send throughput is client-bound; readers are server side, so fix at the first value.
    let readers = grid_from_env("TYPHOON_LOAD_BENCH_READERS", DEFAULT_READER_COUNTS)[0];
    let transfer_sizes = grid_from_env("TYPHOON_LOAD_BENCH_SIZES", DEFAULT_TRANSFER_SIZES);

    let mut group = c.benchmark_group("load");
    for &flows in &flow_counts {
        {
            let rt = Runtime::new().expect("tokio runtime");
            let socket = setup(&rt, flows, readers);
            for &size in &transfer_sizes {
                let payload = vec![0xABu8; size];
                group.throughput(Throughput::Bytes(size as u64));
                group.bench_with_input(BenchmarkId::new(format!("f{flows}"), size), &size, |b, _| {
                    b.to_async(&rt).iter(|| send_transfer(&socket, &payload));
                });
            }
        }
    }
    group.finish();
}

criterion_group!(benches, bench_load);
criterion_main!(benches);
