/// Heavy-traffic example: server binds three UDP ports (three flow managers); the client
/// certificate embeds only two of those addresses so traffic distributes across two flows.
/// The client pipelines PIPELINE_DEPTH messages per batch, collects all echoes, then
/// pauses before the next batch.  Total run-time is approximately five minutes.
/// Both client and server use random FlowConfig for traffic obfuscation; byte-level counting
/// ensures correctness regardless of how messages are split into wire packets.
use std::sync::Arc;
use std::time::{Duration, Instant};

#[cfg(feature = "async-std")]
use async_io::Timer;
use env_logger::init;
use futures::channel::oneshot::channel;
#[cfg(not(feature = "tokio"))]
use futures::executor::block_on;
#[cfg(feature = "tokio")]
use tokio::runtime::Runtime;
#[cfg(feature = "tokio")]
use tokio::time::sleep;
use typhoon::bytes::StaticByteBuffer;
use typhoon::certificate::ServerKeyPair;
use typhoon::defaults::{AsyncExecutor, DefaultClientConnectionHandler, DefaultExecutor, DefaultServerConnectionHandler, decoy_factory};
use typhoon::flow::FlowConfig;
use typhoon::flow::decoy::{NoisyDecoyProvider, SmoothDecoyProvider, SparseDecoyProvider};
use typhoon::settings::SettingsBuilder;
use typhoon::socket::{ClientSocketBuilder, ListenerBuilder, ServerFlowConfiguration};

const PIPELINE_DEPTH: usize = 20;
const BATCH_COUNT: usize = 750;
const INTER_BATCH_MS: u64 = 400;
const PAYLOAD_SIZE: usize = 1400;
const TOTAL_MESSAGES: usize = PIPELINE_DEPTH * BATCH_COUNT;
const TOTAL_BYTES: usize = TOTAL_MESSAGES * PAYLOAD_SIZE;

#[cfg(feature = "tokio")]
fn main() {
    Runtime::new().expect("failed to create tokio runtime").block_on(run());
}

#[cfg(not(feature = "tokio"))]
fn main() {
    block_on(run());
}

#[cfg(feature = "tokio")]
async fn wait(duration: Duration) {
    sleep(duration).await;
}

#[cfg(feature = "async-std")]
async fn wait(duration: Duration) {
    Timer::after(duration).await;
}

async fn run() {
    init();

    let settings = Arc::new(SettingsBuilder::<DefaultExecutor>::new().build().expect("default settings should be valid"));

    let flow1_addr = "127.0.0.1:19985".parse().expect("valid address");
    let flow2_addr = "127.0.0.1:19986".parse().expect("valid address");
    let flow3_addr = "127.0.0.1:19987".parse().expect("valid address");

    let key_pair = ServerKeyPair::generate();
    let certificate = key_pair.to_client_certificate(vec![flow1_addr, flow2_addr]);

    let listener: Arc<_> = Arc::new(
        ListenerBuilder::<StaticByteBuffer, DefaultExecutor, DefaultServerConnectionHandler>::new(key_pair, DefaultServerConnectionHandler)
            .add_flow(ServerFlowConfiguration::with_address(FlowConfig::random(&*settings), flow1_addr).with_decoy::<NoisyDecoyProvider<StaticByteBuffer, DefaultExecutor>>())
            .add_flow(ServerFlowConfiguration::with_address(FlowConfig::random(&*settings), flow2_addr).with_decoy::<SmoothDecoyProvider<StaticByteBuffer, DefaultExecutor>>())
            .add_flow(ServerFlowConfiguration::with_address(FlowConfig::random(&*settings), flow3_addr).with_decoy::<SparseDecoyProvider<StaticByteBuffer, DefaultExecutor>>())
            .with_settings(settings.clone())
            .build()
            .await
            .expect("listener should build"),
    );
    listener.start().await;
    println!("Server: listening on {flow1_addr}, {flow2_addr}, {flow3_addr} (client uses first two)");

    let (done_tx, done_rx) = channel::<usize>();
    let (ack_tx, ack_rx) = channel::<()>();
    let listener_handle = listener.clone();
    settings.executor().spawn(async move {
        let client = listener_handle.accept().await.expect("accept should succeed");
        println!("Server: client connected, will echo {TOTAL_BYTES} B across {BATCH_COUNT} batches");
        let mut echoed_bytes = 0usize;
        let report_interval = PIPELINE_DEPTH * 75 * PAYLOAD_SIZE;
        while echoed_bytes < TOTAL_BYTES {
            let data = client.receive_bytes().await.expect("receive should succeed");
            let prev = echoed_bytes;
            echoed_bytes += data.len();
            client.send_bytes(&data).await.expect("echo should succeed");
            if echoed_bytes / report_interval > prev / report_interval {
                println!("Server: echoed {} KB / {} KB", echoed_bytes / 1024, TOTAL_BYTES / 1024);
            }
        }
        println!("Server: finished echoing {echoed_bytes} B");
        let _ = done_tx.send(echoed_bytes);
        let _ = ack_rx.await;
    });

    let socket = ClientSocketBuilder::<StaticByteBuffer, DefaultExecutor, DefaultClientConnectionHandler>::new(certificate, DefaultClientConnectionHandler).with_decoy_factory(decoy_factory::<StaticByteBuffer, DefaultExecutor, SmoothDecoyProvider<StaticByteBuffer, DefaultExecutor>>()).with_settings(settings.clone()).build().await.expect("client socket should build");
    println!("Client: connected, sending {BATCH_COUNT} batches of {PIPELINE_DEPTH} × {PAYLOAD_SIZE}B (~5 min)");

    let payload: Vec<u8> = (0..PAYLOAD_SIZE).map(|i| (i % 256) as u8).collect();
    let inter_batch = Duration::from_millis(INTER_BATCH_MS);
    let batch_bytes = PIPELINE_DEPTH * PAYLOAD_SIZE;
    let start = Instant::now();
    let mut total_sent = 0usize;
    let mut total_received_bytes = 0usize;

    for batch in 0..BATCH_COUNT {
        for i in 0..PIPELINE_DEPTH {
            let mut msg = payload.clone();
            let seq = ((batch * PIPELINE_DEPTH + i) as u64).to_le_bytes();
            msg[..seq.len()].copy_from_slice(&seq);
            socket.send_bytes(&msg).await.expect("send should succeed");
            total_sent += 1;
        }

        let mut batch_received = 0usize;
        while batch_received < batch_bytes {
            let data = socket.receive_bytes().await.expect("receive should succeed");
            batch_received += data.len();
            total_received_bytes += data.len();
        }

        if (batch + 1) % 75 == 0 {
            let elapsed = start.elapsed();
            let throughput = (total_sent * PAYLOAD_SIZE) as f64 / elapsed.as_secs_f64() / 1024.0;
            println!("Client: batch {}/{BATCH_COUNT} | {total_sent} msgs sent | {:.1} KB/s | {:.0}s elapsed", batch + 1, throughput, elapsed.as_secs_f64());
        }

        wait(inter_batch).await;
    }

    let elapsed = start.elapsed();
    let throughput = (total_sent * PAYLOAD_SIZE) as f64 / elapsed.as_secs_f64() / 1024.0;
    println!("Client: done — {total_sent} sent, {} KB received in {:.1}s ({:.1} KB/s)", total_received_bytes / 1024, elapsed.as_secs_f64(), throughput);

    let server_bytes = done_rx.await.expect("server task should complete");
    let _ = ack_tx.send(());
    assert_eq!(total_sent, TOTAL_MESSAGES, "wrong send count");
    assert_eq!(total_received_bytes, TOTAL_BYTES, "wrong receive bytes");
    assert_eq!(server_bytes, TOTAL_BYTES, "server echoed wrong bytes");
    println!("Success! {TOTAL_MESSAGES} × {PAYLOAD_SIZE}B messages round-tripped across 2 flows in {:.1}s", elapsed.as_secs_f64());
}
