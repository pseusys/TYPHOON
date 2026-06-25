/// `ClientPool` example: several clients connect concurrently to one server, which dispatches all
/// of them through a single multiplexed `ClientPool` instead of one `ClientHandle` per connection.
/// Demonstrates `receive()`/`send()` keyed by client identity.
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use env_logger::init;
use futures::channel::oneshot::channel;
#[cfg(not(feature = "tokio"))]
use futures::executor::block_on;
use futures::future::join_all;
#[cfg(feature = "tokio")]
use tokio::runtime::Runtime;
use typhoon::bytes::StaticByteBuffer;
use typhoon::certificate::ServerKeyPair;
use typhoon::defaults::{AsyncExecutor, DefaultClientConnectionHandler, DefaultExecutor, DefaultServerConnectionHandler};
use typhoon::flow::{FakeBodyMode, FakeHeaderConfig, FlowConfig};
use typhoon::settings::SettingsBuilder;
use typhoon::socket::{ClientSocketBuilder, ServerBuilder, ServerFlowConfiguration};

const CLIENT_COUNT: usize = 3;
const MESSAGES_PER_CLIENT: usize = 10;

#[cfg(feature = "tokio")]
fn main() {
    Runtime::new().expect("failed to create tokio runtime").block_on(run());
}

#[cfg(not(feature = "tokio"))]
fn main() {
    block_on(run());
}

async fn run() {
    init();

    let settings = Arc::new(SettingsBuilder::<DefaultExecutor>::new().build().expect("default settings should be valid"));
    let server_addr = "127.0.0.1:19990".parse().expect("valid address");

    let key_pair = ServerKeyPair::generate();
    let certificates: Vec<_> = (0..CLIENT_COUNT).map(|_| key_pair.to_client_certificate(vec![server_addr])).collect();

    let flow_config = FlowConfig::new(FakeBodyMode::Empty, FakeHeaderConfig::new(vec![]));

    // --- Build and start the server as a ClientPool ---
    let pool: Arc<_> = Arc::new(ServerBuilder::<StaticByteBuffer, DefaultExecutor, DefaultServerConnectionHandler>::new(key_pair, DefaultServerConnectionHandler).add_flow(ServerFlowConfiguration::with_address(flow_config, server_addr)).with_settings(settings.clone()).build_pool().await.expect("pool should build"));
    pool.start().await;
    println!("Server: listening on {server_addr} via ClientPool");

    // Single server task: pulls (identity, packet) from any client and echoes it back.
    let echoed = Arc::new(AtomicUsize::new(0));
    let pool_handle = pool.clone();
    let echoed_handle = echoed.clone();
    let (done_tx, done_rx) = channel::<usize>();
    settings.executor().spawn(async move {
        let mut done_tx = Some(done_tx);
        while let Ok((id, data)) = pool_handle.receive().await {
            if pool_handle.send(&id, data).await.is_ok() {
                let count = echoed_handle.fetch_add(1, Ordering::Relaxed) + 1;
                if count == CLIENT_COUNT * MESSAGES_PER_CLIENT
                    && let Some(done_tx) = done_tx.take()
                {
                    let _ = done_tx.send(count);
                }
            }
        }
    });

    // --- Connect all clients concurrently ---
    let client_futs: Vec<_> = certificates
        .into_iter()
        .enumerate()
        .map(|(client_id, certificate)| {
            let settings = settings.clone();
            async move {
                let socket = ClientSocketBuilder::<StaticByteBuffer, DefaultExecutor, DefaultClientConnectionHandler>::new(certificate, DefaultClientConnectionHandler).with_settings(settings.clone()).build().await.expect("client socket should build");

                println!("Client {client_id}: connected");

                for i in 0..MESSAGES_PER_CLIENT {
                    let msg = format!("c{client_id}-msg-{i:02}");
                    socket.send_bytes(msg.as_bytes()).await.expect("send should succeed");
                }

                let mut received = 0;
                for _ in 0..MESSAGES_PER_CLIENT {
                    let data = socket.receive_bytes().await.expect("receive should succeed");
                    println!("Client {}: received '{}'", client_id, String::from_utf8_lossy(&data));
                    received += 1;
                }

                received
            }
        })
        .collect();

    let client_counts = join_all(client_futs).await;
    for (id, count) in client_counts.iter().enumerate() {
        assert_eq!(*count, MESSAGES_PER_CLIENT, "client {id} received wrong count");
    }

    let total_echoed = done_rx.await.expect("server task should complete");
    assert_eq!(total_echoed, CLIENT_COUNT * MESSAGES_PER_CLIENT, "pool echoed wrong count");

    println!("Success! {CLIENT_COUNT} clients × {MESSAGES_PER_CLIENT} messages all round-tripped through one ClientPool.");
}
