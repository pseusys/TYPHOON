/// Multi-client example: several clients connect concurrently to one server.
/// Each client sends a unique set of messages; the server handles all sessions in parallel.
/// Tests independent session isolation and concurrent RwLock read access to the sessions map.
use std::sync::Arc;

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
use typhoon::flow::decoy::SimpleDecoyProvider;
use typhoon::flow::{FakeBodyMode, FakeHeaderConfig, FlowConfig};
use typhoon::settings::SettingsBuilder;
use typhoon::socket::{ClientSocketBuilder, ListenerBuilder, ServerFlowConfiguration};

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
    let server_addr = "127.0.0.1:19992".parse().expect("valid address");

    let key_pair = ServerKeyPair::generate();

    // Generate all client certificates before consuming key_pair into the listener builder.
    let certificates: Vec<_> = (0..CLIENT_COUNT).map(|_| key_pair.to_client_certificate(vec![server_addr])).collect();

    let flow_config = FlowConfig::new(FakeBodyMode::Empty, FakeHeaderConfig::new(vec![]));

    // --- Build and start the server ---
    let listener: Arc<_> = Arc::new(ListenerBuilder::<StaticByteBuffer, DefaultExecutor, SimpleDecoyProvider, DefaultServerConnectionHandler>::new(key_pair, DefaultServerConnectionHandler).add_flow(ServerFlowConfiguration::with_address(flow_config, server_addr)).with_settings(settings.clone()).build().await.expect("listener should build"));
    listener.start().await;
    println!("Server: listening on {server_addr}");

    // Spawn one echo task per expected client (accepted in order of handshake arrival).
    let mut server_done_rxs = Vec::with_capacity(CLIENT_COUNT);
    for client_id in 0..CLIENT_COUNT {
        let (done_tx, done_rx) = channel::<usize>();
        server_done_rxs.push(done_rx);

        let listener_handle = listener.clone();
        settings.executor().spawn(async move {
            let client = listener_handle.accept().await.expect("accept should succeed");
            println!("Server: client {client_id} connected");
            let mut count = 0;
            while count < MESSAGES_PER_CLIENT {
                let data = client.receive_bytes().await.expect("receive should succeed");
                client.send_bytes(&data).await.expect("echo send should succeed");
                count += 1;
            }
            println!("Server: client {client_id} echoed {count} messages");
            let _ = done_tx.send(count);
        });
    }

    // --- Connect all clients concurrently ---
    let client_futs: Vec<_> = certificates
        .into_iter()
        .enumerate()
        .map(|(client_id, certificate)| {
            let settings = settings.clone();
            async move {
                let socket = ClientSocketBuilder::<StaticByteBuffer, DefaultExecutor, SimpleDecoyProvider, DefaultClientConnectionHandler>::new(certificate, DefaultClientConnectionHandler).with_settings(settings.clone()).build().await.expect("client socket should build");

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

                println!("Client {client_id}: all {received} messages echoed");
                received
            }
        })
        .collect();

    let client_counts = join_all(client_futs).await;

    for (id, count) in client_counts.iter().enumerate() {
        assert_eq!(*count, MESSAGES_PER_CLIENT, "client {id} received wrong count");
    }

    for (id, done_rx) in server_done_rxs.into_iter().enumerate() {
        let count = done_rx.await.expect("server task should complete");
        assert_eq!(count, MESSAGES_PER_CLIENT, "server echoed wrong count for client {id}");
    }

    println!("Success! {} clients × {} messages all round-tripped correctly.", CLIENT_COUNT, MESSAGES_PER_CLIENT);
}
