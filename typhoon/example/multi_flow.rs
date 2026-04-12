/// Multi-flow example: server binds two UDP ports, client certificate embeds both addresses.
/// The client creates one flow manager per address and the session layer distributes packets
/// across them. All messages must arrive regardless of which flow handles each packet.
use std::sync::Arc;

use env_logger;
use futures::channel::oneshot::channel;
#[cfg(not(feature = "tokio"))]
use futures::executor::block_on;
#[cfg(feature = "tokio")]
use tokio::runtime::Runtime;
use typhoon::bytes::StaticByteBuffer;
use typhoon::certificate::ServerKeyPair;
use typhoon::defaults::{AsyncExecutor, DefaultClientConnectionHandler, DefaultExecutor, DefaultServerConnectionHandler};
use typhoon::flow::decoy::SimpleDecoyProvider;
use typhoon::flow::{FakeBodyMode, FakeHeaderConfig, FlowConfig};
use typhoon::settings::SettingsBuilder;
use typhoon::socket::{ClientSocketBuilder, ListenerBuilder, ServerFlowConfiguration};

const MESSAGE_COUNT: usize = 30;

#[cfg(feature = "tokio")]
fn main() {
    Runtime::new().expect("failed to create tokio runtime").block_on(run());
}

#[cfg(not(feature = "tokio"))]
fn main() {
    block_on(run());
}

async fn run() {
    env_logger::init();

    let settings = Arc::new(SettingsBuilder::<DefaultExecutor>::new().build().expect("default settings should be valid"));

    let flow1_addr = "127.0.0.1:19995".parse().expect("valid address");
    let flow2_addr = "127.0.0.1:19994".parse().expect("valid address");

    let key_pair = ServerKeyPair::generate();
    // Embed both server addresses in the certificate — the client will open a socket for each.
    let certificate = key_pair.to_client_certificate(vec![flow1_addr, flow2_addr]);

    let flow_config = FlowConfig::new(FakeBodyMode::Empty, FakeHeaderConfig::new(vec![]));

    // --- Build and start the server with two flow managers ---
    let listener: Arc<_> = Arc::new(ListenerBuilder::<StaticByteBuffer, DefaultExecutor, SimpleDecoyProvider, DefaultServerConnectionHandler>::new(key_pair, DefaultServerConnectionHandler).add_flow(ServerFlowConfiguration::with_address(flow_config.clone(), flow1_addr)).add_flow(ServerFlowConfiguration::with_address(flow_config.clone(), flow2_addr)).with_settings(settings.clone()).build().await.expect("listener should build"));
    listener.start().await;
    println!("Server: listening on {} and {}", flow1_addr, flow2_addr);

    let (done_tx, done_rx) = channel::<usize>();
    // The server holds `client` alive until the client signals it has finished
    // receiving all echoes.  Dropping `client` earlier triggers a TERMINATION
    // packet that races with in-flight echo responses and causes ChannelClosed.
    let (ack_tx, ack_rx) = channel::<()>();
    let listener_handle = listener.clone();
    settings.executor().spawn(async move {
        let client = listener_handle.accept().await.expect("accept should succeed");
        println!("Server: client connected");
        let mut echoed = 0;
        while echoed < MESSAGE_COUNT {
            let data = client.receive_bytes().await.expect("receive should succeed");
            client.send_bytes(&data).await.expect("echo send should succeed");
            echoed += 1;
        }
        println!("Server: echoed {} messages", echoed);
        let _ = done_tx.send(echoed);
        // Keep `client` alive until the client confirms receipt.
        let _ = ack_rx.await;
    });

    // --- Build the client — flows are auto-created from both certificate addresses ---
    let socket = ClientSocketBuilder::<StaticByteBuffer, DefaultExecutor, SimpleDecoyProvider, DefaultClientConnectionHandler>::new(certificate, DefaultClientConnectionHandler).with_settings(settings.clone()).build().await.expect("client socket should build");
    println!("Client: connected (2 flows)");

    for i in 0..MESSAGE_COUNT {
        let msg = format!("msg-{:03}", i);
        socket.send_bytes(msg.as_bytes()).await.expect("send should succeed");
    }
    println!("Client: sent {} messages", MESSAGE_COUNT);

    let mut received = 0;
    for _ in 0..MESSAGE_COUNT {
        let data = socket.receive_bytes().await.expect("receive should succeed");
        println!("Client: received '{}'", String::from_utf8_lossy(&data));
        received += 1;
    }

    let server_count = done_rx.await.expect("server task should complete");
    // All messages received — release the server so it can close the connection.
    let _ = ack_tx.send(());
    assert_eq!(server_count, MESSAGE_COUNT, "server echoed wrong count");
    assert_eq!(received, MESSAGE_COUNT, "client received wrong count");
    println!("Success! All {} messages round-tripped across 2 flows.", MESSAGE_COUNT);
}
