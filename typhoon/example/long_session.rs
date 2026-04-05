/// Long-session example: 200 sequential send/receive round trips over a single connection.
/// Health check packets fire in the background between data packets, exercising the
/// health provider's keepalive path. Every response payload must match the sent payload.
use std::sync::Arc;
use std::time::Duration;

use env_logger;

use tokio::time::sleep;
use typhoon::bytes::StaticByteBuffer;
use typhoon::certificate::ServerKeyPair;
use typhoon::defaults::{AsyncExecutor, DefaultClientConnectionHandler, DefaultExecutor, DefaultServerConnectionHandler};
use typhoon::flow::decoy::SimpleDecoyProvider;
use typhoon::flow::{FakeBodyMode, FakeHeaderConfig, FlowConfig};
use typhoon::settings::SettingsBuilder;
use typhoon::socket::{ClientSocketBuilder, ListenerBuilder, ServerFlowConfiguration};

const ROUND_TRIPS: usize = 200;

#[cfg(feature = "tokio")]
fn main() {
    tokio::runtime::Runtime::new()
        .expect("failed to create tokio runtime")
        .block_on(run());
}

#[cfg(not(feature = "tokio"))]
fn main() {
    futures::executor::block_on(run());
}

async fn run() {
    env_logger::init();

    let settings = Arc::new(
        SettingsBuilder::<DefaultExecutor>::new()
            .build()
            .expect("default settings should be valid"),
    );

    let server_addr = "127.0.0.1:19993".parse().expect("valid address");

    let key_pair = ServerKeyPair::generate();
    let certificate = key_pair.to_client_certificate(vec![server_addr]);

    let flow_config = FlowConfig::new(FakeBodyMode::Empty, FakeHeaderConfig::new(vec![]));

    // --- Build and start the server ---
    let listener: Arc<_> = Arc::new(
        ListenerBuilder::<StaticByteBuffer, DefaultExecutor, SimpleDecoyProvider, DefaultServerConnectionHandler>::new(
            key_pair,
            DefaultServerConnectionHandler,
        )
        .add_flow(ServerFlowConfiguration::with_address(flow_config, server_addr))
        .with_settings(settings.clone())
        .build()
        .await
        .expect("listener should build"),
    );
    listener.start().await;
    println!("Server: listening on {}", server_addr);

    let (done_tx, done_rx) = futures::channel::oneshot::channel::<usize>();
    let listener_handle = listener.clone();
    settings.executor().spawn(async move {
        let client = listener_handle.accept().await.expect("accept should succeed");
        println!("Server: client connected, running echo loop for {} round trips", ROUND_TRIPS);
        let mut count = 0;
        while count < ROUND_TRIPS {
            let data = client.receive_bytes().await.expect("receive should succeed");
            client.send_bytes(&data).await.expect("echo send should succeed");
            count += 1;
        }
        let _ = done_tx.send(count);
    });

    // --- Build the client ---
    let socket =
        ClientSocketBuilder::<StaticByteBuffer, DefaultExecutor, SimpleDecoyProvider, DefaultClientConnectionHandler>::new(
            certificate,
            DefaultClientConnectionHandler,
        )
        .with_settings(settings.clone())
        .build()
        .await
        .expect("client socket should build");
    println!("Client: connected, running {} round trips", ROUND_TRIPS);

    for i in 0..ROUND_TRIPS {
        let sent = format!("round-{:04}", i);
        socket.send_bytes(sent.as_bytes()).await.expect("send should succeed");

        let received = socket.receive_bytes().await.expect("receive should succeed");
        assert_eq!(
            received.as_slice(),
            sent.as_bytes(),
            "payload mismatch on round trip {}",
            i
        );

        if (i + 1) % 50 == 0 {
            println!("Client: completed {}/{} round trips", i + 1, ROUND_TRIPS);
        }

        sleep(Duration::from_secs_f32(1.5)).await;
    }

    let server_count = done_rx.await.expect("server task should complete");
    assert_eq!(server_count, ROUND_TRIPS);
    println!("Success! All {} round trips completed with correct payloads.", ROUND_TRIPS);
}
