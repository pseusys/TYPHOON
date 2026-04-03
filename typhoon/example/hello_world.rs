use std::sync::Arc;

use typhoon::bytes::StaticByteBuffer;
use typhoon::certificate::ServerKeyPair;
use typhoon::defaults::{AsyncExecutor, DefaultClientConnectionHandler, DefaultExecutor, DefaultServerConnectionHandler};
use typhoon::flow::decoy::SimpleDecoyProvider;
use typhoon::flow::{FakeBodyMode, FakeHeaderConfig, FlowConfig};
use typhoon::settings::SettingsBuilder;
use typhoon::socket::{
    ClientSocketBuilder, ListenerBuilder, ServerFlowConfiguration,
};

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
    let settings = Arc::new(
        SettingsBuilder::<DefaultExecutor>::new()
            .build()
            .expect("default settings should be valid"),
    );

    let server_addr = "127.0.0.1:19999".parse().expect("valid address");

    // Generate a server key pair and derive a client certificate with the server address.
    let key_pair = ServerKeyPair::generate();
    let certificate = key_pair.to_client_certificate(vec![server_addr]);

    // Shared flow config: no fake headers or body padding.
    let flow_config = FlowConfig::new(FakeBodyMode::Empty, FakeHeaderConfig::new(vec![]));

    // --- Build and start the server ---
    let server_flow = ServerFlowConfiguration::with_address(flow_config, server_addr);
    let listener: Arc<_> = Arc::new(
        ListenerBuilder::<StaticByteBuffer, DefaultExecutor, SimpleDecoyProvider, DefaultServerConnectionHandler>::new(
            key_pair,
            DefaultServerConnectionHandler,
        )
        .add_flow(server_flow)
        .with_settings(settings.clone())
        .build()
        .await
        .expect("listener should build"),
    );
    listener.start().await;
    println!("Server listening on {}", server_addr);

    // Spawn server handler: accept one client, echo back what it receives.
    let listener_handle = listener.clone();
    let (done_tx, done_rx) = futures::channel::oneshot::channel::<String>();

    settings.executor().spawn(async move {
        let client = listener_handle
            .accept()
            .await
            .expect("accept should succeed");
        println!("Server: client connected");

        let received = client
            .receive_bytes()
            .await
            .expect("receive should succeed");
        let msg = String::from_utf8_lossy(&received).to_string();
        println!("Server: received '{}'", msg);

        client
            .send_bytes(format!("echo: {}", msg).as_bytes())
            .await
            .expect("send should succeed");
        println!("Server: sent echo response");

        let _ = done_tx.send(msg);
    });

    // --- Build the client and connect ---
    // Flows are auto-created from the addresses embedded in the certificate.
    let socket =
        ClientSocketBuilder::<StaticByteBuffer, DefaultExecutor, SimpleDecoyProvider, DefaultClientConnectionHandler>::new(
            certificate,
            DefaultClientConnectionHandler,
        )
        .with_settings(settings.clone())
        .build()
        .await
        .expect("client socket should build");
    println!("Client: connected to {}", server_addr);

    // Send a message and receive the echo.
    socket
        .send_bytes(b"hello world")
        .await
        .expect("send should succeed");
    println!("Client: sent 'hello world'");

    let response = socket
        .receive_bytes()
        .await
        .expect("receive should succeed");
    println!(
        "Client: received '{}'",
        String::from_utf8_lossy(&response)
    );

    // Wait for server task to finish.
    let server_received = done_rx.await.expect("server task should complete");
    assert_eq!(server_received, "hello world");
    println!("Success! Round-trip verified.");
}
