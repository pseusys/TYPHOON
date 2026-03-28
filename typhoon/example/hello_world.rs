use std::sync::Arc;

use classic_mceliece_rust::{PublicKey as McEliecePublicKey, keypair_boxed};
use ed25519_dalek::SigningKey;
use rand::RngCore;
use typhoon::bytes::StaticByteBuffer;
use typhoon::crypto::{Certificate, ServerSecret};
use typhoon::defaults::{DefaultExecutor, RandomIdentityGenerator};
use typhoon::flow::decoy::SimpleDecoyProvider;
use typhoon::flow::{FakeBodyMode, FakeHeaderConfig, FlowConfig};
use typhoon::settings::SettingsBuilder;
use typhoon::socket::{
    ClientSocketBuilder, FlowManagerConfiguration, ListenerBuilder, ServerFlowConfiguration,
};

fn main() {
    let rt = tokio::runtime::Runtime::new().expect("failed to create tokio runtime");
    rt.block_on(async {
    let settings = Arc::new(
        SettingsBuilder::<DefaultExecutor>::new()
            .build()
            .expect("default settings should be valid"),
    );

    // Generate shared key material.
    let mut rng = rand::thread_rng();
    let (pk, sk) = keypair_boxed(&mut rng);

    let mut signing_bytes = [0u8; 32];
    rng.fill_bytes(&mut signing_bytes);
    let signing_key = SigningKey::from_bytes(&signing_bytes);
    let verifying_key = signing_key.verifying_key();

    let mut obfs_bytes = [0u8; 32];
    rng.fill_bytes(&mut obfs_bytes);

    // Client certificate (public side).
    let certificate = Certificate {
        epk: Arc::new(McEliecePublicKey::from(pk)),
        vpk: verifying_key,
        obfs: StaticByteBuffer::from(&obfs_bytes),
    };

    // Server secret (private side).
    let server_secret = ServerSecret {
        esk: sk,
        vsk: signing_key,
        obfs: StaticByteBuffer::from(&obfs_bytes),
    };

    // Shared flow config: no fake headers or body padding.
    let flow_config = FlowConfig::new(FakeBodyMode::Empty, FakeHeaderConfig::new(vec![]));
    let server_addr = "127.0.0.1:19999".parse().expect("valid address");

    // --- Build and start the server ---
    let server_flow = ServerFlowConfiguration::with_address(flow_config.clone(), server_addr);
    let listener: Arc<_> = Arc::new(
        ListenerBuilder::<StaticByteBuffer, DefaultExecutor, SimpleDecoyProvider, RandomIdentityGenerator>::new(
            server_secret,
            RandomIdentityGenerator,
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
    let (done_tx, done_rx) = tokio::sync::oneshot::channel::<String>();

    tokio::spawn(async move {
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
    let client_flow = FlowManagerConfiguration::with_address(flow_config, server_addr);
    let socket =
        ClientSocketBuilder::<StaticByteBuffer, DefaultExecutor, SimpleDecoyProvider>::new(
            certificate,
        )
        .add_flow(client_flow)
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
    });
}
