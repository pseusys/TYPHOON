use std::sync::Arc;

use classic_mceliece_rust::{keypair_boxed, PublicKey as McEliecePublicKey};
use ed25519_dalek::SigningKey;
use rand::RngCore;

use typhoon::bytes::StaticByteBuffer;
use typhoon::crypto::Certificate;
use typhoon::defaults::DefaultExecutor;
use typhoon::flow::decoy::SimpleDecoyProvider;
use typhoon::flow::{FakeBodyMode, FakeHeaderConfig, FlowConfig};
use typhoon::settings::SettingsBuilder;
use typhoon::socket::{ClientSocketBuilder, FlowManagerConfiguration};

fn main() {
    let rt = tokio::runtime::Runtime::new().expect("failed to create tokio runtime");
    rt.block_on(async {
        // Build protocol settings with defaults.
        let settings = Arc::new(
            SettingsBuilder::<DefaultExecutor>::new()
                .build()
                .expect("default settings should be valid"),
        );

        // Generate cryptographic keys.
        let mut rng = rand::thread_rng();
        let (pk, _sk) = keypair_boxed(&mut rng);
        let mut signing_bytes = [0u8; 32];
        rng.fill_bytes(&mut signing_bytes);
        let signing_key = SigningKey::from_bytes(&signing_bytes);
        let verifying_key = signing_key.verifying_key();
        let mut obfs_bytes = [0u8; 32];
        rng.fill_bytes(&mut obfs_bytes);

        // Build a client certificate and crypto tool.
        let certificate = Certificate {
            epk: Arc::new(McEliecePublicKey::from(pk)),
            vpk: verifying_key,
            obfs: StaticByteBuffer::from(&obfs_bytes),
        };

        // Configure a single flow with no fake headers or body padding.
        let flow_config = FlowConfig::new(FakeBodyMode::Empty, FakeHeaderConfig::new(vec![]));
        let server_addr = "127.0.0.1:9999".parse().expect("valid address");
        let flow = FlowManagerConfiguration::with_address(flow_config, server_addr);

        // Build the client socket builder.
        let builder = ClientSocketBuilder::<StaticByteBuffer, _, SimpleDecoyProvider>::new(certificate)
            .add_flow(flow).with_settings(settings);

        println!("Client socket builder configured for {}", server_addr);

        // Build the client socket and send a "hello world" message.
        // NB: `build()` initiates a health check handshake with the server,
        // so a running TYPHOON server is required at the target address.
        let socket = builder.build().await.expect("client socket should build successfully");
        socket.send_bytes(b"hello world").await.expect("send should succeed");

        println!("Sent 'hello world' to {}", server_addr);

        // Socket is automatically cleaned up when it goes out of scope.
    });
}
