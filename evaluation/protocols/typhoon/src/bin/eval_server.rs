/// TYPHOON evaluation server.
///
/// Generates a ServerKeyPair, saves the ClientCertificate to /keys/typhoon.cert
/// (so the client container can load it from the shared eval_keys volume), then
/// accepts one connection and receives TRANSFER_BYTES bytes in chunks, then exits 0.
use std::{env, net::SocketAddr, process, sync::Arc};

use typhoon::{
    bytes::StaticByteBuffer,
    certificate::ServerKeyPair,
    defaults::{DefaultExecutor, DefaultServerConnectionHandler, AsyncExecutor},
    flow::{FakeBodyMode, FakeHeaderConfig, FlowConfig, decoy::SimpleDecoyProvider},
    settings::SettingsBuilder,
    socket::{ListenerBuilder, ServerFlowConfiguration},
};

const CERT_PATH: &str = "/keys/typhoon.cert";
const PORT:      u16  = 19999;
const CHUNK:     usize = 65536;

#[tokio::main]
async fn main() {
    // Route setup: add return route to client subnet via observer gateway
    if let Ok(gw) = env::var("OBSERVER_GW") {
        let _ = std::process::Command::new("ip")
            .args(["route", "add", "172.20.0.0/24", "via", &gw])
            .status();
    }

    let transfer_bytes: usize = env::var("TRANSFER_BYTES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(104_857_600);

    let settings = Arc::new(
        SettingsBuilder::<DefaultExecutor>::new()
            .build()
            .expect("default settings"),
    );

    // The certificate must contain the server's externally reachable address so the client
    // knows where to connect.
    let cert_ip   = env::var("CERT_HOST").unwrap_or_else(|_| "172.21.0.10".to_string());
    let cert_addr: SocketAddr = format!("{cert_ip}:{PORT}").parse().unwrap();
    let bind_addr: SocketAddr = format!("0.0.0.0:{PORT}").parse().unwrap();

    let key_pair    = ServerKeyPair::generate();
    let certificate = key_pair.to_client_certificate(vec![cert_addr]);

    // Save cert so the client container can load it
    certificate.save(CERT_PATH).expect("save cert to /keys/typhoon.cert");
    println!("Certificate saved to {CERT_PATH}");

    let flow_config = FlowConfig::new(FakeBodyMode::Empty, FakeHeaderConfig::new(vec![]));
    let listener: Arc<_> = Arc::new(
        ListenerBuilder::<StaticByteBuffer, DefaultExecutor, SimpleDecoyProvider, DefaultServerConnectionHandler>::new(
            key_pair,
            DefaultServerConnectionHandler,
        )
        .add_flow(ServerFlowConfiguration::with_address(flow_config, bind_addr))
        .with_settings(settings.clone())
        .build()
        .await
        .expect("listener build"),
    );
    listener.start().await;
    println!("TYPHOON eval server listening on :{PORT}");

    let client = listener.accept().await.expect("accept");
    println!("Client connected");

    let mut received: usize = 0;
    while received < transfer_bytes {
        let data = client.receive_bytes().await.expect("receive");
        received += data.len();
    }

    println!("Received {received}/{transfer_bytes} bytes — done");
    process::exit(0);
}
