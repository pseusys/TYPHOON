/// TYPHOON evaluation server.
///
/// Generates a ServerKeyPair, saves the ClientCertificate to /keys/typhoon.cert
/// (so the client container can load it from the shared eval_keys volume), then
/// accepts one connection and receives TRANSFER_BYTES bytes in chunks, then exits 0.
use std::env::var;
use std::net::SocketAddr;
use std::process;
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

use tokio::time::timeout;

use typhoon::bytes::StaticByteBuffer;
use typhoon::certificate::ServerKeyPair;
use typhoon::defaults::{DefaultExecutor, DefaultServerConnectionHandler};
use typhoon::flow::{FakeBodyMode, FakeHeaderConfig, FlowConfig};
use typhoon::settings::SettingsBuilder;
use typhoon::socket::{ListenerBuilder, ServerFlowConfiguration};

const CERT_PATH: &str = "/keys/typhoon.cert";
const PORTS: [u16; 3] = [19999, 19998, 19997];

#[tokio::main]
async fn main() {
    // Route setup: add return route to client subnet via observer gateway
    if let Ok(gw) = var("OBSERVER_GW") {
        let _ = Command::new("ip")
            .args(["route", "add", "172.20.0.0/24", "via", &gw])
            .status();
    }

    let transfer_bytes: usize = var("TRANSFER_BYTES")
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
    let cert_ip = var("CERT_HOST").unwrap_or_else(|_| "172.21.0.10".to_string());
    let cert_addrs: Vec<SocketAddr> = PORTS
        .iter()
        .map(|p| format!("{cert_ip}:{p}").parse().unwrap())
        .collect();
    let bind_addrs: Vec<SocketAddr> = PORTS
        .iter()
        .map(|p| format!("0.0.0.0:{p}").parse().unwrap())
        .collect();

    let key_pair = ServerKeyPair::generate();
    let certificate = key_pair.to_client_certificate(cert_addrs);

    certificate
        .save(CERT_PATH)
        .expect("save cert to /keys/typhoon.cert");
    println!("Certificate saved to {CERT_PATH}");

    let flow_config = FlowConfig::new(FakeBodyMode::Empty, FakeHeaderConfig::new(vec![]));
    let flows: Vec<ServerFlowConfiguration<StaticByteBuffer, DefaultExecutor>> = bind_addrs
        .into_iter()
        .map(|addr| ServerFlowConfiguration::with_address(flow_config.clone(), addr))
        .collect();
    let listener: Arc<_> = Arc::new(
        ListenerBuilder::<StaticByteBuffer, DefaultExecutor, DefaultServerConnectionHandler>::new(
            key_pair,
            DefaultServerConnectionHandler,
        )
        .with_flows(flows)
        .with_settings(settings.clone())
        .build()
        .await
        .expect("listener build"),
    );
    listener.start().await;
    println!("TYPHOON eval server listening on ports {:?}", PORTS);

    let idle_timeout = Duration::from_secs(
        var("IDLE_TIMEOUT_S").ok().and_then(|v| v.parse().ok()).unwrap_or(120),
    );

    let client = listener.accept().await.expect("accept");
    println!("Client connected");

    let mut received: usize = 0;
    loop {
        match timeout(idle_timeout, client.receive_bytes()).await {
            Ok(Ok(data)) => {
                received += data.len();
                if received >= transfer_bytes {
                    break;
                }
            }
            Ok(Err(_)) => break,
            Err(_) => break,
        }
    }

    let pct = received as f64 / transfer_bytes as f64 * 100.0;
    println!("Received {received}/{transfer_bytes} bytes ({pct:.1}%) — done");
    process::exit(0);
}
