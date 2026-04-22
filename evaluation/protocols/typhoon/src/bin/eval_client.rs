/// TYPHOON evaluation client.
///
/// Polls /keys/typhoon.cert until the server writes it, loads the certificate,
/// connects to the server, and sends TRANSFER_BYTES bytes in CHUNK-sized messages,
/// then exits 0.
use std::{env, path::Path, process, sync::Arc, time::Duration};

use typhoon::{
    bytes::StaticByteBuffer,
    certificate::ClientCertificate,
    defaults::{DefaultClientConnectionHandler, DefaultExecutor},
    flow::{FakeBodyMode, FakeHeaderConfig, FlowConfig, decoy::SimpleDecoyProvider},
    settings::SettingsBuilder,
    socket::ClientSocketBuilder,
};

const CERT_PATH: &str = "/keys/typhoon.cert";
const CHUNK: usize = 65536;

#[tokio::main]
async fn main() {
    if let Ok(gw) = env::var("OBSERVER_GW") {
        let _ = std::process::Command::new("ip")
            .args(["route", "add", "172.21.0.0/24", "via", &gw])
            .status();
    }

    let transfer_bytes: usize = env::var("TRANSFER_BYTES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(104_857_600);

    // Wait for server to write the certificate
    println!("Waiting for {CERT_PATH}...");
    for _ in 0..60 {
        if Path::new(CERT_PATH).exists() {
            break;
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    if !Path::new(CERT_PATH).exists() {
        eprintln!("Certificate never appeared at {CERT_PATH}");
        process::exit(1);
    }

    let certificate = ClientCertificate::load(CERT_PATH).expect("load cert");
    println!("Certificate loaded");

    let settings = Arc::new(
        SettingsBuilder::<DefaultExecutor>::new()
            .build()
            .expect("default settings"),
    );

    let socket = ClientSocketBuilder::<
        StaticByteBuffer,
        DefaultExecutor,
        SimpleDecoyProvider,
        DefaultClientConnectionHandler,
    >::new(certificate, DefaultClientConnectionHandler)
    .with_settings(settings.clone())
    .build()
    .await
    .expect("client socket build");
    println!("Connected to server");

    let chunk = vec![0u8; CHUNK];
    let mut sent: usize = 0;
    while sent < transfer_bytes {
        let n = CHUNK.min(transfer_bytes - sent);
        socket.send_bytes(&chunk[..n]).await.expect("send");
        sent += n;
    }

    println!("Sent {sent}/{transfer_bytes} bytes — done");
    process::exit(0);
}
