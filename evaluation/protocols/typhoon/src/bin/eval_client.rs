/// TYPHOON evaluation client.
///
/// Polls /keys/typhoon.cert until the server writes it, loads the certificate,
/// connects to the server, and sends TRANSFER_BYTES bytes in CHUNK-sized messages,
/// then exits 0.
use std::env::var;
use std::path::Path;
use std::process::{Command, exit};
use std::sync::Arc;
use std::time::{Duration, Instant};

use env_logger::{Builder, Env};
use log::info;
use tokio::time::sleep;

use typhoon::{
    bytes::StaticByteBuffer,
    certificate::ClientCertificate,
    defaults::{DefaultClientConnectionHandler, DefaultExecutor},
    settings::SettingsBuilder,
    socket::ClientSocketBuilder,
};

const CERT_PATH: &str = "/keys/typhoon.cert";
const CHUNK: usize = 500;

#[tokio::main]
async fn main() {
    Builder::from_env(Env::default().default_filter_or("typhoon=debug")).init();

    if let Ok(gw) = var("OBSERVER_GW") {
        let _ = Command::new("ip")
            .args(["route", "add", "172.21.0.0/24", "via", &gw])
            .status();
    }

    let transfer_bytes: usize = var("TRANSFER_BYTES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(104_857_600);

    let delay_ms: u64 = var("INTER_PACKET_DELAY_MS")
        .ok()
        .and_then(|v| v.parse::<f64>().ok())
        .map(|f| f as u64)
        .unwrap_or(0);
    let delay_every: usize = var("DELAY_EVERY_N")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(1);

    info!("config: transfer_bytes={transfer_bytes}, chunk={CHUNK}, delay_ms={delay_ms}, delay_every={delay_every}");

    // Wait for server to write the certificate
    println!("Waiting for {CERT_PATH}...");
    for _ in 0..60 {
        if Path::new(CERT_PATH).exists() {
            break;
        }
        sleep(Duration::from_secs(1)).await;
    }
    if !Path::new(CERT_PATH).exists() {
        eprintln!("Certificate never appeared at {CERT_PATH}");
        exit(1);
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
        DefaultClientConnectionHandler,
    >::new(certificate, DefaultClientConnectionHandler)
    .with_settings(settings.clone())
    .build()
    .await
    .expect("client socket build");
    println!("Connected to server");

    let chunk = vec![0u8; CHUNK];
    let mut sent: usize = 0;
    let mut packets: usize = 0;
    let mut total_sleep_ms: u64 = 0;
    let transfer_start = Instant::now();
    while sent < transfer_bytes {
        let n = CHUNK.min(transfer_bytes - sent);
        socket.send_bytes(&chunk[..n]).await.expect("send");
        sent += n;
        packets += 1;
        if delay_ms > 0 && packets % delay_every == 0 {
            sleep(Duration::from_millis(delay_ms)).await;
            total_sleep_ms += delay_ms;
        }
    }
    let transfer_time_s = transfer_start.elapsed().as_secs_f64() - total_sleep_ms as f64 / 1000.0;

    println!("Sent {sent}/{transfer_bytes} bytes — done");
    println!("transfer_time_s={transfer_time_s:.3}");
    exit(0);
}
