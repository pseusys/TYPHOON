/// TYPHOON evaluation client.
///
/// Polls /keys/typhoon.cert until the server writes it, loads the certificate,
/// connects to the server, and runs a traffic scenario selected by TRAFFIC_SCENARIO.
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
    let scenario = var("TRAFFIC_SCENARIO").unwrap_or_else(|_| "bulk".to_string());

    info!(
        "config: transfer_bytes={transfer_bytes}, chunk={CHUNK}, delay_ms={delay_ms}, delay_every={delay_every}, scenario={scenario}"
    );

    // Wait for server to write the certificate.
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

    let mut sent: usize = 0;
    let mut total_sleep_ms: u64 = 0;
    let transfer_start = Instant::now();

    match scenario.as_str() {
        "bulk" | "echo" => {
            let chunk = vec![0u8; CHUNK];
            let mut packets: usize = 0;
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
        }
        "interactive" => {
            const ICHUNK: usize = 50;
            let chunk = vec![0u8; ICHUNK];
            while sent < transfer_bytes {
                let n = ICHUNK.min(transfer_bytes - sent);
                socket.send_bytes(&chunk[..n]).await.expect("send");
                sent += n;
                sleep(Duration::from_millis(100)).await;
                total_sleep_ms += 100;
            }
        }
        "streaming" => {
            const SCHUNK: usize = 1250;
            let chunk = vec![0u8; SCHUNK];
            while sent < transfer_bytes {
                let n = SCHUNK.min(transfer_bytes - sent);
                socket.send_bytes(&chunk[..n]).await.expect("send");
                sent += n;
                sleep(Duration::from_millis(10)).await;
                total_sleep_ms += 10;
            }
        }
        "burst" => {
            const BCHUNK: usize = 4096;
            let chunk = vec![0u8; BCHUNK];
            let burst_size = (transfer_bytes / 3).max(1);
            for burst_idx in 0..3usize {
                let burst_target = burst_size.min(transfer_bytes - sent);
                let mut burst_sent: usize = 0;
                while burst_sent < burst_target {
                    let n = BCHUNK.min(burst_target - burst_sent);
                    socket.send_bytes(&chunk[..n]).await.expect("send");
                    burst_sent += n;
                }
                sent += burst_sent;
                if burst_idx < 2 && sent < transfer_bytes {
                    sleep(Duration::from_secs(10)).await;
                    total_sleep_ms += 10_000;
                }
            }
        }
        "idle" => {
            socket.send_bytes(&[0u8; 8]).await.expect("send");
            sent = 8;
            sleep(Duration::from_secs(30)).await;
            total_sleep_ms += 30_000;
        }
        other => {
            eprintln!("unknown scenario {other:?}, falling back to bulk");
            let chunk = vec![0u8; CHUNK];
            while sent < transfer_bytes {
                let n = CHUNK.min(transfer_bytes - sent);
                socket.send_bytes(&chunk[..n]).await.expect("send");
                sent += n;
            }
        }
    }

    let transfer_time_s = transfer_start.elapsed().as_secs_f64() - total_sleep_ms as f64 / 1000.0;

    println!("Sent {sent}/{transfer_bytes} bytes — done");
    println!("transfer_time_s={transfer_time_s:.3}");
    exit(0);
}
