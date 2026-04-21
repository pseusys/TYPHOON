/// typhoon-debug: run TYPHOON debug diagnostics against a server.
///
/// Usage:
///   typhoon-debug <certificate> [mode]
///
/// Arguments:
///   certificate   Path to a client certificate file (.typhoon)
///   mode          Optional: reachability | rtt | throughput | all  (default: all)
///
/// Example:
///   typhoon-debug server.client.typhoon
///   typhoon-debug server.client.typhoon rtt
use std::process::exit;
use std::sync::Arc;

#[cfg(not(feature = "tokio"))]
use futures::executor::block_on;
#[cfg(feature = "tokio")]
use tokio::runtime::Runtime;
use typhoon::certificate::ClientCertificate;
use typhoon::debug::{DebugMode, run_debug};
use typhoon::defaults::DefaultExecutor;
use typhoon::settings::SettingsBuilder;

fn usage() -> ! {
    eprintln!("Usage: typhoon-debug <certificate> [reachability|rtt|throughput|all]");
    exit(1);
}

#[cfg(feature = "tokio")]
fn main() {
    Runtime::new().expect("failed to create tokio runtime").block_on(run_cli());
}

#[cfg(not(feature = "tokio"))]
fn main() {
    block_on(run_cli());
}

async fn run_cli() {
    let mut args = std::env::args().skip(1);

    let cert_path = args.next().unwrap_or_else(|| usage());
    let mode = match args.next().as_deref() {
        None | Some("all") => DebugMode::All,
        Some("reachability") => DebugMode::Reachability,
        Some("rtt") => DebugMode::ReturnTime,
        Some("throughput") => DebugMode::Throughput,
        Some(other) => {
            eprintln!("Unknown mode '{other}'. Expected: reachability | rtt | throughput | all");
            usage();
        }
    };

    let certificate = ClientCertificate::load(&cert_path).unwrap_or_else(|e| {
        eprintln!("Failed to load certificate '{}': {}", cert_path, e);
        exit(1);
    });

    let settings = Arc::new(SettingsBuilder::<DefaultExecutor>::new().build().expect("default settings should be valid"));

    println!("Certificate: {}", cert_path);
    println!("Mode:        {:?}", mode);
    println!("Addresses:   {:?}", certificate.addresses());
    println!();

    let result = run_debug(certificate, mode, settings).await;

    println!("Results:");
    if let Some(r) = result.reachable {
        println!("  reachable:      {}", r);
    }
    if let Some(rtt) = result.rtt_ms {
        println!("  rtt:            {:.2} ms", rtt);
    }
    if let Some(bps) = result.throughput_bps {
        println!("  throughput:     {:.0} B/s  ({:.2} Mbit/s)", bps, bps * 8.0 / 1_000_000.0);
    }
    println!("  packets sent:   {}", result.packets_sent);
    println!("  packets recv:   {}", result.packets_received);
}
