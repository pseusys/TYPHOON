/// typhoon-gen-key: generate a TYPHOON server key pair and optionally a client certificate.
use std::net::SocketAddr;
use std::path::PathBuf;

use clap::Parser;

use typhoon::certificate::ServerKeyPair;

/// Generate a TYPHOON server key pair and, optionally, a client certificate.
#[derive(Parser)]
#[command(name = "typhoon-gen-key", version)]
struct Args {
    /// Output path for the server key pair file.
    server_key: PathBuf,

    /// Also derive and save a client certificate to this path.
    #[arg(long, value_name = "PATH")]
    cert: Option<PathBuf>,

    /// Embed this address in the client certificate (required with --cert, repeatable).
    #[arg(long, value_name = "IP:PORT")]
    addr: Vec<SocketAddr>,

    /// Override the default MTU in bytes.
    #[arg(long, value_name = "BYTES")]
    mtu: Option<usize>,

    /// Set a TYPHOON_* setting override as KEY=VALUE (repeatable).
    #[arg(long = "set", value_name = "KEY=VALUE")]
    overrides: Vec<String>,
}

fn main() {
    let args = Args::parse();

    if args.cert.is_some() && args.addr.is_empty() {
        eprintln!("error: --cert requires at least one --addr");
        std::process::exit(1);
    }

    // Apply --set overrides as environment variables so SettingsBuilder picks them up.
    for kv in &args.overrides {
        let (key, value) = kv.split_once('=').unwrap_or_else(|| {
            eprintln!("error: --set argument must be KEY=VALUE, got '{kv}'");
            std::process::exit(1);
        });
        // Safety: single-threaded at this point.
        unsafe { std::env::set_var(key, value); }
    }

    let _ = args.mtu; // noted; future SettingsBuilder integration point.

    println!("Generating server key pair (this may take a few seconds)...");
    let key_pair = ServerKeyPair::generate();

    if let Some(parent) = std::path::Path::new(&server_key_path).parent() {
        std::fs::create_dir_all(parent).unwrap_or_else(|e| {
            eprintln!("Failed to create directories for '{server_key_path}': {e}");
            std::process::exit(1);
        });
    }
    key_pair.save(&server_key_path).unwrap_or_else(|e| {
        eprintln!("Failed to save server key to '{server_key_path}': {e}");
        std::process::exit(1);
    });
    println!("Server key pair written to: {}", args.server_key.display());

    if let Some(ref cert_out) = cert_path {
        if let Some(parent) = std::path::Path::new(cert_out).parent() {
            std::fs::create_dir_all(parent).unwrap_or_else(|e| {
                eprintln!("Failed to create directories for '{cert_out}': {e}");
                std::process::exit(1);
            });
        }
        let cert = key_pair.to_client_certificate(addrs.clone());
        cert.save(cert_out).unwrap_or_else(|e| {
            eprintln!("Failed to save client certificate to '{cert_out}': {e}");
            std::process::exit(1);
        });
        println!("Client certificate written to: {}", cert_out.display());
        println!("  Embedded addresses:");
        for addr in &args.addr {
            println!("    {addr}");
        }
    }
}
