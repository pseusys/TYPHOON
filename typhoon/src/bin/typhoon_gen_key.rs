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

    println!("Generating server key pair (this may take a few seconds)...");
    let key_pair = ServerKeyPair::generate();

    if let Some(parent) = std::path::Path::new(&args.server_key).parent() {
        std::fs::create_dir_all(parent).unwrap_or_else(|e| {
            eprintln!("Failed to create directories for '{}': {e}", args.server_key.display());
            std::process::exit(1);
        });
    }
    key_pair.save(&args.server_key).unwrap_or_else(|e| {
        eprintln!("Failed to save server key to '{}': {e}", args.server_key.display());
        std::process::exit(1);
    });
    println!("Server key pair written to: {}", args.server_key.display());

    if let Some(ref cert_out) = args.cert {
        if let Some(parent) = std::path::Path::new(cert_out).parent() {
            std::fs::create_dir_all(parent).unwrap_or_else(|e| {
                eprintln!("Failed to create directories for '{}': {e}", cert_out.display());
                std::process::exit(1);
            });
        }
        let cert = key_pair.to_client_certificate(args.addr.clone());
        cert.save(cert_out).unwrap_or_else(|e| {
            eprintln!("Failed to save client certificate to '{}': {e}", cert_out.display());
            std::process::exit(1);
        });
        println!("Client certificate written to: {}", cert_out.display());
        println!("  Embedded addresses:");
        for addr in &args.addr {
            println!("    {addr}");
        }
    }
}
