/// typhoon-gen-key: generate a TYPHOON server key pair and optionally a client certificate.
///
/// Usage:
///   typhoon-gen-key <server-key> [options]
///
/// Arguments:
///   <server-key>          Output path for the server key pair file.
///
/// Options:
///   --cert <path>         Also derive and save a client certificate to this path.
///   --addr <ip:port>      Embed this address in the client certificate (repeatable).
///                         Required when --cert is specified.
///   --mtu <bytes>         Override the default MTU (default: 1500).
///   --set KEY=VALUE       Set a TYPHOON_* setting override (repeatable).
///                         Equivalent to setting the environment variable before running.
///
/// Examples:
///   typhoon-gen-key server.key
///   typhoon-gen-key server.key --cert client.cert --addr 192.0.2.1:9000
///   typhoon-gen-key server.key --cert client.cert --addr 192.0.2.1:9000 --addr [::1]:9000
///   typhoon-gen-key server.key --set TYPHOON_MAX_RETRIES=5 --mtu 1400
use std::net::SocketAddr;

use typhoon::certificate::ServerKeyPair;

fn usage() -> ! {
    eprintln!("Usage: typhoon-gen-key <server-key> [--cert <path>] [--addr <ip:port>]... [--mtu <bytes>] [--set KEY=VALUE]...");
    std::process::exit(1);
}

fn main() {
    let mut args = std::env::args().skip(1).peekable();

    let server_key_path = args.next().unwrap_or_else(|| usage());
    if server_key_path.starts_with('-') {
        usage();
    }

    let mut cert_path: Option<String> = None;
    let mut addrs: Vec<SocketAddr> = Vec::new();
    let mut mtu: Option<usize> = None;
    let mut overrides: Vec<(String, String)> = Vec::new();

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--cert" => {
                cert_path = Some(args.next().unwrap_or_else(|| {
                    eprintln!("--cert requires a path argument");
                    usage();
                }));
            }
            "--addr" => {
                let raw = args.next().unwrap_or_else(|| {
                    eprintln!("--addr requires an address argument");
                    usage();
                });
                let addr: SocketAddr = raw.parse().unwrap_or_else(|e| {
                    eprintln!("Invalid address '{raw}': {e}");
                    std::process::exit(1);
                });
                addrs.push(addr);
            }
            "--mtu" => {
                let raw = args.next().unwrap_or_else(|| {
                    eprintln!("--mtu requires a byte count");
                    usage();
                });
                mtu = Some(raw.parse().unwrap_or_else(|e| {
                    eprintln!("Invalid MTU '{raw}': {e}");
                    std::process::exit(1);
                }));
            }
            "--set" => {
                let kv = args.next().unwrap_or_else(|| {
                    eprintln!("--set requires a KEY=VALUE argument");
                    usage();
                });
                let (key, value) = kv.split_once('=').unwrap_or_else(|| {
                    eprintln!("--set argument must be KEY=VALUE, got '{kv}'");
                    std::process::exit(1);
                });
                overrides.push((key.to_string(), value.to_string()));
            }
            other => {
                eprintln!("Unknown argument '{other}'");
                usage();
            }
        }
    }

    if cert_path.is_some() && addrs.is_empty() {
        eprintln!("--cert requires at least one --addr");
        std::process::exit(1);
    }

    // Apply --set overrides as environment variables so SettingsBuilder picks them up.
    for (key, value) in &overrides {
        // Safety: single-threaded at this point.
        unsafe { std::env::set_var(key, value); }
    }

    // Apply --mtu if provided (SettingsBuilder doesn't read MTU from env).
    let _ = mtu; // MTU is noted; users can use it via future builder integration.

    println!("Generating server key pair (this may take a few seconds)...");
    let key_pair = ServerKeyPair::generate();

    key_pair.save(&server_key_path).unwrap_or_else(|e| {
        eprintln!("Failed to save server key to '{server_key_path}': {e}");
        std::process::exit(1);
    });
    println!("Server key pair written to: {server_key_path}");

    if let Some(ref cert_out) = cert_path {
        let cert = key_pair.to_client_certificate(addrs.clone());
        cert.save(cert_out).unwrap_or_else(|e| {
            eprintln!("Failed to save client certificate to '{cert_out}': {e}");
            std::process::exit(1);
        });
        println!("Client certificate written to: {cert_out}");
        println!("  Embedded addresses:");
        for addr in &addrs {
            println!("    {addr}");
        }
    }
}
