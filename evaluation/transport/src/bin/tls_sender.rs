//! TLS 1.3 client — a spaced ping of small equal-sized messages echoed by the
//! sink, timing per-packet round-trips over the TLS session
//! (see `eval_transport::latency`).

use std::env::var;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::Path;
use std::process::exit;
use std::thread::sleep;
use std::time::Duration;

use eval_transport::add_route;
use eval_transport::latency::{self, Config};
use eval_transport::tls::{client_config, install_provider};
use rustls::pki_types::ServerName;
use rustls::{ClientConnection, StreamOwned};

const CERT_PATH: &str = "/keys/tls_cert.pem";

fn main() {
    install_provider();
    add_route("172.21.0.0/24");
    let host = var("SERVER_HOST").expect("SERVER_HOST not set");
    let port: u16 = var("LISTEN_PORT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(9000);

    for _ in 0..30 {
        if Path::new(CERT_PATH).exists() {
            break;
        }
        sleep(Duration::from_secs(1));
    }

    let config = client_config();

    let mut sock = None;
    for _ in 0..30 {
        match TcpStream::connect((host.as_str(), port)) {
            Ok(s) => {
                sock = Some(s);
                break;
            }
            Err(_) => sleep(Duration::from_secs(1)),
        }
    }
    let Some(sock) = sock else {
        eprintln!("failed to connect to {host}:{port}");
        exit(1);
    };
    sock.set_nodelay(true).ok();

    let cfg = Config::from_env();
    sock.set_read_timeout(Some(cfg.recv_timeout)).ok();
    let server_name = ServerName::try_from("tls-eval").unwrap();
    let conn = ClientConnection::new(config, server_name).expect("client conn");
    let mut tls = StreamOwned::new(conn, sock);

    let mut rbuf = vec![0u8; cfg.size];
    latency::ping_loop(
        |m| {
            tls.write_all(m)?;
            tls.read_exact(&mut rbuf)?;
            Ok(Some(rbuf.clone()))
        },
        &cfg,
    );
}
