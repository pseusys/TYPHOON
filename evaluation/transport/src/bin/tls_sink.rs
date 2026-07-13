//! TLS 1.3 sink — self-signed cert to /keys/tls_cert.pem (client readiness gate),
//! accepts one TLS connection and echoes each fixed-size probe
//! (see `eval_transport::latency`). Reports one-way (c2s) delivery.

use std::fs::write;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::process::exit;
use std::time::Duration;

use eval_transport::add_route;
use eval_transport::idle_timeout_s;
use eval_transport::latency::{self, Config};
use eval_transport::tls::{install_provider, server_config};
use rustls::{ServerConnection, StreamOwned};

const PORT: u16 = 9000;
const CERT_PATH: &str = "/keys/tls_cert.pem";

fn main() {
    install_provider();
    add_route("172.20.0.0/24");

    let (config, cert_pem) = server_config("tls-eval");
    write(CERT_PATH, cert_pem).expect("write cert");

    let listener = TcpListener::bind(("0.0.0.0", PORT)).expect("bind");
    println!("TLS sink ready on :{PORT}");
    let (sock, _) = listener.accept().expect("accept");
    sock.set_read_timeout(Some(Duration::from_secs(idle_timeout_s())))
        .ok();
    let conn = ServerConnection::new(config).expect("server conn");
    let mut tls = StreamOwned::new(conn, sock);

    let cfg = Config::from_env();
    let mut rbuf = vec![0u8; cfg.size];
    latency::echo_loop(
        || match tls.read_exact(&mut rbuf) {
            Ok(()) => {
                tls.write_all(&rbuf)?;
                Ok(true)
            }
            Err(_) => Ok(false),
        },
        &cfg,
    );
    exit(0);
}
