//! Tor OR simulator sink — self-signed cert to /keys/tor_cert.pem (client
//! readiness gate), accepts one TLS connection on the conventional ORPort 9001
//! and echoes each probe as a fresh RELAY cell (see `eval_transport::latency`).
//! Reports one-way (c2s) delivery.

use std::fs::write;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::process::exit;
use std::time::Duration;

use eval_transport::add_route;
use eval_transport::idle_timeout_s;
use eval_transport::latency::{self, Config};
use eval_transport::tls::{install_provider, server_config};
use rand::RngCore;
use rustls::{ServerConnection, StreamOwned};

const PORT: u16 = 9001;
const CELL: usize = 514;
const DATA_PER_CELL: usize = 498;
const LENGTH_OFFSET: usize = 14;
const CERT_PATH: &str = "/keys/tor_cert.pem";

/// Build a 514-byte RELAY_DATA cell around `data` (≤498 B) — mirror of the sender.
fn make_relay_cell(data: &[u8]) -> [u8; CELL] {
    let mut cell = [0u8; CELL];
    cell[0..4].copy_from_slice(&1u32.to_be_bytes());
    cell[4] = 3;
    cell[5] = 2;
    cell[8..10].copy_from_slice(&[0, 1]);
    rand::thread_rng().fill_bytes(&mut cell[10..14]);
    cell[LENGTH_OFFSET..16].copy_from_slice(&(data.len() as u16).to_be_bytes());
    cell[16..16 + data.len()].copy_from_slice(data);
    cell
}

fn main() {
    install_provider();
    add_route("172.20.0.0/24");

    let (config, cert_pem) = server_config("tor-eval");
    write(CERT_PATH, cert_pem).expect("write cert");

    let listener = TcpListener::bind(("0.0.0.0", PORT)).expect("bind");
    println!("Tor OR simulator listening on :{PORT}");
    let (sock, _) = listener.accept().expect("accept");
    sock.set_read_timeout(Some(Duration::from_secs(idle_timeout_s())))
        .ok();
    let conn = ServerConnection::new(config).expect("server conn");
    let mut tls = StreamOwned::new(conn, sock);

    let cfg = Config::from_env();
    let mut rbuf = [0u8; CELL];
    latency::echo_loop(
        || match tls.read_exact(&mut rbuf) {
            Ok(()) => {
                let len = (u16::from_be_bytes([rbuf[LENGTH_OFFSET], rbuf[LENGTH_OFFSET + 1]])
                    as usize)
                    .min(DATA_PER_CELL);
                tls.write_all(&make_relay_cell(&rbuf[16..16 + len]))?;
                Ok(true)
            }
            Err(_) => Ok(false),
        },
        &cfg,
    );
    exit(0);
}
