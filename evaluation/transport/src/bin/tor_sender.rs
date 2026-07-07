//! Tor link-protocol-v4 client — wraps traffic in fixed 514-byte RELAY cells
//! over TLS 1.3 (the same on-wire shape as a Tor ORPort). Pings small probes,
//! one per cell, that the sink echoes as cells, timing per-packet round-trips
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
use rand::RngCore;
use rustls::pki_types::ServerName;
use rustls::{ClientConnection, StreamOwned};

const PORT: u16 = 9001;
const CELL: usize = 514;
const DATA_PER_CELL: usize = 498;
const CERT_PATH: &str = "/keys/tor_cert.pem";

/// Build a 514-byte Tor link-protocol-v4 RELAY_DATA cell around `data` (≤498 B).
fn make_relay_cell(data: &[u8]) -> [u8; CELL] {
    let mut cell = [0u8; CELL];
    cell[0..4].copy_from_slice(&1u32.to_be_bytes()); // circid
    cell[4] = 3; // CMD_RELAY
    cell[5] = 2; // relay_cmd = RELAY_DATA
    cell[6..8].copy_from_slice(&[0, 0]); // recognized
    cell[8..10].copy_from_slice(&[0, 1]); // stream_id
    rand::thread_rng().fill_bytes(&mut cell[10..14]); // digest (random for realism)
    cell[14..16].copy_from_slice(&(data.len() as u16).to_be_bytes()); // length
    cell[16..16 + data.len()].copy_from_slice(data); // payload, zero-padded
    cell
}

/// Extract the RELAY_DATA payload from a 514-byte cell.
fn cell_data(cell: &[u8]) -> Vec<u8> {
    let len = (u16::from_be_bytes([cell[14], cell[15]]) as usize).min(DATA_PER_CELL);
    cell[16..16 + len].to_vec()
}

fn main() {
    install_provider();
    add_route("172.21.0.0/24");
    let host = var("SERVER_HOST").expect("SERVER_HOST not set");

    for _ in 0..30 {
        if Path::new(CERT_PATH).exists() {
            break;
        }
        sleep(Duration::from_secs(1));
    }

    let config = client_config();

    let mut sock = None;
    for _ in 0..30 {
        match TcpStream::connect((host.as_str(), PORT)) {
            Ok(s) => {
                sock = Some(s);
                break;
            }
            Err(_) => sleep(Duration::from_secs(1)),
        }
    }
    let Some(sock) = sock else {
        eprintln!("failed to connect to {host}:{PORT}");
        exit(1);
    };
    sock.set_nodelay(true).ok();

    let cfg = Config::from_env();
    sock.set_read_timeout(Some(cfg.recv_timeout)).ok();
    let server_name = ServerName::try_from("tor-eval").unwrap();
    let conn = ClientConnection::new(config, server_name).expect("client conn");
    let mut tls = StreamOwned::new(conn, sock);

    let mut rbuf = [0u8; CELL];
    latency::ping_loop(
        |m| {
            tls.write_all(&make_relay_cell(m))?; // probe ≤ 498 B fits one cell
            tls.read_exact(&mut rbuf)?;
            Ok(Some(cell_data(&rbuf)))
        },
        &cfg,
    );
}
