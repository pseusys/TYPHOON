//! TCP client — a spaced ping of small equal-sized messages echoed by the sink,
//! measuring per-packet round-trip time (see `eval_transport::latency`). Over a
//! reliable stream every echo returns, so delivery stays 100% and loss shows up
//! as higher RTT (retransmit) — the honest TCP behaviour.

use std::env::var;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::process::exit;
use std::thread::sleep;
use std::time::Duration;

use eval_transport::add_route;
use eval_transport::latency::{self, Config};

fn main() {
    add_route("172.21.0.0/24");
    let host = var("SERVER_HOST").expect("SERVER_HOST not set");
    let port: u16 = var("LISTEN_PORT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(9000);

    let mut stream = None;
    for _ in 0..30 {
        match TcpStream::connect((host.as_str(), port)) {
            Ok(s) => {
                stream = Some(s);
                break;
            }
            Err(_) => sleep(Duration::from_secs(1)),
        }
    }
    let Some(mut stream) = stream else {
        eprintln!("failed to connect to {host}:{port}");
        exit(1);
    };
    stream.set_nodelay(true).ok();

    let cfg = Config::from_env();
    stream.set_read_timeout(Some(cfg.recv_timeout)).ok();
    let mut rbuf = vec![0u8; cfg.size];
    latency::ping_loop(
        |m| {
            stream.write_all(m)?;
            stream.read_exact(&mut rbuf)?; // reliable: echo always arrives, or Err on close
            Ok(Some(rbuf.clone()))
        },
        &cfg,
    );
}
