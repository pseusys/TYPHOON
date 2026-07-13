//! TCP sink — an echo server: reads each fixed-size probe and writes it straight
//! back (see `eval_transport::latency`). Reports one-way (c2s) delivery.

use std::env::var;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::process::exit;
use std::time::Duration;

use eval_transport::add_route;
use eval_transport::idle_timeout_s;
use eval_transport::latency::{self, Config};

fn main() {
    add_route("172.20.0.0/24");
    // Honour LISTEN_PORT so a proxy fronting the sink can own :9000 and forward
    // to the sink on another port (e.g. obfs4proxy → ORPORT 9001).
    let port: u16 = var("LISTEN_PORT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(9000);

    let listener = TcpListener::bind(("0.0.0.0", port)).expect("bind");
    println!("TCP sink ready on :{port}");

    let (mut conn, _) = listener.accept().expect("accept");
    conn.set_read_timeout(Some(Duration::from_secs(idle_timeout_s())))
        .ok();

    let cfg = Config::from_env();
    let mut rbuf = vec![0u8; cfg.size];
    latency::echo_loop(
        || match conn.read_exact(&mut rbuf) {
            Ok(()) => {
                conn.write_all(&rbuf)?;
                Ok(true)
            }
            Err(_) => Ok(false), // EOF / idle / reset ends the run
        },
        &cfg,
    );
    exit(0);
}
