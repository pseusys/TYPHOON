//! UDP client — a spaced ping of small equal-sized datagrams echoed by the sink,
//! measuring per-packet round-trip time in tunnel-like conditions
//! (see `eval_transport::latency`).

use std::env::var;
use std::io::ErrorKind;
use std::net::UdpSocket;
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

    let sock = UdpSocket::bind("0.0.0.0:0").expect("bind");
    sock.connect((host.as_str(), port)).expect("connect");
    sleep(Duration::from_millis(200)); // let the sink bind before the first probe

    let cfg = Config::from_env();
    sock.set_read_timeout(Some(cfg.recv_timeout)).ok();
    let mut buf = vec![0u8; cfg.size.max(2048)];
    latency::ping_loop(
        |m| {
            sock.send(m)?;
            match sock.recv(&mut buf) {
                Ok(n) => Ok(Some(buf[..n].to_vec())),
                Err(e) if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::TimedOut => {
                    Ok(None) // lost echo — keep pinging
                }
                Err(e) => Err(e),
            }
        },
        &cfg,
    );
}
