//! SOCKS5 client — connects to SERVER_HOST:SERVER_PORT through a local SOCKS5
//! proxy (Shadowsocks / Tor / VLESS / obfs4 / Hysteria2) and pings small
//! equal-sized messages the sink echoes, timing per-packet round-trips through
//! the proxy (see `eval_transport::latency`).
//!
//! obfs4's pluggable-transport args go in SOCKS5_USERNAME (password is a NUL).

use std::env::var;
use std::io::{Read, Write};
use std::process::exit;
use std::thread::sleep;
use std::time::Duration;

use eval_transport::add_route;
use eval_transport::latency::{self, Config};
use socks::Socks5Stream;

fn main() {
    add_route("172.21.0.0/24");
    let server_host = var("SERVER_HOST").expect("SERVER_HOST not set");
    let server_port: u16 = var("SERVER_PORT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(9000);
    let socks_host = var("SOCKS5_HOST").unwrap_or_else(|_| "127.0.0.1".to_string());
    let socks_port: u16 = var("SOCKS5_PORT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(1080);
    let user = var("SOCKS5_USERNAME").ok();

    let proxy = (socks_host.as_str(), socks_port);
    let target = (server_host.as_str(), server_port);

    let mut stream = None;
    for attempt in 0..30 {
        let res = match &user {
            Some(u) => Socks5Stream::connect_with_password(proxy, target, u, "\x00"),
            None => Socks5Stream::connect(proxy, target),
        };
        match res {
            Ok(s) => {
                stream = Some(s);
                break;
            }
            Err(e) => {
                println!("attempt {}/30: {e}", attempt + 1);
                sleep(Duration::from_secs(2));
            }
        }
    }
    let Some(mut stream) = stream else {
        eprintln!("failed to connect via SOCKS5");
        exit(1);
    };

    let cfg = Config::from_env();
    stream
        .get_ref()
        .set_read_timeout(Some(cfg.recv_timeout))
        .ok();
    let mut rbuf = vec![0u8; cfg.size];
    latency::ping_loop(
        |m| {
            stream.write_all(m)?;
            stream.read_exact(&mut rbuf)?;
            Ok(Some(rbuf.clone()))
        },
        &cfg,
    );
}
