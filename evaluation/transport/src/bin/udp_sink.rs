//! UDP sink — an echo server: reflects each probe back to its sender so the
//! client can time round-trips (see `eval_transport::latency`). Reports one-way
//! (c2s) delivery.

use std::net::UdpSocket;
use std::os::unix::io::AsRawFd;
use std::process::exit;
use std::time::Duration;

use eval_transport::add_route;
use eval_transport::idle_timeout_s;
use eval_transport::latency::{self, Config};

const PORT: u16 = 9000;
const RCVBUF_BYTES: libc::c_int = 64 * 1024 * 1024;

fn main() {
    add_route("172.20.0.0/24");

    let sock = UdpSocket::bind(("0.0.0.0", PORT)).expect("bind");
    set_rcvbuf(&sock);
    sock.set_read_timeout(Some(Duration::from_secs(idle_timeout_s())))
        .ok();
    println!("UDP sink ready on :{PORT}");

    let cfg = Config::from_env();
    let mut buf = vec![0u8; cfg.size.max(2048)];
    latency::echo_loop(
        || match sock.recv_from(&mut buf) {
            Ok((n, from)) => {
                sock.send_to(&buf[..n], from)?;
                Ok(true)
            }
            Err(_) => Ok(false), // idle timeout ends the run
        },
        &cfg,
    );
    exit(0);
}

/// SO_RCVBUFFORCE bypasses net.core.rmem_max with CAP_NET_ADMIN; fall back to
/// SO_RCVBUF (capped) if that fails.
fn set_rcvbuf(sock: &UdpSocket) {
    let fd = sock.as_raw_fd();
    let sz = RCVBUF_BYTES;
    let len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    let ptr = std::ptr::addr_of!(sz).cast();
    unsafe {
        if libc::setsockopt(fd, libc::SOL_SOCKET, libc::SO_RCVBUFFORCE, ptr, len) != 0 {
            libc::setsockopt(fd, libc::SOL_SOCKET, libc::SO_RCVBUF, ptr, len);
        }
    }
}
