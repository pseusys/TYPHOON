//! Shared evaluation helpers for the TYPHOON eval client/server binaries.
//!
//! - `profile`: runtime-configurable traffic profiles selected via the
//!   `TRAFFIC_PROFILE` environment variable.
//! - `identity`: 4-byte `ShortIdentity` type + matching server handler used
//!   by both binaries to lower the per-packet wire-overhead floor.

pub mod identity;
pub mod profile;

/// Host-wide monotonic clock in nanoseconds. Docker containers share the kernel
/// clock (no time namespace by default), so the client's `send_start/end` and
/// the server's `recv_first/last` readings are directly comparable — the basis
/// for the cross-endpoint transfer timings the analysis derives.
pub fn monotonic_ns() -> u128 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    unsafe {
        libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts);
    }
    (ts.tv_sec as u128) * 1_000_000_000 + (ts.tv_nsec as u128)
}

/// Latency-mode helpers (a duplicate of the shared `eval-transport::latency`
/// contract, since the two eval crates don't share a dependency). The client
/// pings small equal-sized probes that the server echoes; RTT is timed on the
/// client. See the transport crate for the rationale.
pub mod latency {
    use std::env::var;
    use std::time::Duration;

    pub const HEADER: usize = 20; // seq(4) + send_ns(16)

    /// Ping parameters: probe count, spacing, fixed size, and per-echo timeout.
    pub struct Config {
        pub count: u32,
        pub interval: Duration,
        pub size: usize,
        pub recv_timeout: Duration,
    }

    impl Config {
        /// Read the config from the `LAT_*` env vars (harness-set).
        pub fn from_env() -> Self {
            Self {
                count: env_u32("LAT_COUNT", 500),
                interval: Duration::from_secs_f64(env_f64("LAT_INTERVAL_MS", 20.0) / 1000.0),
                size: (env_u32("LAT_SIZE", 256) as usize).max(HEADER),
                recv_timeout: Duration::from_secs_f64(
                    env_f64("LAT_RECV_TIMEOUT_MS", 5000.0) / 1000.0,
                ),
            }
        }
    }

    pub fn pack(seq: u32, send_ns: u128, size: usize) -> Vec<u8> {
        let mut m = vec![0u8; size];
        m[0..4].copy_from_slice(&seq.to_be_bytes());
        m[4..HEADER].copy_from_slice(&send_ns.to_be_bytes());
        m
    }

    pub fn send_ns_of(msg: &[u8]) -> u128 {
        let mut b = [0u8; 16];
        b.copy_from_slice(&msg[4..HEADER]);
        u128::from_be_bytes(b)
    }

    /// Print the client `sent` / `roundtrip_delivery_pct` / `rtt_*` contract.
    pub fn print_client_report(rtts: &mut [f64], count: u32) {
        println!("sent {count} packets");
        let delivery = rtts.len() as f64 / count.max(1) as f64 * 100.0;
        println!("roundtrip_delivery_pct={delivery:.1}");
        if !rtts.is_empty() {
            rtts.sort_by(|a, b| a.partial_cmp(b).unwrap());
            let pct = |p: f64| rtts[(((rtts.len() - 1) as f64) * p).round() as usize];
            let p50 = pct(0.50);
            let p95 = pct(0.95);
            println!("rtt_min_ms={:.3}", rtts[0]);
            println!("rtt_p50_ms={p50:.3}");
            println!("rtt_p95_ms={p95:.3}");
            println!("rtt_p99_ms={:.3}", pct(0.99));
            println!("rtt_jitter_ms={:.3}", p95 - p50);
        }
    }

    fn env_u32(key: &str, default: u32) -> u32 {
        var(key)
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(default)
    }

    fn env_f64(key: &str, default: f64) -> f64 {
        var(key)
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(default)
    }
}
