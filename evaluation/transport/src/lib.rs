//! Shared helpers for the eval transport binaries: the per-packet latency ping
//! (`latency` module), the cross-endpoint monotonic clock, forward routing, and
//! (in the `tls` module) the rustls plumbing used by the TLS and Tor binaries.
//! Blocking (std) — a sequential ping needs no async runtime.

use std::env::var;

/// Best-effort forward route to the opposite /24 via the observer tap.
pub fn add_route(default_subnet: &str) {
    if let Ok(gw) = var("OBSERVER_GW") {
        if !gw.is_empty() {
            let subnet = var("FORWARD_SUBNET").unwrap_or_else(|_| default_subnet.to_string());
            let _ = std::process::Command::new("ip")
                .args(["route", "add", &subnet, "via", &gw])
                .status();
        }
    }
}

/// Idle timeout (s) after which an echo sink gives up waiting for more probes.
pub fn idle_timeout_s() -> u64 {
    var("IDLE_TIMEOUT_S")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(30)
}

/// Host-wide monotonic clock in nanoseconds. Docker containers share the kernel
/// clock (no time namespace by default), so client and server readings are
/// directly comparable — the basis for the cross-endpoint transfer timings.
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

/// Round-trip per-packet latency probe — the operational default. A spaced ping
/// of small, equal-sized packets that the sink echoes verbatim, so we measure
/// each protocol's inherent per-packet cost (client processing + wire + server
/// processing, both ways) in tunnel-like conditions, without the bulk pressure
/// that best-effort transports are *designed* to shed. Sequential (one packet
/// outstanding) so it works over any transport, including a single TLS session,
/// with no threading: a lost UDP echo simply times out and counts as loss, while
/// a reliable transport always echoes (its RTT just grows under retransmit).
pub mod latency {
    use std::env::var;
    use std::io;
    use std::thread::sleep;
    use std::time::{Duration, Instant};

    use rand::RngCore;

    use super::monotonic_ns;

    /// Probe header: `seq: u32 BE` + `send_ns: u128 BE`.
    pub const HEADER: usize = 20;

    /// Ping parameters: how many probes, their spacing, their fixed size, and
    /// how long to wait for one echo before treating it as lost.
    pub struct Config {
        pub count: u32,
        pub interval: Duration,
        pub size: usize,
        pub recv_timeout: Duration,
    }

    impl Config {
        /// Read the config from the `LAT_*` env vars (harness-set; defaults match
        /// the orchestrator).
        pub fn from_env() -> Self {
            let count = env_u32("LAT_COUNT", 500);
            let interval = Duration::from_secs_f64(env_f64("LAT_INTERVAL_MS", 20.0) / 1000.0);
            let size = (env_u32("LAT_SIZE", 256) as usize).max(HEADER);
            let recv_timeout =
                Duration::from_secs_f64(env_f64("LAT_RECV_TIMEOUT_MS", 5000.0) / 1000.0);
            Self {
                count,
                interval,
                size,
                recv_timeout,
            }
        }
    }

    /// Build a `size`-byte probe: seq + monotonic send timestamp + random pad
    /// (random so payload entropy matches a real encrypted packet).
    pub fn pack(seq: u32, send_ns: u128, size: usize, pad: &[u8]) -> Vec<u8> {
        let mut m = vec![0u8; size];
        m[0..4].copy_from_slice(&seq.to_be_bytes());
        m[4..HEADER].copy_from_slice(&send_ns.to_be_bytes());
        let n = size.saturating_sub(HEADER).min(pad.len());
        m[HEADER..HEADER + n].copy_from_slice(&pad[..n]);
        m
    }

    /// Recover the send timestamp an echo carries.
    pub fn send_ns_of(msg: &[u8]) -> u128 {
        let mut b = [0u8; 16];
        b.copy_from_slice(&msg[4..HEADER]);
        u128::from_be_bytes(b)
    }

    /// Client side: for each probe, `probe(msg)` sends it and returns its echo —
    /// `Ok(Some(echo))` (RTT recorded), `Ok(None)` for a UDP-style lost echo
    /// (miss, keep going), or `Err` for a dead/EOF stream (stop). A single closure
    /// (send-then-receive) so it can hold the one `&mut` a stream needs. Prints
    /// the `sent`, round-trip delivery, and `rtt_*` contract.
    pub fn ping_loop(mut probe: impl FnMut(&[u8]) -> io::Result<Option<Vec<u8>>>, cfg: &Config) {
        let mut pad = vec![0u8; cfg.size];
        rand::thread_rng().fill_bytes(&mut pad);
        let mut rtts: Vec<f64> = Vec::with_capacity(cfg.count as usize);

        for seq in 0..cfg.count {
            let send_ns = monotonic_ns();
            let msg = pack(seq, send_ns, cfg.size, &pad);
            let t_send = Instant::now();
            match probe(&msg) {
                Ok(Some(echo)) if echo.len() >= HEADER => {
                    let rtt_ms = (monotonic_ns().saturating_sub(send_ns_of(&echo))) as f64 / 1e6;
                    rtts.push(rtt_ms);
                }
                Ok(_) => {}      // lost echo (UDP) — count as a miss, continue
                Err(_) => break, // stream dead / peer gone
            }
            let elapsed = t_send.elapsed();
            if elapsed < cfg.interval {
                sleep(cfg.interval - elapsed);
            }
        }

        let echoed = rtts.len() as u32;
        println!("sent {} packets", cfg.count);
        let delivery = echoed as f64 / cfg.count.max(1) as f64 * 100.0;
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

    /// Server side: `serve()` receives one probe and echoes it, returning
    /// `Ok(true)` (handled), `Ok(false)` (idle/EOF — stop), or `Err` (stop). One
    /// closure (receive-then-send) for the same `&mut` reason as `ping_loop`.
    /// Prints one-way (c2s) delivery in the shared `received N/M packets (P%)`
    /// form the harness parses.
    pub fn echo_loop(mut serve: impl FnMut() -> io::Result<bool>, cfg: &Config) {
        let mut received = 0u32;
        while received < cfg.count {
            match serve() {
                Ok(true) => received += 1,
                _ => break, // idle / EOF / error
            }
        }
        let delivery = received as f64 / cfg.count.max(1) as f64 * 100.0;
        println!("received {received}/{} packets ({delivery:.1}%)", cfg.count);
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

/// Shared rustls plumbing for the TLS-based binaries (tls, tor): a self-signed
/// server config and a verification-skipping client config. The eval measures
/// transport behaviour, not a real PKI, so cert trust is intentionally bypassed.
pub mod tls {
    use std::sync::Arc;

    use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
    use rustls::pki_types::{
        CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime,
    };
    use rustls::{ClientConfig, DigitallySignedStruct, ServerConfig, SignatureScheme};

    /// Install the ring crypto provider (idempotent); call once at startup.
    pub fn install_provider() {
        let _ = rustls::crypto::ring::default_provider().install_default();
    }

    /// Self-signed server config for CN=`name`; returns the config plus the cert
    /// PEM to write where the sender's readiness gate looks.
    pub fn server_config(name: &str) -> (Arc<ServerConfig>, String) {
        let cert = rcgen::generate_simple_self_signed(vec![name.to_string()]).expect("cert");
        let pem = cert.cert.pem();
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der()));
        let config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert.cert.der().clone()], key)
            .expect("server config");
        (Arc::new(config), pem)
    }

    /// Client config that accepts any server certificate (self-signed eval certs).
    pub fn client_config() -> Arc<ClientConfig> {
        Arc::new(
            ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(SkipVerify::new()))
                .with_no_client_auth(),
        )
    }

    #[derive(Debug)]
    struct SkipVerify(Arc<rustls::crypto::CryptoProvider>);

    impl SkipVerify {
        fn new() -> Self {
            Self(Arc::new(rustls::crypto::ring::default_provider()))
        }
    }

    impl ServerCertVerifier for SkipVerify {
        fn verify_server_cert(
            &self,
            _e: &CertificateDer<'_>,
            _i: &[CertificateDer<'_>],
            _n: &ServerName<'_>,
            _o: &[u8],
            _t: UnixTime,
        ) -> Result<ServerCertVerified, rustls::Error> {
            Ok(ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            m: &[u8],
            c: &CertificateDer<'_>,
            d: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            rustls::crypto::verify_tls12_signature(
                m,
                c,
                d,
                &self.0.signature_verification_algorithms,
            )
        }

        fn verify_tls13_signature(
            &self,
            m: &[u8],
            c: &CertificateDer<'_>,
            d: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            rustls::crypto::verify_tls13_signature(
                m,
                c,
                d,
                &self.0.signature_verification_algorithms,
            )
        }

        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            self.0.signature_verification_algorithms.supported_schemes()
        }
    }
}
