//! quic-eval — native Rust QUIC sender/receiver for the TYPHOON protocol
//! comparison, using `quinn` with its **BBR** congestion controller.
//!
//! History: the Python (aioquic) client stalled under chaos; the Go (quic-go)
//! rewrite completed but collapsed to ~300 s under 2% loss because quic-go has
//! no BBR — only NewReno. quinn ships a BBR controller, which is loss-tolerant,
//! so this build stays fast on lossy links.
//!
//! One binary, two roles selected by argv[1] (`client` | `server`). The server
//! writes a self-signed cert to /keys/quic_cert.pem (client readiness gate) and
//! echoes each probe on the client-opened bidi stream; the client pings probes
//! and prints the `rtt_*` / delivery contract the harness parses (see `lat`).

use std::env::var;
use std::error::Error;
use std::fs::write;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::Path;
use std::process::exit;
use std::sync::Arc;
use std::time::{Duration, Instant};

use quinn::congestion::BbrConfig;
use quinn::crypto::rustls::QuicClientConfig;
use quinn::{ClientConfig, Endpoint, ServerConfig, TransportConfig};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};

const PORT: u16 = 9000;
const CERT_PATH: &str = "/keys/quic_cert.pem";

type BoxErr = Box<dyn Error + Send + Sync>;

#[tokio::main]
async fn main() {
    // rustls 0.23 requires a process-wide crypto provider before any config build.
    let _ = rustls::crypto::ring::default_provider().install_default();

    let role = std::env::args().nth(1).unwrap_or_default();
    let result = match role.as_str() {
        "server" => run_server().await,
        "client" => run_client().await,
        other => {
            eprintln!("usage: quic-eval <client|server> (got {other:?})");
            exit(2);
        }
    };
    if let Err(e) = result {
        eprintln!("{e}");
        exit(1);
    }
}

/// Host-wide monotonic clock in nanoseconds. Docker containers share the kernel
/// clock (no time namespace by default), so client `send_start/end` and server
/// `recv_first/last` are directly comparable — the cross-endpoint transfer base.
fn monotonic_ns() -> u128 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    unsafe {
        libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts);
    }
    (ts.tv_sec as u128) * 1_000_000_000 + (ts.tv_nsec as u128)
}

/// Best-effort forward route to the opposite /24 via the observer tap.
fn add_route(subnet: &str) {
    if let Ok(gw) = var("OBSERVER_GW") {
        if !gw.is_empty() {
            let _ = std::process::Command::new("ip")
                .args(["route", "add", subnet, "via", &gw])
                .status();
        }
    }
}

/// Shared transport config: BBR congestion control + generous windows/idle so a
/// single bulk stream is bounded by the link, not by flow control.
fn transport() -> Arc<TransportConfig> {
    let mut t = TransportConfig::default();
    t.congestion_controller_factory(Arc::new(BbrConfig::default()));
    t.max_idle_timeout(Some(Duration::from_secs(300).try_into().unwrap()));
    t.stream_receive_window((128u32 << 20).into());
    t.receive_window((256u32 << 20).into());
    Arc::new(t)
}

// ── Latency mode: per-packet round-trip ping over a bidi stream ──────────────
// A duplicate of the shared `eval-transport::latency` contract (the eval crates
// don't share a dependency). QUIC is reliable, so echoes always return and RTT
// grows under loss (like TCP) rather than dropping.
mod lat {
    use std::env::var;
    use std::time::Duration;

    pub const HEADER: usize = 20; // seq(4) + send_ns(16)

    pub fn count() -> u32 {
        envu("LAT_COUNT", 500)
    }
    pub fn interval() -> Duration {
        Duration::from_secs_f64(envf("LAT_INTERVAL_MS", 20.0) / 1000.0)
    }
    pub fn size() -> usize {
        (envu("LAT_SIZE", 256) as usize).max(HEADER)
    }
    pub fn recv_timeout() -> Duration {
        Duration::from_secs_f64(envf("LAT_RECV_TIMEOUT_MS", 5000.0) / 1000.0)
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
    pub fn report(rtts: &mut [f64], count: u32) {
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
    fn envu(k: &str, d: u32) -> u32 {
        var(k).ok().and_then(|v| v.parse().ok()).unwrap_or(d)
    }
    fn envf(k: &str, d: f64) -> f64 {
        var(k).ok().and_then(|v| v.parse().ok()).unwrap_or(d)
    }
}

// ── Server ───────────────────────────────────────────────────────────────────

async fn run_server() -> Result<(), BoxErr> {
    add_route("172.20.0.0/24");

    // Self-signed cert; write the PEM last so its presence gates the client.
    let cert = rcgen::generate_simple_self_signed(vec!["quic-eval".to_string()])?;
    let cert_der = cert.cert.der().clone();
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der()));
    write(CERT_PATH, cert.cert.pem())?;

    let mut server_config = ServerConfig::with_single_cert(vec![cert_der], key_der)?;
    server_config.transport_config(transport());

    let addr = SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), PORT);
    let endpoint = Endpoint::server(server_config, addr)?;
    println!("QUIC sink ready on :{PORT}");

    let connecting = endpoint
        .accept()
        .await
        .ok_or("endpoint closed before a connection arrived")?;
    let connection = connecting.await?;
    println!("connection accepted");

    // Echo each probe back on the client-opened bidi stream (see `lat`).
    let (mut send, mut recv) = connection.accept_bi().await?;
    let cnt = lat::count();
    let mut buf = vec![0u8; lat::size()];
    let mut received = 0u32;
    while received < cnt {
        match recv.read_exact(&mut buf).await {
            Ok(()) => {
                send.write_all(&buf).await?;
                received += 1;
            }
            Err(_) => break,
        }
    }
    let pct = received as f64 / cnt.max(1) as f64 * 100.0;
    println!("received {received}/{cnt} packets ({pct:.1}%)");
    connection.close(0u32.into(), b"done");
    endpoint.wait_idle().await;
    Ok(())
}

// ── Client ───────────────────────────────────────────────────────────────────

async fn run_client() -> Result<(), BoxErr> {
    add_route("172.21.0.0/24");
    let server_host = var("SERVER_HOST").map_err(|_| "SERVER_HOST not set")?;

    // Gate on the server's cert file, mirroring the prior implementations.
    let mut ready = false;
    for _ in 0..30 {
        if Path::new(CERT_PATH).exists() {
            ready = true;
            break;
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    if !ready {
        return Err(format!("{CERT_PATH} never appeared").into());
    }

    let crypto = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(SkipServerVerification::new()))
        .with_no_client_auth();
    let mut client_config = ClientConfig::new(Arc::new(QuicClientConfig::try_from(crypto)?));
    client_config.transport_config(transport());

    let mut endpoint = Endpoint::client(SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 0))?;
    endpoint.set_default_client_config(client_config);

    let server_addr = SocketAddr::new(server_host.parse()?, PORT);
    println!("Connecting...");
    let connection = endpoint.connect(server_addr, "quic-eval")?.await?;
    println!("Connected, sending data...");

    // Ping probes over a bidi stream, timing round-trips (see `lat`).
    let (mut send, mut recv) = connection.open_bi().await?;
    let cnt = lat::count();
    let interval = lat::interval();
    let rto = lat::recv_timeout();
    let mut rbuf = vec![0u8; lat::size()];
    let mut rtts: Vec<f64> = Vec::with_capacity(cnt as usize);
    for seq in 0..cnt {
        let send_ns = monotonic_ns();
        let msg = lat::pack(seq, send_ns, lat::size());
        let t0 = Instant::now();
        send.write_all(&msg).await?;
        match tokio::time::timeout(rto, recv.read_exact(&mut rbuf)).await {
            Ok(Ok(())) => {
                let rtt = (monotonic_ns().saturating_sub(lat::send_ns_of(&rbuf))) as f64 / 1e6;
                rtts.push(rtt);
            }
            _ => break, // reliable stream: timeout/err means the peer is gone
        }
        let el = t0.elapsed();
        if el < interval {
            tokio::time::sleep(interval - el).await;
        }
    }
    lat::report(&mut rtts, cnt);
    connection.close(0u32.into(), b"done");
    endpoint.wait_idle().await;
    Ok(())
}
// ── TLS: accept the eval's self-signed cert (verification is out of scope) ─────

#[derive(Debug)]
struct SkipServerVerification(Arc<rustls::crypto::CryptoProvider>);

impl SkipServerVerification {
    fn new() -> Self {
        Self(Arc::new(rustls::crypto::ring::default_provider()))
    }
}

impl rustls::client::danger::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}
