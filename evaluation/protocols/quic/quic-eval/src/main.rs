//! quic-eval — native Rust QUIC sender/receiver for the TYPHOON protocol
//! comparison, using `quinn` with its **BBR** congestion controller.
//!
//! History: the Python (aioquic) client stalled under chaos; the Go (quic-go)
//! rewrite completed but collapsed to ~300 s under 2% loss because quic-go has
//! no BBR — only NewReno. quinn ships a BBR controller, which is loss-tolerant,
//! so this build stays fast on lossy links.
//!
//! One binary, two roles selected by argv[1] (`client` | `server`). The
//! wire/console contract matches the previous implementations so the harness
//! needs no changes:
//!   - server writes a self-signed cert to /keys/quic_cert.pem (client readiness
//!     gate) and prints "received N/T bytes (P%)" for delivery parsing;
//!   - client prints "transfer_time_s=<f>" (wall time minus deliberate pacing).

mod profile;

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
use quinn::{ClientConfig, Endpoint, RecvStream, SendStream, ServerConfig, TransportConfig};
use rand::RngCore;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};

use profile::ProfileConfig;

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

fn env_u64(key: &str, default: u64) -> u64 {
    var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

// ── Server ───────────────────────────────────────────────────────────────────

async fn run_server() -> Result<(), BoxErr> {
    add_route("172.20.0.0/24");
    let transfer_bytes = env_u64("PROFILE_BYTES_C2S", 104_857_600) as usize;

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

    let mut recv = connection.accept_uni().await?;
    let received = drain_stream(&mut recv, transfer_bytes).await?;

    let pct = received as f64 / transfer_bytes as f64 * 100.0;
    println!("received {received}/{transfer_bytes} bytes ({pct:.1}%)");
    connection.close(0u32.into(), b"done");
    endpoint.wait_idle().await;
    Ok(())
}

/// Read the stream to its end (or until `limit` bytes), returning the byte count.
async fn drain_stream(recv: &mut RecvStream, limit: usize) -> Result<usize, BoxErr> {
    let mut received = 0usize;
    let mut buf = vec![0u8; 64 * 1024];
    while received < limit {
        match recv.read(&mut buf).await? {
            Some(n) => received += n,
            None => break, // peer finished the stream
        }
    }
    Ok(received)
}

// ── Client ───────────────────────────────────────────────────────────────────

async fn run_client() -> Result<(), BoxErr> {
    add_route("172.21.0.0/24");
    let server_host = var("SERVER_HOST").map_err(|_| "SERVER_HOST not set")?;
    let wait_timeout = Duration::from_secs(env_u64("QUIC_WAIT_TIMEOUT_S", 240));

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

    let mut stream = connection.open_uni().await?;
    let transfer_start = Instant::now();
    let (sent, total_sleep) = send_profile(&mut stream).await?;
    let transfer_time = (transfer_start.elapsed().as_secs_f64() - total_sleep).max(0.0);

    stream.finish()?; // FIN — signal end of stream to the server

    println!("All {sent} bytes enqueued, waiting for server close...");
    if tokio::time::timeout(wait_timeout, connection.closed())
        .await
        .is_err()
    {
        println!("wait_closed timed out after {wait_timeout:?}");
    }
    endpoint.wait_idle().await;

    println!("sent {sent} bytes via QUIC");
    println!("transfer_time_s={transfer_time:.3}");
    Ok(())
}

/// Drive the c2s send loop over `stream`, honouring per-packet IAT and the
/// every-N-packets batch delay; returns (bytes_sent, total_sleep_s).
async fn send_profile(stream: &mut SendStream) -> Result<(usize, f64), BoxErr> {
    let cfg = ProfileConfig::from_env();
    if cfg.bytes_c2s == 0 {
        return Ok((0, 0.0));
    }
    let mut chunk = vec![0u8; cfg.chunk_c2s];
    rand::thread_rng().fill_bytes(&mut chunk);

    let delay = Duration::from_secs_f64((cfg.iat_c2s_ms.max(0.0)) / 1000.0);
    let batch_delay = Duration::from_secs_f64((cfg.inter_batch_ms.max(0.0)) / 1000.0);
    let deadline = Instant::now() + Duration::from_secs_f64(cfg.duration_s.max(0.0));

    let mut sent = 0usize;
    let mut total_sleep = 0.0f64;

    if cfg.bursty && cfg.burst_count > 1 {
        let bytes_per_burst = cfg.bytes_c2s / cfg.burst_count;
        for i in 0..cfg.burst_count {
            let target = sent + bytes_per_burst;
            send_until(
                stream,
                &chunk,
                &mut sent,
                target,
                delay,
                batch_delay,
                cfg.batch_size,
                deadline,
                &mut total_sleep,
            )
            .await?;
            if sent >= cfg.bytes_c2s || Instant::now() >= deadline {
                break;
            }
            if i + 1 < cfg.burst_count && cfg.burst_idle_s > 0.0 {
                tokio::time::sleep(Duration::from_secs_f64(cfg.burst_idle_s)).await;
                total_sleep += cfg.burst_idle_s;
            }
        }
    } else {
        let target = cfg.bytes_c2s;
        send_until(
            stream,
            &chunk,
            &mut sent,
            target,
            delay,
            batch_delay,
            cfg.batch_size,
            deadline,
            &mut total_sleep,
        )
        .await?;
    }
    Ok((sent, total_sleep))
}

#[allow(clippy::too_many_arguments)]
async fn send_until(
    stream: &mut SendStream,
    chunk: &[u8],
    sent: &mut usize,
    target: usize,
    delay: Duration,
    batch_delay: Duration,
    batch_size: usize,
    deadline: Instant,
    total_sleep: &mut f64,
) -> Result<(), BoxErr> {
    let mut packets_in_batch = 0usize;
    while *sent < target && Instant::now() < deadline {
        let n = (target - *sent).min(chunk.len());
        stream.write_all(&chunk[..n]).await?;
        *sent += n;
        packets_in_batch += 1;
        if !delay.is_zero() {
            tokio::time::sleep(delay).await;
            *total_sleep += delay.as_secs_f64();
        }
        if !batch_delay.is_zero() && packets_in_batch >= batch_size {
            tokio::time::sleep(batch_delay).await;
            *total_sleep += batch_delay.as_secs_f64();
            packets_in_batch = 0;
        }
    }
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
