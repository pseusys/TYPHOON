//! TYPHOON evaluation client.
//!
//! Polls `/keys/typhoon.cert` until the server writes it, loads the certificate,
//! connects, and runs the per-packet latency ping (see `typhoon_eval::latency`).
//! `TRAFFIC_PROFILE` / `PROFILE_*` still select the TYPHOON flow settings (decoys,
//! fake headers, FlowConfig overrides) so the ping runs over a realistically
//! shaped flow; the profile's transfer fields (chunk/bytes/IAT) are unused here.

use std::env::var;
use std::path::Path;
use std::process::{Command, exit};
use std::sync::Arc;
use std::time::Instant;

use env_logger::{Builder, Env};
use log::info;
use rand::SeedableRng;
use rand::rngs::StdRng;
use rand::seq::SliceRandom;
use tokio::signal::unix::{SignalKind, signal};
use tokio::time::{Duration, sleep, timeout};
use typhoon::certificate::ClientCertificate;
use typhoon::defaults::{DefaultClientConnectionHandler, DefaultExecutor};
use typhoon::flow::decoy::{SimpleDecoyProvider, SparseDecoyProvider};
use typhoon::settings::SettingsBuilder;
use typhoon::settings::keys::{
    DECOY_CURRENT_ALPHA, DECOY_FALLTHROUGH_PACKETS_MAX, DECOY_FALLTHROUGH_PACKETS_MIN,
    DECOY_HEAVY_BASE_RATE, DECOY_LENGTH_MAX, DECOY_NOISY_BASE_RATE, DECOY_PROVIDER_WEIGHT_HEAVY,
    DECOY_PROVIDER_WEIGHT_NOISY, DECOY_PROVIDER_WEIGHT_SIMPLE, DECOY_PROVIDER_WEIGHT_SMOOTH,
    DECOY_PROVIDER_WEIGHT_SPARSE, DECOY_SMOOTH_BASE_RATE, DECOY_SPARSE_BASE_RATE,
    DECOY_SPARSE_LENGTH_MAX, DECOY_SPARSE_LENGTH_MIN, FAKE_BODY_CONSTANT_LENGTH_MAX,
    FAKE_BODY_CONSTANT_LENGTH_MIN, FAKE_BODY_LENGTH_MAX, FAKE_HEADER_FIELD_WEIGHT_CONSTANT,
    FAKE_HEADER_FIELD_WEIGHT_INCREMENTAL, FAKE_HEADER_FIELD_WEIGHT_RANDOM,
    FAKE_HEADER_FIELD_WEIGHT_SWITCHING, FAKE_HEADER_FIELD_WEIGHT_VOLATILE, FAKE_HEADER_LENGTH_MAX,
    FAKE_HEADER_PROBABILITY, FAKE_HEADER_SWITCHING_TIMEOUT_MIN_MS,
    FAKE_HEADER_VOLATILE_CHANGE_PROB_MAX, HEALTH_CHECK_NEXT_IN_MAX, HEALTH_CHECK_NEXT_IN_MIN,
    SEND_BYTES_CHUNK, SEND_BYTES_JITTER,
};
use typhoon::socket::ClientSocketBuilder;
use typhoon_eval::identity::ShortIdentity;
use typhoon_eval::latency;
use typhoon_eval::monotonic_ns;
use typhoon_eval::profile::TrafficProfile;

// ── Eval-side overrides (skipped for `raw_default`) ──────────────────────────

const EVAL_FAKE_HEADER_PROBABILITY: f64 = 1.0;
const EVAL_FAKE_BODY_CONSTANT_LENGTH_MIN: u64 = 1200;
const EVAL_FAKE_BODY_CONSTANT_LENGTH_MAX: u64 = 1200;
const EVAL_FAKE_BODY_LENGTH_MAX: u64 = 1300;
const EVAL_SEND_BYTES_JITTER: f64 = 0.30;

// QUIC-only: MTU 1450 leaves ack-frame headroom; sparse decoy length range
// supplies the bimodal small-packet mode real QUIC shows.
const EVAL_QUIC_MTU: usize = 1450;
const EVAL_QUIC_SEND_BYTES_JITTER: f64 = 0.10;
const EVAL_QUIC_DECOY_SPARSE_LENGTH_MIN: u64 = 64;
const EVAL_QUIC_DECOY_SPARSE_LENGTH_MAX: u64 = 120;

// Health-check interval pushed past flow duration so checks never fire
// mid-eval. Constraint: MIN > TIMEOUT_MAX (32 000), MIN < MAX.
const EVAL_HEALTH_CHECK_NEXT_IN_MIN: u64 = 300_000;
const EVAL_HEALTH_CHECK_NEXT_IN_MAX: u64 = 600_000;

// ── Tuned-default overrides (applied only when `is_tuned_default()`) ─────────

const EVAL_TUNED_SEND_BYTES_JITTER: f64 = 0.8;
const EVAL_TUNED_SEND_BYTES_CHUNK: u64 = 512;
const EVAL_TUNED_DECOY_PROVIDER_WEIGHT_SIMPLE: u64 = 1;
const EVAL_TUNED_DECOY_PROVIDER_WEIGHT_SPARSE: u64 = 6;
const EVAL_TUNED_DECOY_PROVIDER_WEIGHT_NOISY: u64 = 1;
const EVAL_TUNED_DECOY_PROVIDER_WEIGHT_SMOOTH: u64 = 3;
const EVAL_TUNED_DECOY_PROVIDER_WEIGHT_HEAVY: u64 = 1;
const EVAL_TUNED_DECOY_CURRENT_ALPHA: f64 = 0.01;
const EVAL_TUNED_FALLTHROUGH_MIN: f64 = 0.0;
const EVAL_TUNED_FALLTHROUGH_MAX: f64 = 0.75;
const EVAL_TUNED_DECOY_HEAVY_BASE_RATE: f64 = 0.075;
const EVAL_TUNED_DECOY_NOISY_BASE_RATE: f64 = 4.5;
const EVAL_TUNED_DECOY_SPARSE_BASE_RATE: f64 = 30.0;
const EVAL_TUNED_DECOY_SMOOTH_BASE_RATE: f64 = 0.45;
const EVAL_TUNED_FAKE_HEADER_PROBABILITY: f64 = 0.70;
const EVAL_TUNED_FAKE_HEADER_LENGTH_MAX: u64 = 48;
const EVAL_TUNED_HDR_WEIGHT_RANDOM: u64 = 3;
const EVAL_TUNED_HDR_WEIGHT_CONSTANT: u64 = 4;
const EVAL_TUNED_HDR_WEIGHT_VOLATILE: u64 = 3;
const EVAL_TUNED_HDR_WEIGHT_SWITCHING: u64 = 3;
const EVAL_TUNED_HDR_WEIGHT_INCREMENTAL: u64 = 3;
const EVAL_TUNED_VOLATILE_CHANGE_PROB_MAX: f64 = 0.25;
const EVAL_TUNED_SWITCHING_TIMEOUT_MIN_MS: u64 = 1500;
const EVAL_TUNED_FAKE_BODY_CONSTANT_LENGTH_MAX: u64 = 900;
const EVAL_TUNED_DECOY_LENGTH_MAX: u64 = 1100;

const CERT_PATH: &str = "/keys/typhoon.cert";
const CERT_POLL_ATTEMPTS: u32 = 60;
const CERT_POLL_INTERVAL: Duration = Duration::from_secs(1);

#[tokio::main]
async fn main() {
    Builder::from_env(Env::default().default_filter_or("typhoon=debug")).init();

    tokio::spawn(async move {
        let mut sigterm = signal(SignalKind::terminate()).expect("install SIGTERM handler");
        sigterm.recv().await;
        exit(0);
    });

    if let Ok(gw) = var("OBSERVER_GW") {
        let _ = Command::new("ip")
            .args(["route", "add", "172.21.0.0/24", "via", &gw])
            .status();
    }

    let profile = match TrafficProfile::from_env() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("profile error: {e}");
            exit(2);
        }
    };
    info!(
        "profile={} chunk_c2s={} chunk_s2c={} iat_c2s_ms={:.3} iat_s2c_ms={:.3} bytes_c2s={} bytes_s2c={} duration_s={:.3}",
        profile.name,
        profile.chunk_c2s,
        profile.chunk_s2c,
        profile.iat_c2s_ms,
        profile.iat_s2c_ms,
        profile.bytes_c2s,
        profile.bytes_s2c,
        profile.duration_s,
    );

    println!("Waiting for {CERT_PATH}...");
    for _ in 0..CERT_POLL_ATTEMPTS {
        if Path::new(CERT_PATH).exists() {
            break;
        }
        sleep(CERT_POLL_INTERVAL).await;
    }
    if !Path::new(CERT_PATH).exists() {
        eprintln!("Certificate never appeared at {CERT_PATH}");
        exit(1);
    }

    let certificate = ClientCertificate::load(CERT_PATH).expect("load cert");
    println!("Certificate loaded");

    let is_quic = matches!(profile.name.as_str(), "as_quic_d" | "as_quic_u");
    let settings_builder = SettingsBuilder::<DefaultExecutor>::new();
    let settings_builder = if is_quic {
        settings_builder.with_mtu(EVAL_QUIC_MTU)
    } else {
        settings_builder
    };
    let settings_builder = if profile.is_raw_default() {
        settings_builder
    } else if profile.is_tuned_default() {
        settings_builder
            .set(&FAKE_HEADER_PROBABILITY, EVAL_TUNED_FAKE_HEADER_PROBABILITY)
            .set(&FAKE_HEADER_LENGTH_MAX, EVAL_TUNED_FAKE_HEADER_LENGTH_MAX)
            .set(
                &FAKE_HEADER_FIELD_WEIGHT_RANDOM,
                EVAL_TUNED_HDR_WEIGHT_RANDOM,
            )
            .set(
                &FAKE_HEADER_FIELD_WEIGHT_CONSTANT,
                EVAL_TUNED_HDR_WEIGHT_CONSTANT,
            )
            .set(
                &FAKE_HEADER_FIELD_WEIGHT_VOLATILE,
                EVAL_TUNED_HDR_WEIGHT_VOLATILE,
            )
            .set(
                &FAKE_HEADER_FIELD_WEIGHT_SWITCHING,
                EVAL_TUNED_HDR_WEIGHT_SWITCHING,
            )
            .set(
                &FAKE_HEADER_FIELD_WEIGHT_INCREMENTAL,
                EVAL_TUNED_HDR_WEIGHT_INCREMENTAL,
            )
            .set(
                &FAKE_HEADER_VOLATILE_CHANGE_PROB_MAX,
                EVAL_TUNED_VOLATILE_CHANGE_PROB_MAX,
            )
            .set(
                &FAKE_HEADER_SWITCHING_TIMEOUT_MIN_MS,
                EVAL_TUNED_SWITCHING_TIMEOUT_MIN_MS,
            )
            .set(
                &FAKE_BODY_CONSTANT_LENGTH_MAX,
                EVAL_TUNED_FAKE_BODY_CONSTANT_LENGTH_MAX,
            )
            .set(&DECOY_LENGTH_MAX, EVAL_TUNED_DECOY_LENGTH_MAX)
            .set(&SEND_BYTES_JITTER, EVAL_TUNED_SEND_BYTES_JITTER)
            .set(&SEND_BYTES_CHUNK, EVAL_TUNED_SEND_BYTES_CHUNK)
            .set(
                &DECOY_PROVIDER_WEIGHT_SIMPLE,
                EVAL_TUNED_DECOY_PROVIDER_WEIGHT_SIMPLE,
            )
            .set(
                &DECOY_PROVIDER_WEIGHT_SPARSE,
                EVAL_TUNED_DECOY_PROVIDER_WEIGHT_SPARSE,
            )
            .set(
                &DECOY_PROVIDER_WEIGHT_NOISY,
                EVAL_TUNED_DECOY_PROVIDER_WEIGHT_NOISY,
            )
            .set(
                &DECOY_PROVIDER_WEIGHT_SMOOTH,
                EVAL_TUNED_DECOY_PROVIDER_WEIGHT_SMOOTH,
            )
            .set(
                &DECOY_PROVIDER_WEIGHT_HEAVY,
                EVAL_TUNED_DECOY_PROVIDER_WEIGHT_HEAVY,
            )
            .set(&DECOY_CURRENT_ALPHA, EVAL_TUNED_DECOY_CURRENT_ALPHA)
            .set(&DECOY_FALLTHROUGH_PACKETS_MIN, EVAL_TUNED_FALLTHROUGH_MIN)
            .set(&DECOY_FALLTHROUGH_PACKETS_MAX, EVAL_TUNED_FALLTHROUGH_MAX)
            .set(&DECOY_HEAVY_BASE_RATE, EVAL_TUNED_DECOY_HEAVY_BASE_RATE)
            .set(&DECOY_NOISY_BASE_RATE, EVAL_TUNED_DECOY_NOISY_BASE_RATE)
            .set(&DECOY_SPARSE_BASE_RATE, EVAL_TUNED_DECOY_SPARSE_BASE_RATE)
            .set(&DECOY_SMOOTH_BASE_RATE, EVAL_TUNED_DECOY_SMOOTH_BASE_RATE)
            .set(&HEALTH_CHECK_NEXT_IN_MIN, EVAL_HEALTH_CHECK_NEXT_IN_MIN)
            .set(&HEALTH_CHECK_NEXT_IN_MAX, EVAL_HEALTH_CHECK_NEXT_IN_MAX)
    } else {
        let jitter = if is_quic {
            EVAL_QUIC_SEND_BYTES_JITTER
        } else {
            EVAL_SEND_BYTES_JITTER
        };
        let mut b = settings_builder
            .set(&FAKE_HEADER_PROBABILITY, EVAL_FAKE_HEADER_PROBABILITY)
            .set(
                &FAKE_BODY_CONSTANT_LENGTH_MIN,
                EVAL_FAKE_BODY_CONSTANT_LENGTH_MIN,
            )
            .set(
                &FAKE_BODY_CONSTANT_LENGTH_MAX,
                EVAL_FAKE_BODY_CONSTANT_LENGTH_MAX,
            )
            .set(&FAKE_BODY_LENGTH_MAX, EVAL_FAKE_BODY_LENGTH_MAX)
            .set(&SEND_BYTES_JITTER, jitter)
            .set(&HEALTH_CHECK_NEXT_IN_MIN, EVAL_HEALTH_CHECK_NEXT_IN_MIN)
            .set(&HEALTH_CHECK_NEXT_IN_MAX, EVAL_HEALTH_CHECK_NEXT_IN_MAX);
        if is_quic {
            b = b
                .set(&DECOY_SPARSE_LENGTH_MIN, EVAL_QUIC_DECOY_SPARSE_LENGTH_MIN)
                .set(&DECOY_SPARSE_LENGTH_MAX, EVAL_QUIC_DECOY_SPARSE_LENGTH_MAX);
        }
        b
    };
    let settings = Arc::new(settings_builder.build().expect("eval settings"));

    let mut builder = ClientSocketBuilder::<
        ShortIdentity,
        DefaultExecutor,
        DefaultClientConnectionHandler,
    >::new(certificate.clone(), DefaultClientConnectionHandler)
    .with_settings(settings.clone());

    // `raw_default`/`tuned_default` (is_unrestricted()) must NOT pin a flow config here —
    // they exist to measure genuine protocol-default behaviour, which includes the builder's
    // auto-fill flow-count selection (1..=addresses().len(), each independently randomised).
    // Pinning a single address here (as the mimicry branch below does deliberately) would
    // silently narrow "default" to just the N=1 sub-case of that distribution.
    if !profile.is_unrestricted() {
        if is_quic {
            builder = builder.with_decoy::<SparseDecoyProvider<ShortIdentity, DefaultExecutor>>();
        } else if !profile.is_bulk_upload() {
            builder = builder.with_decoy::<SimpleDecoyProvider>();
        }
        // Mimicry profiles pin exactly one randomly-chosen address so a TYPHOON flow's
        // packet cadence matches a real single-flow target session (e.g. quic_download)
        // instead of being diluted across several concurrently-multiplexed flows.
        let flow_addr = *certificate
            .addresses()
            .choose(&mut StdRng::from_entropy())
            .expect("certificate must have at least one address");
        builder = builder.with_flow_config(flow_addr, profile.flow_config());
    }

    let socket = builder.build().await.expect("client socket build");
    println!("Connected to server");

    let socket = Arc::new(socket);
    run_latency(&socket).await;
}

/// Sequential ping — send a probe, await its echo, record RTT.
async fn run_latency(
    socket: &typhoon::socket::ClientSocket<
        ShortIdentity,
        DefaultExecutor,
        DefaultClientConnectionHandler,
    >,
) {
    let cfg = latency::Config::from_env();
    let mut rtts: Vec<f64> = Vec::with_capacity(cfg.count as usize);
    for seq in 0..cfg.count {
        let send_ns = monotonic_ns();
        let msg = latency::pack(seq, send_ns, cfg.size);
        let t0 = Instant::now();
        if socket.send_bytes(&msg).await.is_err() {
            break;
        }
        match timeout(cfg.recv_timeout, socket.receive_bytes()).await {
            Ok(Ok(echo)) if echo.len() >= latency::HEADER => {
                let rtt = (monotonic_ns().saturating_sub(latency::send_ns_of(&echo))) as f64 / 1e6;
                rtts.push(rtt);
            }
            _ => {} // lost echo — keep pinging
        }
        let elapsed = t0.elapsed();
        if elapsed < cfg.interval {
            sleep(cfg.interval - elapsed).await;
        }
    }
    latency::print_client_report(&mut rtts, cfg.count);
}
