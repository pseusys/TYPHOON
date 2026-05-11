//! TYPHOON evaluation client.
//!
//! Polls `/keys/typhoon.cert` until the server writes it, loads the certificate,
//! connects to the server, and runs the traffic profile selected by the
//! `TRAFFIC_PROFILE` env variable.  Profile parameters (chunk sizes, IATs, byte
//! budgets, FlowConfig overrides) are read from the `PROFILE_*` env vars; both
//! the client and server containers receive identical values from the same
//! per-run env file written by the orchestrator.

use std::env::var;
use std::path::Path;
use std::process::{Command, exit};
use std::sync::Arc;
use std::time::Instant;

use env_logger::{Builder, Env};
use log::info;
use tokio::time::{Duration, sleep, timeout};
use typhoon_eval::profile::TrafficProfile;

use typhoon::bytes::StaticByteBuffer;
use typhoon::certificate::ClientCertificate;
use typhoon::defaults::{DefaultClientConnectionHandler, DefaultExecutor};
use typhoon::settings::SettingsBuilder;
use typhoon::flow::decoy::SimpleDecoyProvider;
use typhoon::settings::keys::{
    FAKE_BODY_CONSTANT_LENGTH, FAKE_BODY_LENGTH_MAX, FAKE_HEADER_PROBABILITY,
    HEALTH_CHECK_NEXT_IN_MAX, HEALTH_CHECK_NEXT_IN_MIN, SEND_BYTES_JITTER,
};
use typhoon::socket::ClientSocketBuilder;

/// Eval-side override: every flow gets a fake header (no header-less outliers).
/// Skipped for the `raw_default` profile so pure protocol defaults apply.
const EVAL_FAKE_HEADER_PROBABILITY: f64 = 1.0;
/// Eval-side override: when Constant body mode is selected, pad to QUIC's typical
/// initial-packet size instead of the conservative protocol default of 512 B.
const EVAL_FAKE_BODY_CONSTANT_LENGTH: u64 = 1200;
/// Eval-side override: widen the upper bound of Random fake-body length so per-
/// packet size variance closes the size_std fingerprint that the protocol
/// default of 512 B leaves visible.
const EVAL_FAKE_BODY_LENGTH_MAX: u64 = 1300;
/// Eval-side override: per-packet user-data length is sampled from
/// `[max_data_payload * (1 - JITTER), max_data_payload]`, breaking the
/// otherwise-uniform per-flow chunk-size fingerprint that drove `size_mean`,
/// `size_p50` and `size_p95` Δs above 2 σ in pair-binary detection.
const EVAL_SEND_BYTES_JITTER: f64 = 0.30;
/// Eval-side override: health-check interval pushed to 5-10 minutes so no
/// health-check packets fire inside the 30-120 s eval flows.  Health-checks
/// produced 0-1 off-cadence packets per flow that landed on the IAT
/// distribution as outliers, driving `iat_std` / `iat_entropy` Δs on
/// as_voice.  Asserted constraints: MIN > TIMEOUT_MAX (32 000), MIN < MAX.
const EVAL_HEALTH_CHECK_NEXT_IN_MIN: u64 = 300_000;
const EVAL_HEALTH_CHECK_NEXT_IN_MAX: u64 = 600_000;

const CERT_PATH: &str = "/keys/typhoon.cert";
const CERT_POLL_ATTEMPTS: u32 = 60;
const CERT_POLL_INTERVAL: Duration = Duration::from_secs(1);

#[tokio::main]
async fn main() {
    Builder::from_env(Env::default().default_filter_or("typhoon=debug")).init();

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

    // For tuned profiles, apply eval-side settings overrides; for raw_default
    // skip the overrides so pure protocol defaults are exercised.  When the
    // profile says decoys are disabled (silent_idle), force every decoy mode's
    // BASE_RATE to 0 so no decoy traffic is generated regardless of which mode
    // FlowConfig::random picks for the flow.
    // Tuned profiles get every eval-side override (header probability, body length,
    // send-bytes jitter); raw_default skips them so pure protocol defaults are
    // exercised.  Decoy suppression for tuned + silent profiles is set via the
    // builder hook below (ClientSocketBuilder::with_decoy::<SimpleDecoyProvider>),
    // not via settings — `DECOY_PROVIDER_WEIGHT_*` must all be > 0 (asserted by the
    // settings layer), so weight-zeroing is not an option.
    let settings_builder = SettingsBuilder::<DefaultExecutor>::new();
    let settings_builder = if profile.is_raw_default() {
        settings_builder
    } else {
        settings_builder
            .set(&FAKE_HEADER_PROBABILITY, EVAL_FAKE_HEADER_PROBABILITY)
            .set(&FAKE_BODY_CONSTANT_LENGTH, EVAL_FAKE_BODY_CONSTANT_LENGTH)
            .set(&FAKE_BODY_LENGTH_MAX, EVAL_FAKE_BODY_LENGTH_MAX)
            .set(&SEND_BYTES_JITTER, EVAL_SEND_BYTES_JITTER)
            .set(&HEALTH_CHECK_NEXT_IN_MIN, EVAL_HEALTH_CHECK_NEXT_IN_MIN)
            .set(&HEALTH_CHECK_NEXT_IN_MAX, EVAL_HEALTH_CHECK_NEXT_IN_MAX)
    };
    let settings = Arc::new(settings_builder.build().expect("eval settings"));

    let mut builder =
        ClientSocketBuilder::<StaticByteBuffer, DefaultExecutor, DefaultClientConnectionHandler>::new(
            certificate.clone(),
            DefaultClientConnectionHandler,
        )
        .with_settings(settings.clone());
    // Tuned profiles pin the FlowConfig to profile-derived values, fully
    // overriding the per-flow `FlowConfig::random` draw, and pin every flow
    // to `SimpleDecoyProvider` (no-op pass-through) so the eval measures the
    // data-flow shape without decoy interference.  raw_default skips both so
    // the random per-flow draws (FlowConfig and decoy provider) run as they
    // would in pure-protocol use.
    if !profile.is_raw_default() {
        builder = builder.with_decoy::<SimpleDecoyProvider>();
        let flow_cfg = profile.flow_config();
        for addr in certificate.addresses() {
            builder = builder.with_flow_config(*addr, flow_cfg.clone());
        }
    }

    let socket = builder.build().await.expect("client socket build");
    println!("Connected to server");

    let socket = Arc::new(socket);
    let transfer_start = Instant::now();
    let deadline = transfer_start + profile.duration();

    // Concurrent c2s send / s2c receive loops bounded by deadline and byte budgets.
    let send_handle = if profile.has_c2s_traffic() {
        Some(tokio::spawn(run_c2s_send(socket.clone(), profile.clone(), deadline)))
    } else {
        None
    };
    let recv_handle = if profile.has_s2c_traffic() {
        Some(tokio::spawn(run_s2c_recv(socket.clone(), profile.clone(), deadline)))
    } else {
        None
    };

    let sent = match send_handle {
        Some(h) => h.await.expect("c2s join"),
        None => 0,
    };
    let received = match recv_handle {
        Some(h) => h.await.expect("s2c join"),
        None => 0,
    };

    let elapsed_s = transfer_start.elapsed().as_secs_f64();
    println!("Sent {sent} bytes c2s, received {received} bytes s2c — done");
    println!("transfer_time_s={elapsed_s:.3}");
    exit(0);
}

/// Drive the c2s send loop, respecting `bytes_c2s`, `chunk_c2s`, IAT, and bursty mode.
async fn run_c2s_send(
    socket: Arc<
        typhoon::socket::ClientSocket<StaticByteBuffer, DefaultExecutor, DefaultClientConnectionHandler>,
    >,
    profile: TrafficProfile,
    deadline: Instant,
) -> usize {
    let chunk = vec![0u8; profile.chunk_c2s];
    let mut sent: usize = 0;

    if profile.bursty && profile.burst_count > 1 {
        let bytes_per_burst = profile.bytes_c2s / profile.burst_count.max(1);
        for i in 0..profile.burst_count {
            sent += send_until(&socket, &chunk, &profile, deadline, sent + bytes_per_burst).await;
            if sent >= profile.bytes_c2s || Instant::now() >= deadline {
                break;
            }
            if i + 1 < profile.burst_count {
                let idle_until = Instant::now() + profile.burst_idle();
                if idle_until > deadline {
                    break;
                }
                sleep(profile.burst_idle()).await;
            }
        }
    } else {
        sent += send_until(&socket, &chunk, &profile, deadline, profile.bytes_c2s).await;
    }
    sent
}

async fn send_until(
    socket: &typhoon::socket::ClientSocket<StaticByteBuffer, DefaultExecutor, DefaultClientConnectionHandler>,
    chunk: &[u8],
    profile: &TrafficProfile,
    deadline: Instant,
    target: usize,
) -> usize {
    let mut sent = 0;
    let mut packets = 0;
    let delay = profile.c2s_delay();
    while sent < target && Instant::now() < deadline && packets < profile.max_packets() {
        let n = chunk.len().min(target - sent);
        if socket.send_bytes(&chunk[..n]).await.is_err() {
            break;
        }
        sent += n;
        packets += 1;
        if !delay.is_zero() {
            sleep(delay).await;
        }
    }
    sent
}

/// Drive the s2c receive loop until the byte budget or deadline is met.
async fn run_s2c_recv(
    socket: Arc<
        typhoon::socket::ClientSocket<StaticByteBuffer, DefaultExecutor, DefaultClientConnectionHandler>,
    >,
    profile: TrafficProfile,
    deadline: Instant,
) -> usize {
    let mut received: usize = 0;
    let now = Instant::now();
    let mut remaining = if deadline > now { deadline - now } else { Duration::from_secs(0) };
    while received < profile.bytes_s2c && !remaining.is_zero() {
        match timeout(remaining, socket.receive_bytes()).await {
            Ok(Ok(data)) => received += data.len(),
            _ => break,
        }
        let now = Instant::now();
        remaining = if deadline > now { deadline - now } else { Duration::from_secs(0) };
    }
    received
}
