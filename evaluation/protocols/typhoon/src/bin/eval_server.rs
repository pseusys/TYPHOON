//! TYPHOON evaluation server.
//!
//! Generates a `ServerKeyPair`, saves the `ClientCertificate` to
//! `/keys/typhoon.cert` (so the client container can load it from the
//! shared `eval_keys` volume), then accepts one connection and runs the
//! traffic profile selected by the `TRAFFIC_PROFILE` env variable.
//!
//! Profile parameters are read from the same `PROFILE_*` env vars that the
//! client receives, so both ends drive matching c2s/s2c loops without any
//! in-band negotiation.

use std::env::var;
use std::net::SocketAddr;
use std::process::Command;
use std::process::exit;
use std::sync::Arc;
use std::time::Instant;

use env_logger::{Builder, Env};
use log::info;
use rand::SeedableRng;
use rand::rngs::StdRng;
use tokio::time::{Duration, sleep, timeout};
use typhoon_eval::identity::{EvalServerConnectionHandler, ShortIdentity};
use typhoon_eval::profile::TrafficProfile;

use typhoon::certificate::ServerKeyPair;
use typhoon::defaults::DefaultExecutor;
use typhoon::flow::FlowConfig;
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
use typhoon::socket::{ClientHandle, ListenerBuilder, ServerFlowConfiguration};

/// Eval-side override mirroring the client; both sides apply identical settings.
const EVAL_FAKE_HEADER_PROBABILITY: f64 = 1.0;
/// Eval-side override mirroring the client — pin per-flow constant length to 1200.
const EVAL_FAKE_BODY_CONSTANT_LENGTH_MIN: u64 = 1200;
const EVAL_FAKE_BODY_CONSTANT_LENGTH_MAX: u64 = 1200;
/// Eval-side override mirroring the client.
const EVAL_FAKE_BODY_LENGTH_MAX: u64 = 1300;
/// Eval-side override mirroring the client — see eval_client.rs.
const EVAL_SEND_BYTES_JITTER: f64 = 0.30;
/// QUIC-only eval overrides — see eval_client.rs.
const EVAL_QUIC_MTU: usize = 1450;
const EVAL_QUIC_SEND_BYTES_JITTER: f64 = 0.10;
const EVAL_QUIC_DECOY_SPARSE_LENGTH_MIN: u64 = 64;
const EVAL_QUIC_DECOY_SPARSE_LENGTH_MAX: u64 = 120;
/// Eval-side override mirroring the client — see eval_client.rs.
const EVAL_HEALTH_CHECK_NEXT_IN_MIN: u64 = 300_000;
const EVAL_HEALTH_CHECK_NEXT_IN_MAX: u64 = 600_000;

/// Tuned-default overrides mirroring the client — see eval_client.rs.
const EVAL_TUNED_SEND_BYTES_JITTER: f64 = 0.8;
/// Tuned-default fragmentation target — mirrors eval_client.rs.
const EVAL_TUNED_SEND_BYTES_CHUNK: u64 = 512;
/// Tuned-default decoy-provider weights — mirrors eval_client.rs.
const EVAL_TUNED_DECOY_PROVIDER_WEIGHT_SIMPLE: u64 = 1;
const EVAL_TUNED_DECOY_PROVIDER_WEIGHT_SPARSE: u64 = 6;
const EVAL_TUNED_DECOY_PROVIDER_WEIGHT_NOISY: u64 = 1;
const EVAL_TUNED_DECOY_PROVIDER_WEIGHT_SMOOTH: u64 = 3;
const EVAL_TUNED_DECOY_PROVIDER_WEIGHT_HEAVY: u64 = 1;
/// Tuned-default decoy current-rate alpha — mirrors eval_client.rs.
const EVAL_TUNED_DECOY_CURRENT_ALPHA: f64 = 0.01;
const EVAL_TUNED_FALLTHROUGH_MIN: f64 = 0.0;
const EVAL_TUNED_FALLTHROUGH_MAX: f64 = 0.75;
const EVAL_TUNED_DECOY_HEAVY_BASE_RATE: f64 = 0.075;
const EVAL_TUNED_DECOY_NOISY_BASE_RATE: f64 = 4.5;
const EVAL_TUNED_DECOY_SPARSE_BASE_RATE: f64 = 30.0;
const EVAL_TUNED_DECOY_SMOOTH_BASE_RATE: f64 = 0.45;
/// Tuned-default fake-header probability — mirrors eval_client.rs.
const EVAL_TUNED_FAKE_HEADER_PROBABILITY: f64 = 0.70;
/// Tuned-default fake-header length cap — mirrors eval_client.rs.
const EVAL_TUNED_FAKE_HEADER_LENGTH_MAX: u64 = 48;
/// Tuned-default field-type weights — mirrors eval_client.rs.
const EVAL_TUNED_HDR_WEIGHT_RANDOM: u64 = 3;
const EVAL_TUNED_HDR_WEIGHT_CONSTANT: u64 = 4;
const EVAL_TUNED_HDR_WEIGHT_VOLATILE: u64 = 3;
const EVAL_TUNED_HDR_WEIGHT_SWITCHING: u64 = 3;
const EVAL_TUNED_HDR_WEIGHT_INCREMENTAL: u64 = 3;
/// Tuned-default Volatile / Switching widening — mirrors eval_client.rs.
const EVAL_TUNED_VOLATILE_CHANGE_PROB_MAX: f64 = 0.25;
const EVAL_TUNED_SWITCHING_TIMEOUT_MIN_MS: u64 = 1500;
/// Tuned-default Constant body length cap — mirrors eval_client.rs.
const EVAL_TUNED_FAKE_BODY_CONSTANT_LENGTH_MAX: u64 = 900;
/// Tuned-default decoy length cap — mirrors eval_client.rs.
const EVAL_TUNED_DECOY_LENGTH_MAX: u64 = 1100;

const CERT_PATH: &str = "/keys/typhoon.cert";
const PORTS: [u16; 3] = [19999, 19998, 19997];

#[tokio::main]
async fn main() {
    Builder::from_env(Env::default().default_filter_or("typhoon=debug")).init();

    if let Ok(gw) = var("OBSERVER_GW") {
        let _ = Command::new("ip")
            .args(["route", "add", "172.20.0.0/24", "via", &gw])
            .status();
    }

    let cert_host = var("CERT_HOST").unwrap_or_else(|_| "172.21.0.10".to_string());

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

    // Mirror the client's settings choice — see eval_client.rs for rationale.
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

    let cert_addrs: Vec<SocketAddr> = PORTS
        .iter()
        .map(|p| format!("{cert_host}:{p}").parse().unwrap())
        .collect();
    let bind_addrs: Vec<SocketAddr> = PORTS
        .iter()
        .map(|p| format!("0.0.0.0:{p}").parse().unwrap())
        .collect();

    let key_pair = ServerKeyPair::generate();
    let certificate = key_pair.to_client_certificate(cert_addrs);

    certificate
        .save(CERT_PATH)
        .expect("save cert to /keys/typhoon.cert");
    println!("Certificate saved to {CERT_PATH}");

    // Tuned profiles pin every server flow to the profile-derived FlowConfig so
    // the s2c side produces packets with the same shape as the c2s side.
    // raw_default skips pinning and uses FlowConfig::random per flow, matching
    // the client's behaviour.
    let flow_cfg: FlowConfig = if profile.is_unrestricted() {
        FlowConfig::random(&settings)
    } else {
        profile.flow_config()
    };
    let flows: Vec<ServerFlowConfiguration<ShortIdentity, DefaultExecutor>> = bind_addrs
        .into_iter()
        .map(|addr| ServerFlowConfiguration::with_address(flow_cfg.clone(), addr))
        .collect();

    // Tuned profiles pin every server flow to a concrete decoy provider so the
    // eval measures a known traffic shape: SimpleDecoyProvider (no decoys) for
    // most profiles, SparseDecoyProvider for QUIC profiles (supplies the ACK-
    // sized small-packet mode the chunk-driven data path can't reach).
    // raw_default skips pinning so the random per-flow draw runs as it would
    // in pure-protocol use.
    let listener_builder = ListenerBuilder::<
        ShortIdentity,
        DefaultExecutor,
        EvalServerConnectionHandler,
    >::new(key_pair, EvalServerConnectionHandler)
    .with_flows(flows)
    .with_settings(settings.clone());
    let listener_builder = if profile.is_unrestricted() {
        listener_builder
    } else if is_quic {
        listener_builder.with_decoy::<SparseDecoyProvider<ShortIdentity, DefaultExecutor>>()
    } else {
        listener_builder.with_decoy::<SimpleDecoyProvider>()
    };
    let listener: Arc<_> = Arc::new(listener_builder.build().await.expect("listener build"));
    listener.start().await;
    println!("TYPHOON eval server listening on ports {:?}", PORTS);

    let client = Arc::new(listener.accept().await.expect("accept"));
    println!("Client connected");

    let session_start = Instant::now();
    let deadline = session_start + profile.duration();

    // Concurrent c2s receive and s2c send loops bounded by deadline and byte budgets.
    let recv_handle = if profile.has_c2s_traffic() {
        Some(tokio::spawn(run_c2s_recv(
            client.clone(),
            profile.clone(),
            deadline,
        )))
    } else {
        None
    };
    let send_handle = if profile.has_s2c_traffic() {
        Some(tokio::spawn(run_s2c_send(
            client.clone(),
            profile.clone(),
            deadline,
        )))
    } else {
        None
    };

    let received = match recv_handle {
        Some(h) => h.await.expect("c2s join"),
        None => 0,
    };
    let sent = match send_handle {
        Some(h) => h.await.expect("s2c join"),
        None => 0,
    };

    let pct_c2s = if profile.bytes_c2s > 0 {
        received as f64 / profile.bytes_c2s as f64 * 100.0
    } else {
        100.0
    };
    println!(
        "Received {received}/{} bytes c2s ({pct_c2s:.1}%); sent {sent}/{} bytes s2c — done",
        profile.bytes_c2s, profile.bytes_s2c
    );
    println!("recv_time_s={:.3}", session_start.elapsed().as_secs_f64());
    exit(0);
}

/// Drive the c2s receive loop until the byte budget or deadline is met.
async fn run_c2s_recv(
    client: Arc<ClientHandle<ShortIdentity, DefaultExecutor>>,
    profile: TrafficProfile,
    deadline: Instant,
) -> usize {
    let mut received: usize = 0;
    let now = Instant::now();
    let mut remaining = if deadline > now {
        deadline - now
    } else {
        Duration::from_secs(0)
    };
    while received < profile.bytes_c2s && !remaining.is_zero() {
        match timeout(remaining, client.receive_bytes()).await {
            Ok(Ok(data)) => received += data.len(),
            _ => break,
        }
        let now = Instant::now();
        remaining = if deadline > now {
            deadline - now
        } else {
            Duration::from_secs(0)
        };
    }
    received
}

/// Drive the s2c send loop, respecting `bytes_s2c`, `chunk_s2c`, IAT, and bursty mode.
async fn run_s2c_send(
    client: Arc<ClientHandle<ShortIdentity, DefaultExecutor>>,
    profile: TrafficProfile,
    deadline: Instant,
) -> usize {
    let buf_size = profile.chunk_s2c.max(profile.chunk_s2c_max);
    let chunk = vec![0u8; buf_size];
    let mut sent: usize = 0;

    if profile.bursty && profile.burst_count > 1 {
        let bytes_per_burst = profile.bytes_s2c / profile.burst_count.max(1);
        for i in 0..profile.burst_count {
            sent += send_until_s(&client, &chunk, &profile, deadline, sent + bytes_per_burst).await;
            if sent >= profile.bytes_s2c || Instant::now() >= deadline {
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
        sent += send_until_s(&client, &chunk, &profile, deadline, profile.bytes_s2c).await;
    }
    sent
}

async fn send_until_s(
    client: &ClientHandle<ShortIdentity, DefaultExecutor>,
    chunk: &[u8],
    profile: &TrafficProfile,
    deadline: Instant,
    target: usize,
) -> usize {
    let mut sent = 0;
    let mut packets = 0;
    let fixed_delay = profile.s2c_delay();
    let randomise = profile.is_unrestricted();
    // `StdRng::from_entropy()` is `Send` — see eval_client.rs for rationale.
    let mut rng = StdRng::from_entropy();
    while sent < target && Instant::now() < deadline && packets < profile.max_packets() {
        let pkt_size = if randomise {
            profile.sample_chunk_s2c(&mut rng)
        } else {
            profile.chunk_s2c
        };
        let n = pkt_size.min(target - sent).min(chunk.len());
        if n == 0 {
            break;
        }
        if client.send_bytes(&chunk[..n]).await.is_err() {
            break;
        }
        sent += n;
        packets += 1;
        let delay = if randomise {
            profile.sample_s2c_delay(&mut rng)
        } else {
            fixed_delay
        };
        if !delay.is_zero() {
            sleep(delay).await;
        }
    }
    sent
}
