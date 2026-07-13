//! TYPHOON evaluation server.
//!
//! Generates a `ServerKeyPair`, saves the `ClientCertificate` to
//! `/keys/typhoon.cert` (so the client container can load it from the shared
//! `eval_keys` volume), then accepts one connection and echoes the client's
//! latency-ping probes (see `typhoon_eval::latency`). `TRAFFIC_PROFILE` /
//! `PROFILE_*` select the TYPHOON flow settings, matching the client's, so the
//! ping runs over a realistically shaped flow.

use std::env::var;
use std::net::SocketAddr;
use std::process::Command;
use std::process::exit;
use std::sync::Arc;

use env_logger::{Builder, Env};
use log::{info, trace};
use tokio::time::{Duration, timeout};

use typhoon_eval::identity::{EvalServerConnectionHandler, ShortIdentity};
use typhoon_eval::profile::TrafficProfile;
use typhoon_eval::{is_load_mode, latency, load};

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
use typhoon::socket::{ClientHandle, ServerBuilder, ServerFlowConfiguration};

// Mirrors of eval_client.rs constants. Both sides must apply identical
// settings; consult eval_client.rs for the override rationale.

const EVAL_FAKE_HEADER_PROBABILITY: f64 = 1.0;
const EVAL_FAKE_BODY_CONSTANT_LENGTH_MIN: u64 = 1200;
const EVAL_FAKE_BODY_CONSTANT_LENGTH_MAX: u64 = 1200;
const EVAL_FAKE_BODY_LENGTH_MAX: u64 = 1300;
const EVAL_SEND_BYTES_JITTER: f64 = 0.30;
const EVAL_QUIC_MTU: usize = 1450;
const EVAL_QUIC_SEND_BYTES_JITTER: f64 = 0.10;
const EVAL_QUIC_DECOY_SPARSE_LENGTH_MIN: u64 = 64;
const EVAL_QUIC_DECOY_SPARSE_LENGTH_MAX: u64 = 120;
const EVAL_HEALTH_CHECK_NEXT_IN_MIN: u64 = 300_000;
const EVAL_HEALTH_CHECK_NEXT_IN_MAX: u64 = 600_000;
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

    // Load mode binds LOAD_FLOWS ports (descending from the primary) each with LOAD_READERS
    // SO_REUSEPORT reader sockets; latency mode keeps the fixed 3-port array with a single reader.
    let load_cfg = load::Config::from_env();
    let ports: Vec<u16> = if is_load_mode() {
        (0..load_cfg.flows).map(|i| PORTS[0] - i as u16).collect()
    } else {
        PORTS.to_vec()
    };
    let readers = if is_load_mode() { load_cfg.readers } else { 1 };

    let cert_addrs: Vec<SocketAddr> = ports
        .iter()
        .map(|p| format!("{cert_host}:{p}").parse().unwrap())
        .collect();
    let bind_addrs: Vec<SocketAddr> = ports
        .iter()
        .map(|p| format!("0.0.0.0:{p}").parse().unwrap())
        .collect();

    let key_pair = ServerKeyPair::generate();
    let certificate = key_pair.to_client_certificate(cert_addrs);

    certificate
        .save(CERT_PATH)
        .expect("save cert to /keys/typhoon.cert");
    println!("Certificate saved to {CERT_PATH}");

    let flow_cfg: FlowConfig = if profile.is_unrestricted() {
        FlowConfig::random(&settings)
    } else {
        profile.flow_config()
    };
    let flows: Vec<ServerFlowConfiguration<ShortIdentity, DefaultExecutor>> = bind_addrs
        .into_iter()
        .map(|addr| {
            ServerFlowConfiguration::with_address(flow_cfg.clone(), addr).with_reader_count(readers)
        })
        .collect();

    let listener_builder = ServerBuilder::<
        ShortIdentity,
        DefaultExecutor,
        EvalServerConnectionHandler,
    >::new(key_pair, EvalServerConnectionHandler)
    .with_flows(flows)
    .with_settings(settings.clone());
    let listener_builder = if profile.is_unrestricted() || profile.is_bulk_upload() {
        listener_builder
    } else if is_quic {
        listener_builder.with_decoy::<SparseDecoyProvider<ShortIdentity, DefaultExecutor>>()
    } else {
        listener_builder.with_decoy::<SimpleDecoyProvider>()
    };
    let listener: Arc<_> = Arc::new(
        listener_builder
            .build_listener()
            .await
            .expect("listener build"),
    );
    listener.start().await;
    println!("TYPHOON eval server listening on ports {ports:?} (readers={readers})");

    let client = Arc::new(listener.accept().await.expect("accept"));
    println!("Client connected");

    if is_load_mode() {
        run_load_drain(&client).await;
    } else {
        run_latency_echo(&client).await;
    }
    exit(0);
}

/// Load mode: drain the client's one-way flood, counting packets and deriving loss from sequence
/// gaps. Emits a `LoadStats` record plus the core `drain_drops`/`recv_errors` counters (via
/// `typhoon::record_loss`) on the `typhoon::capture` target for the harness to parse.
async fn run_load_drain(client: &ClientHandle<ShortIdentity, DefaultExecutor>) {
    let idle = Duration::from_secs(
        var("IDLE_TIMEOUT_S")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(30),
    );
    let mut received = 0usize;
    let mut bytes = 0usize;
    let mut max_seq = 0u64;
    loop {
        match timeout(idle, client.receive_bytes()).await {
            Ok(Ok(data)) => {
                received += 1;
                bytes += data.len();
                max_seq = max_seq.max(load::seq_of(&data));
            }
            _ => break, // idle / error ends the run
        }
    }
    let sent_estimate = if received == 0 { 0 } else { max_seq + 1 };
    let seq_gaps = sent_estimate.saturating_sub(received as u64);
    trace!(target: "typhoon::capture", "{{\"kind\":\"LoadStats\",\"bytes\":{bytes},\"packets\":{received},\"max_seq\":{max_seq},\"seq_gaps\":{seq_gaps}}}");
    typhoon::record_loss();
    println!("LOAD_SERVER_DONE packets={received} bytes={bytes} seq_gaps={seq_gaps}");
}

/// Echo each probe back to the client until `count` seen or idle.
async fn run_latency_echo(client: &ClientHandle<ShortIdentity, DefaultExecutor>) {
    let cfg = latency::Config::from_env();
    let idle = Duration::from_secs(
        var("IDLE_TIMEOUT_S")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(30),
    );
    let mut received = 0u32;
    while received < cfg.count {
        match timeout(idle, client.receive_bytes()).await {
            Ok(Ok(data)) => {
                if client.send_bytes(&data).await.is_err() {
                    break;
                }
                received += 1;
            }
            _ => break, // idle / error ends the run
        }
    }
    let delivery = received as f64 / cfg.count.max(1) as f64 * 100.0;
    println!("received {received}/{} packets ({delivery:.1}%)", cfg.count);
}
