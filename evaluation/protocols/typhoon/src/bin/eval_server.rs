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
use tokio::time::{Duration, sleep, timeout};
use typhoon_eval::profile::TrafficProfile;

use typhoon::bytes::StaticByteBuffer;
use typhoon::certificate::ServerKeyPair;
use typhoon::defaults::{DefaultExecutor, DefaultServerConnectionHandler};
use typhoon::flow::FlowConfig;
use typhoon::settings::SettingsBuilder;
use typhoon::flow::decoy::SimpleDecoyProvider;
use typhoon::settings::keys::{
    FAKE_BODY_CONSTANT_LENGTH, FAKE_BODY_LENGTH_MAX, FAKE_HEADER_PROBABILITY,
    HEALTH_CHECK_NEXT_IN_MAX, HEALTH_CHECK_NEXT_IN_MIN, SEND_BYTES_JITTER,
};
use typhoon::socket::{ClientHandle, ListenerBuilder, ServerFlowConfiguration};

/// Eval-side override mirroring the client; both sides apply identical settings.
const EVAL_FAKE_HEADER_PROBABILITY: f64 = 1.0;
/// Eval-side override mirroring the client.
const EVAL_FAKE_BODY_CONSTANT_LENGTH: u64 = 1200;
/// Eval-side override mirroring the client.
const EVAL_FAKE_BODY_LENGTH_MAX: u64 = 1300;
/// Eval-side override mirroring the client — see eval_client.rs.
const EVAL_SEND_BYTES_JITTER: f64 = 0.30;
/// Eval-side override mirroring the client — see eval_client.rs.
const EVAL_HEALTH_CHECK_NEXT_IN_MIN: u64 = 300_000;
const EVAL_HEALTH_CHECK_NEXT_IN_MAX: u64 = 600_000;

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
    // Decoy suppression is wired via the listener builder below, not via settings
    // weights (`DECOY_PROVIDER_WEIGHT_*` must all be > 0 per the settings asserts).
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
    let flow_cfg: FlowConfig = if profile.is_raw_default() {
        FlowConfig::random(&settings)
    } else {
        profile.flow_config()
    };
    let flows: Vec<ServerFlowConfiguration<StaticByteBuffer, DefaultExecutor>> = bind_addrs
        .into_iter()
        .map(|addr| ServerFlowConfiguration::with_address(flow_cfg.clone(), addr))
        .collect();

    // Tuned profiles pin every server flow to `SimpleDecoyProvider` (no-op
    // pass-through) so the eval measures the data-flow shape without decoy
    // interference; raw_default uses the default random per-flow draw.
    let listener_builder = ListenerBuilder::<StaticByteBuffer, DefaultExecutor, DefaultServerConnectionHandler>::new(
        key_pair,
        DefaultServerConnectionHandler,
    )
    .with_flows(flows)
    .with_settings(settings.clone());
    let listener_builder = if profile.is_raw_default() {
        listener_builder
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
        Some(tokio::spawn(run_c2s_recv(client.clone(), profile.clone(), deadline)))
    } else {
        None
    };
    let send_handle = if profile.has_s2c_traffic() {
        Some(tokio::spawn(run_s2c_send(client.clone(), profile.clone(), deadline)))
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
    client: Arc<ClientHandle<StaticByteBuffer, DefaultExecutor>>,
    profile: TrafficProfile,
    deadline: Instant,
) -> usize {
    let mut received: usize = 0;
    let now = Instant::now();
    let mut remaining = if deadline > now { deadline - now } else { Duration::from_secs(0) };
    while received < profile.bytes_c2s && !remaining.is_zero() {
        match timeout(remaining, client.receive_bytes()).await {
            Ok(Ok(data)) => received += data.len(),
            _ => break,
        }
        let now = Instant::now();
        remaining = if deadline > now { deadline - now } else { Duration::from_secs(0) };
    }
    received
}

/// Drive the s2c send loop, respecting `bytes_s2c`, `chunk_s2c`, IAT, and bursty mode.
async fn run_s2c_send(
    client: Arc<ClientHandle<StaticByteBuffer, DefaultExecutor>>,
    profile: TrafficProfile,
    deadline: Instant,
) -> usize {
    let chunk = vec![0u8; profile.chunk_s2c];
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
    client: &ClientHandle<StaticByteBuffer, DefaultExecutor>,
    chunk: &[u8],
    profile: &TrafficProfile,
    deadline: Instant,
    target: usize,
) -> usize {
    let mut sent = 0;
    let mut packets = 0;
    let delay = profile.s2c_delay();
    while sent < target && Instant::now() < deadline && packets < profile.max_packets() {
        let n = chunk.len().min(target - sent);
        if client.send_bytes(&chunk[..n]).await.is_err() {
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
