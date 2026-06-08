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
use rand::SeedableRng;
use rand::rngs::StdRng;
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
use typhoon_eval::profile::TrafficProfile;

/// Eval-side override: every flow gets a fake header (no header-less outliers).
/// Skipped for the `raw_default` profile so pure protocol defaults apply.
const EVAL_FAKE_HEADER_PROBABILITY: f64 = 1.0;
/// Eval-side override: when Constant body mode is selected, pin the per-flow
/// constant length to QUIC's typical initial-packet size (~1200 B) by giving
/// the protocol's [MIN, MAX] sampler a degenerate range.  Tuned profiles want
/// a stable wire shape, so MIN==MAX is correct here.
const EVAL_FAKE_BODY_CONSTANT_LENGTH_MIN: u64 = 1200;
const EVAL_FAKE_BODY_CONSTANT_LENGTH_MAX: u64 = 1200;
/// Eval-side override: widen the upper bound of Random fake-body length so per-
/// packet size variance closes the size_std fingerprint that the protocol
/// default of 512 B leaves visible.
const EVAL_FAKE_BODY_LENGTH_MAX: u64 = 1300;
/// Eval-side override: per-packet user-data length is sampled from
/// `[max_data_payload * (1 - JITTER), max_data_payload]` when fragmentation
/// is unavoidable, breaking the otherwise-uniform per-flow chunk-size
/// fingerprint.  Lower value used by QUIC profiles (see ``EVAL_QUIC_*``).
const EVAL_SEND_BYTES_JITTER: f64 = 0.30;
/// QUIC-only eval overrides.  Real QUIC s2c data caps just under 1200 B
/// wire; setting MTU=1450 leaves headroom but stops TYPHOON pushing packets
/// to 1500 B.  Lower jitter (0.1 vs 0.3) and a sparse decoy provider with
/// narrow length range supply the bimodal small-packet mode (ACK frames)
/// that the chunk-driven data path can't reach below the 76 B service-
/// packet floor.
const EVAL_QUIC_MTU: usize = 1450;
const EVAL_QUIC_SEND_BYTES_JITTER: f64 = 0.10;
const EVAL_QUIC_DECOY_SPARSE_LENGTH_MIN: u64 = 64;
const EVAL_QUIC_DECOY_SPARSE_LENGTH_MAX: u64 = 120;
/// Eval-side override: health-check interval pushed to 5-10 minutes so no
/// health-check packets fire inside the 30-120 s eval flows.  Health-checks
/// produced 0-1 off-cadence packets per flow that landed on the IAT
/// distribution as outliers, driving `iat_std` / `iat_entropy` Δs on
/// as_voice.  Asserted constraints: MIN > TIMEOUT_MAX (32 000), MIN < MAX.
const EVAL_HEALTH_CHECK_NEXT_IN_MIN: u64 = 300_000;
const EVAL_HEALTH_CHECK_NEXT_IN_MAX: u64 = 600_000;

/// Tuned-default overrides — applied only when `profile.is_tuned_default()`.
/// Push fragment-size jitter and fallthrough rate to the upper end of their
/// asserted ranges, and triple every decoy provider's base emission rate so
/// fallthrough packets dominate enough of the wire to break the residual
/// Constant-mode + max_user_payload modes that raw_default leaks.
const EVAL_TUNED_SEND_BYTES_JITTER: f64 = 0.8;
/// Tuned-default fragmentation target — 512 B with ±80 % jitter spreads
/// fragments across `[102, ~922]` B instead of pinning the MTU.  Directly
/// breaks the `size_max` / `size_std` discriminator that picks out
/// MTU-saturated TYPHOON flows from `unknown` traffic.
const EVAL_TUNED_SEND_BYTES_CHUNK: u64 = 512;
/// Tuned-default decoy-provider weights — bias selection toward `Sparse`
/// (gaussian around 700 B, well inside the wire-size band) and `Smooth`
/// (adaptive growth bounded by `SMOOTH_LENGTH_MAX`), away from `Noisy` and
/// `Heavy`, both of which saturate `DECOY_LENGTH_MAX` ≈ 1400 B during idle
/// periods and produce the MTU-bin spike in TYPHOON flows.  Weights must
/// stay positive (asserted by the settings layer).
const EVAL_TUNED_DECOY_PROVIDER_WEIGHT_SIMPLE: u64 = 1;
const EVAL_TUNED_DECOY_PROVIDER_WEIGHT_SPARSE: u64 = 6;
const EVAL_TUNED_DECOY_PROVIDER_WEIGHT_NOISY: u64 = 1;
const EVAL_TUNED_DECOY_PROVIDER_WEIGHT_SMOOTH: u64 = 3;
const EVAL_TUNED_DECOY_PROVIDER_WEIGHT_HEAVY: u64 = 1;
/// Tuned-default decoy current-rate alpha — slow the EWMA tracker from
/// `0.05` to `0.01` so the decoy provider's rate doesn't snap to data
/// bursts.  Keeps decoy emission steadier across bulk-vs-idle phases and
/// reduces the heavy-tailed burst-bytes-skew / kurt fingerprint.
const EVAL_TUNED_DECOY_CURRENT_ALPHA: f64 = 0.01;
const EVAL_TUNED_FALLTHROUGH_MIN: f64 = 0.0;
const EVAL_TUNED_FALLTHROUGH_MAX: f64 = 0.75;
/// Tuned-default decoy base rates — halved from the previous 3× sweep
/// (Heavy 0.15→0.075, Noisy 9.0→4.5, Sparse 60.0→30.0, Smooth 0.9→0.45).
/// `byte_sum` regressed from -0.16σ (raw) to +0.30σ (tuned) under the 3×
/// regime; halving brings the total bytes-per-flow back toward neutral
/// without removing the per-flow randomization breadth that the providers
/// still supply.
const EVAL_TUNED_DECOY_HEAVY_BASE_RATE: f64 = 0.075;
const EVAL_TUNED_DECOY_NOISY_BASE_RATE: f64 = 4.5;
const EVAL_TUNED_DECOY_SPARSE_BASE_RATE: f64 = 30.0;
const EVAL_TUNED_DECOY_SMOOTH_BASE_RATE: f64 = 0.45;
/// Tuned-default fake-header probability: 0.70.  The empirical sweep that
/// produced Test A FPR@95%TPR = 4.88% (vs 1.04% pre-tuning) confirmed that
/// per-flow shape variance dominates one-class detectability.  Dropping
/// from 0.85 → 0.70 increases the header-less outlier share to ~30%,
/// matching the long-tail residue's natural variance band more closely.
const EVAL_TUNED_FAKE_HEADER_PROBABILITY: f64 = 0.70;
/// Tuned-default fake-header length cap — raise from protocol default 32 B
/// to 48 B so the structured cleartext header section is large enough to
/// drag per-packet entropy below the encrypted-payload floor.
const EVAL_TUNED_FAKE_HEADER_LENGTH_MAX: u64 = 48;
/// Tuned-default field-type weights — push toward uniform (3/4/3/3/3, sum
/// 16) so no single field type dominates.  Constant retains a slight lean
/// (4/16 vs 3/16) for entropy reduction, but Random and Incremental at
/// 3/16 each (was 2/15 = 13%) add genuine field-shape variance that the
/// OCSVM cannot enclose tightly.
const EVAL_TUNED_HDR_WEIGHT_RANDOM: u64 = 3;
const EVAL_TUNED_HDR_WEIGHT_CONSTANT: u64 = 4;
const EVAL_TUNED_HDR_WEIGHT_VOLATILE: u64 = 3;
const EVAL_TUNED_HDR_WEIGHT_SWITCHING: u64 = 3;
const EVAL_TUNED_HDR_WEIGHT_INCREMENTAL: u64 = 3;
/// Tuned-default Volatile change-probability cap — 0.25 (was 0.15).
/// Continues the un-uniformify push: at 0.25 Volatile rotates noticeably
/// faster than Switching, adding a distinct rotation regime per field and
/// further broadening the per-flow manifold.
const EVAL_TUNED_VOLATILE_CHANGE_PROB_MAX: f64 = 0.25;
/// Tuned-default Switching timeout floor — 1500 ms (was 3000 ms).  Lower
/// floor means Switching rotates several times within typical 30-120 s
/// flows, adding cleartext-header shape variance that the previous 3 s
/// floor partially muted.
const EVAL_TUNED_SWITCHING_TIMEOUT_MIN_MS: u64 = 1500;
/// Tuned-default Constant body length cap — lower from 1400 B (= MTU) to
/// 900 B (Option A iteration: was 1100).  Empirical Test A ranking showed
/// `total_size_max` still leading with importance 0.088 and Δz=+1.15 after
/// the 1100 B cap, so we tighten further.  Caps every Constant-mode fake
/// body well below MTU, attacking the per-flow `total_size_max` and
/// `s2c_size_max` features that dominated the post-Track-A leak.
const EVAL_TUNED_FAKE_BODY_CONSTANT_LENGTH_MAX: u64 = 900;
/// Tuned-default decoy length cap — lower from 1400 B (= MTU) to 1100 B.
/// Applies to every decoy provider's output via the global
/// `DECOY_LENGTH_MAX` (Heavy / Smooth / Sparse / Noisy all clamp here),
/// so no decoy emission can park at MTU.  Combined with the Constant body
/// cap above, removes both remaining MTU-saturation sources from
/// tuned_default's wire shape.
const EVAL_TUNED_DECOY_LENGTH_MAX: u64 = 1100;

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

    // Tuned profiles get eval-side overrides; raw_default skips them so pure
    // protocol defaults are exercised.  QUIC profiles get an extra layer:
    // tighter MTU, lower send-bytes jitter, and a small-length sparse decoy
    // provider that supplies the bimodal ACK-sized packet mode real QUIC
    // shows.  Other tuned profiles use `SimpleDecoyProvider` (no decoys).
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

    if !profile.is_unrestricted() {
        if is_quic {
            builder = builder.with_decoy::<SparseDecoyProvider<ShortIdentity, DefaultExecutor>>();
        } else {
            builder = builder.with_decoy::<SimpleDecoyProvider>();
        }
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
        Some(tokio::spawn(run_c2s_send(
            socket.clone(),
            profile.clone(),
            deadline,
        )))
    } else {
        None
    };
    let recv_handle = if profile.has_s2c_traffic() {
        Some(tokio::spawn(run_s2c_recv(
            socket.clone(),
            profile.clone(),
            deadline,
        )))
    } else {
        None
    };

    let had_send = send_handle.is_some();
    let had_recv = recv_handle.is_some();
    let (sent, total_sleep_s) = match send_handle {
        Some(h) => h.await.expect("c2s join"),
        None => (0, 0.0),
    };
    let received = match recv_handle {
        Some(h) => h.await.expect("s2c join"),
        None => 0,
    };

    if !had_send && !had_recv {
        let now = Instant::now();
        if deadline > now {
            sleep(deadline - now).await;
        }
    }

    let elapsed_s = transfer_start.elapsed().as_secs_f64();
    let transfer_time_s = (elapsed_s - total_sleep_s).max(0.0);
    println!("Sent {sent} bytes c2s, received {received} bytes s2c — done");
    println!("transfer_time_s={transfer_time_s:.3}");
    exit(0);
}

/// Drive the c2s send loop, respecting `bytes_c2s`, `chunk_c2s`, IAT, and bursty mode.
async fn run_c2s_send(
    socket: Arc<
        typhoon::socket::ClientSocket<
            ShortIdentity,
            DefaultExecutor,
            DefaultClientConnectionHandler,
        >,
    >,
    profile: TrafficProfile,
    deadline: Instant,
) -> (usize, f64) {
    let buf_size = profile.chunk_c2s.max(profile.chunk_c2s_max);
    let chunk = vec![0u8; buf_size];
    let mut sent: usize = 0;
    let mut total_sleep_s: f64 = 0.0;

    if profile.bursty && profile.burst_count > 1 {
        let bytes_per_burst = profile.bytes_c2s / profile.burst_count.max(1);
        for i in 0..profile.burst_count {
            let (s, slept) = send_until(&socket, &chunk, &profile, deadline, sent + bytes_per_burst).await;
            sent += s;
            total_sleep_s += slept;
            if sent >= profile.bytes_c2s || Instant::now() >= deadline {
                break;
            }
            if i + 1 < profile.burst_count {
                let burst_idle = profile.burst_idle();
                let idle_until = Instant::now() + burst_idle;
                if idle_until > deadline {
                    break;
                }
                sleep(burst_idle).await;
                total_sleep_s += burst_idle.as_secs_f64();
            }
        }
    } else {
        let (s, slept) = send_until(&socket, &chunk, &profile, deadline, profile.bytes_c2s).await;
        sent += s;
        total_sleep_s += slept;
    }
    (sent, total_sleep_s)
}

async fn send_until(
    socket: &typhoon::socket::ClientSocket<
        ShortIdentity,
        DefaultExecutor,
        DefaultClientConnectionHandler,
    >,
    chunk: &[u8],
    profile: &TrafficProfile,
    deadline: Instant,
    target: usize,
) -> (usize, f64) {
    let mut sent = 0;
    let mut packets = 0;
    let mut total_sleep_s: f64 = 0.0;
    let fixed_delay = profile.c2s_delay();
    let randomise = profile.is_unrestricted();
    let inter_batch_delay_ms: f64 = var("INTER_PACKET_DELAY_MS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(40.0);
    let batch_size: u64 = var("DELAY_EVERY_N")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(10)
        .max(1);
    let batch_delay = Duration::from_micros((inter_batch_delay_ms * 1000.0) as u64);
    let mut packets_in_batch: u64 = 0;

    let mut rng = StdRng::from_entropy();
    while sent < target && Instant::now() < deadline && packets < profile.max_packets() {
        let pkt_size = if randomise {
            profile.sample_chunk_c2s(&mut rng)
        } else {
            profile.chunk_c2s
        };
        let n = pkt_size.min(target - sent).min(chunk.len());
        if n == 0 {
            break;
        }
        if socket.send_bytes(&chunk[..n]).await.is_err() {
            break;
        }
        sent += n;
        packets += 1;
        packets_in_batch += 1;
        let delay = if randomise {
            profile.sample_c2s_delay(&mut rng)
        } else {
            fixed_delay
        };
        if !delay.is_zero() {
            sleep(delay).await;
            total_sleep_s += delay.as_secs_f64();
        }
        if !batch_delay.is_zero() && packets_in_batch >= batch_size {
            sleep(batch_delay).await;
            total_sleep_s += batch_delay.as_secs_f64();
            packets_in_batch = 0;
        }
    }
    (sent, total_sleep_s)
}

/// Drive the s2c receive loop until the byte budget or deadline is met.
async fn run_s2c_recv(
    socket: Arc<
        typhoon::socket::ClientSocket<
            ShortIdentity,
            DefaultExecutor,
            DefaultClientConnectionHandler,
        >,
    >,
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
    while received < profile.bytes_s2c && !remaining.is_zero() {
        match timeout(remaining, socket.receive_bytes()).await {
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
