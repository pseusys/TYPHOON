//! Runtime traffic profile for the TYPHOON eval client/server.
//!
//! A profile fixes per-direction packet sizes, inter-arrival times, total
//! byte budgets, session duration, and the FlowConfig override that the
//! TYPHOON client must use.  Both binaries read identical environment
//! variables so the profile is the same on each end of the connection
//! without any in-band negotiation.
//!
//! The profile catalogue (names and default ranges) is owned by the Python
//! side at `evaluation/src/typhoon_eval/shared/profiles.py`.  The Rust
//! binaries only consume already-sampled per-run values delivered as env
//! vars `PROFILE_*`.

use std::env::var;
use std::str::FromStr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rand::{Rng, thread_rng};
use typhoon::flow::{FakeBodyMode, FakeHeaderConfig, FieldType, FieldTypeHolder, FlowConfig};

/// Eval-side weights for fake-header field types.  Bias toward Constant /
/// Switching / Volatile so the cleartext fake-header bytes have meaningful
/// per-flow structure (per-flow random initial value held across packets)
/// instead of being uniformly random — the latter inflates payload_entropy
/// versus real protocol headers, which carry version / connection-ID /
/// sequence fields that look like Constant or rarely-changing fields.
///
/// Defaults bias structured types ~91 % vs Random 9 %.  Tunable here only
/// (eval-side); the protocol crate's defaults remain uniform.
const EVAL_HDR_WEIGHT_RANDOM: u32 = 1;
const EVAL_HDR_WEIGHT_CONSTANT: u32 = 5;
const EVAL_HDR_WEIGHT_VOLATILE: u32 = 2;
const EVAL_HDR_WEIGHT_SWITCHING: u32 = 2;
const EVAL_HDR_WEIGHT_INCREMENTAL: u32 = 1;
/// Range used for Volatile fields' `change_probability` (matches the
/// protocol-side `FakeHeaderConfig::random` defaults).
const EVAL_HDR_VOLATILE_PROB_MIN: f64 = 0.01;
const EVAL_HDR_VOLATILE_PROB_MAX: f64 = 0.20;
/// Switching field's per-flow `switch_timeout` is sampled from this range (ms).
const EVAL_HDR_SWITCHING_MIN_MS: u64 = 1_000;
const EVAL_HDR_SWITCHING_MAX_MS: u64 = 30_000;

/// Default profile name used when `TRAFFIC_PROFILE` is unset.
const DEFAULT_PROFILE_NAME: &str = "bulk_upload";

/// Sentinel profile name for the "no eval-side overrides" comparison target —
/// uses pure protocol defaults including `FlowConfig::random` instead of a
/// pinned per-profile FlowConfig.  Used to measure default TYPHOON blending.
pub const RAW_DEFAULT_PROFILE: &str = "raw_default";

/// Sentinel profile name for the "aggressively-tuned defaults" comparison
/// target — same per-packet randomization and `FlowConfig::random` freedom
/// as `raw_default`, but the eval binaries apply blending-oriented settings
/// overrides on top (jitter, fallthrough, decoy rates).
pub const TUNED_DEFAULT_PROFILE: &str = "tuned_default";

/// Maximum number of packets a single bulk profile run will emit before
/// stopping (safety net so a misconfigured run cannot saturate the network
/// indefinitely).
const MAX_PACKETS_HARD_LIMIT: usize = 1_000_000;

/// Mode of fake-body padding selected by the profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BodyMode {
    /// No padding — application payload only.
    Empty,
    /// Constant per-packet length (`constant_len`).
    Constant,
    /// Random per-packet length in `[random_min, random_max]`, applied to every packet.
    Random,
    /// Random per-packet length in `[random_min, random_max]`, applied only to service packets.
    RandomService,
}

impl FromStr for BodyMode {
    type Err = ProfileError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "empty" => Ok(BodyMode::Empty),
            "constant" => Ok(BodyMode::Constant),
            "random" => Ok(BodyMode::Random),
            "random_service" => Ok(BodyMode::RandomService),
            other => Err(ProfileError::Parse(format!("unknown body mode {other:?}"))),
        }
    }
}

/// Errors that can occur while reading the profile from environment variables.
#[derive(Debug)]
pub enum ProfileError {
    /// An env var failed to parse.
    Parse(String),
}

impl std::fmt::Display for ProfileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProfileError::Parse(msg) => write!(f, "profile parse error: {msg}"),
        }
    }
}

impl std::error::Error for ProfileError {}

/// Per-run traffic profile parameters resolved from the environment.
#[derive(Debug, Clone)]
pub struct TrafficProfile {
    /// Profile catalogue name (e.g. `bulk_upload`).
    pub name: String,
    /// Per-packet client → server application payload size (bytes).
    pub chunk_c2s: usize,
    /// Per-packet server → client application payload size (bytes).  Zero disables s2c.
    pub chunk_s2c: usize,
    /// Lower bound on per-packet c2s chunk size — used only by `raw_default`
    /// for per-packet resampling; tuned profiles ignore this and use `chunk_c2s`.
    pub chunk_c2s_min: usize,
    pub chunk_c2s_max: usize,
    pub chunk_s2c_min: usize,
    pub chunk_s2c_max: usize,
    /// Inter-arrival time between client → server sends (milliseconds).
    pub iat_c2s_ms: f64,
    /// Inter-arrival time between server → client sends (milliseconds).
    pub iat_s2c_ms: f64,
    /// IAT range bounds — same semantics as the chunk_*_min/max bounds.
    pub iat_c2s_ms_min: f64,
    pub iat_c2s_ms_max: f64,
    pub iat_s2c_ms_min: f64,
    pub iat_s2c_ms_max: f64,
    /// Target c2s byte budget; flow stops sending c2s once reached.
    pub bytes_c2s: usize,
    /// Target s2c byte budget; flow stops sending s2c once reached.
    pub bytes_s2c: usize,
    /// Wall-clock cap; whichever of `bytes_*` or `duration_s` triggers first stops the flow.
    pub duration_s: f64,
    /// Body-padding mode selected by the profile.
    pub body_mode: BodyMode,
    /// Constant-mode padding length.
    pub constant_len: usize,
    /// Random-mode minimum padding length.
    pub random_min: usize,
    /// Random-mode maximum padding length.
    pub random_max: usize,
    /// Bytes of fake header to prepend to each packet.
    pub fake_header_len: usize,
    /// Whether the c2s flow should be bursty.
    pub bursty: bool,
    /// Number of bursts when bursty.
    pub burst_count: usize,
    /// Idle gap between bursts when bursty (seconds).
    pub burst_idle_s: f64,
    /// Whether decoy traffic is allowed for this profile.  When false the
    /// eval client/server set every DECOY_*_BASE_RATE to 0 in their settings
    /// override, suppressing all decoy emission for the silent_idle profile.
    pub decoys_enabled: bool,
}

impl TrafficProfile {
    /// Read all `PROFILE_*` env vars and return a fully-populated profile.
    ///
    /// Missing variables fall back to the catalogue defaults for the named
    /// profile (or `bulk_upload` if `TRAFFIC_PROFILE` itself is missing).
    pub fn from_env() -> Result<Self, ProfileError> {
        let name = var("TRAFFIC_PROFILE").unwrap_or_else(|_| DEFAULT_PROFILE_NAME.to_string());
        let chunk_c2s = read_usize("PROFILE_CHUNK_C2S", 1200)?;
        let chunk_s2c = read_usize("PROFILE_CHUNK_S2C", 0)?;
        // MIN/MAX default to the sampled value so tuned profiles' callers get a
        // degenerate range (lo == hi) — `sample_chunk_c2s` then returns the
        // sampled value unchanged.
        let chunk_c2s_min = read_usize("PROFILE_CHUNK_C2S_MIN", chunk_c2s)?;
        let chunk_c2s_max = read_usize("PROFILE_CHUNK_C2S_MAX", chunk_c2s)?;
        let chunk_s2c_min = read_usize("PROFILE_CHUNK_S2C_MIN", chunk_s2c)?;
        let chunk_s2c_max = read_usize("PROFILE_CHUNK_S2C_MAX", chunk_s2c)?;
        let iat_c2s_ms = read_f64("PROFILE_IAT_C2S_MS", 0.0)?;
        let iat_s2c_ms = read_f64("PROFILE_IAT_S2C_MS", 0.0)?;
        let iat_c2s_ms_min = read_f64("PROFILE_IAT_C2S_MIN_MS", iat_c2s_ms)?;
        let iat_c2s_ms_max = read_f64("PROFILE_IAT_C2S_MAX_MS", iat_c2s_ms)?;
        let iat_s2c_ms_min = read_f64("PROFILE_IAT_S2C_MIN_MS", iat_s2c_ms)?;
        let iat_s2c_ms_max = read_f64("PROFILE_IAT_S2C_MAX_MS", iat_s2c_ms)?;
        let bytes_c2s = read_usize("PROFILE_BYTES_C2S", 10_485_760)?;
        let bytes_s2c = read_usize("PROFILE_BYTES_S2C", 0)?;
        let duration_s = read_f64("PROFILE_DURATION_S", 30.0)?;
        let body_mode = read_string("PROFILE_FAKE_BODY_MODE", "constant")?.parse()?;
        let constant_len = read_usize("PROFILE_FAKE_BODY_CONST", 0)?;
        let random_min = read_usize("PROFILE_FAKE_BODY_MIN", 0)?;
        let random_max = read_usize("PROFILE_FAKE_BODY_MAX", 0)?;
        let fake_header_len = read_usize("PROFILE_FAKE_HEADER_LEN", 0)?;
        let bursty = read_usize("PROFILE_BURSTY", 0)? != 0;
        let burst_count = read_usize("PROFILE_BURST_COUNT", 1)?;
        let burst_idle_s = read_f64("PROFILE_BURST_IDLE_S", 0.0)?;
        let decoys_enabled = read_usize("PROFILE_DECOYS_ENABLED", 1)? != 0;
        Ok(Self {
            name,
            chunk_c2s,
            chunk_s2c,
            chunk_c2s_min,
            chunk_c2s_max,
            chunk_s2c_min,
            chunk_s2c_max,
            iat_c2s_ms,
            iat_s2c_ms,
            iat_c2s_ms_min,
            iat_c2s_ms_max,
            iat_s2c_ms_min,
            iat_s2c_ms_max,
            bytes_c2s,
            bytes_s2c,
            duration_s,
            body_mode,
            constant_len,
            random_min,
            random_max,
            fake_header_len,
            bursty,
            burst_count,
            burst_idle_s,
            decoys_enabled,
        })
    }

    /// Build a `FlowConfig` matching this profile.  Returned config is
    /// passed via `with_flow_config` so it overrides `FlowConfig::random`.
    pub fn flow_config(&self) -> FlowConfig {
        let body = match self.body_mode {
            BodyMode::Empty => FakeBodyMode::Empty,
            BodyMode::Constant => FakeBodyMode::Constant {
                packet_length: self.constant_len,
            },
            BodyMode::Random => FakeBodyMode::Random {
                min_length: self.random_min,
                max_length: self.random_max,
                service: false,
            },
            BodyMode::RandomService => FakeBodyMode::Random {
                min_length: self.random_min,
                max_length: self.random_max,
                service: true,
            },
        };
        let header = if self.fake_header_len == 0 {
            FakeHeaderConfig::new(vec![])
        } else {
            FakeHeaderConfig::new(build_weighted_header_fields(self.fake_header_len))
        };
        FlowConfig::new(body, header)
    }

    /// IAT for c2s sends as a `Duration` (zero if `iat_c2s_ms` is zero).
    #[inline]
    pub fn c2s_delay(&self) -> Duration {
        Duration::from_micros((self.iat_c2s_ms * 1000.0) as u64)
    }

    /// IAT for s2c sends as a `Duration` (zero if `iat_s2c_ms` is zero).
    #[inline]
    pub fn s2c_delay(&self) -> Duration {
        Duration::from_micros((self.iat_s2c_ms * 1000.0) as u64)
    }

    /// Per-packet random c2s chunk size sampled uniformly in
    /// `[chunk_c2s_min, chunk_c2s_max]`.  Used by `raw_default` to give every
    /// c2s packet a fresh size from the profile's range — tuned profiles' MIN
    /// and MAX are both equal to the per-run sampled value, so the result is
    /// deterministic for them.
    #[inline]
    pub fn sample_chunk_c2s(&self, rng: &mut impl Rng) -> usize {
        if self.chunk_c2s_min >= self.chunk_c2s_max {
            self.chunk_c2s
        } else {
            rng.gen_range(self.chunk_c2s_min..=self.chunk_c2s_max)
        }
    }

    /// Per-packet random s2c chunk size — see `sample_chunk_c2s`.
    #[inline]
    pub fn sample_chunk_s2c(&self, rng: &mut impl Rng) -> usize {
        if self.chunk_s2c_min >= self.chunk_s2c_max {
            self.chunk_s2c
        } else {
            rng.gen_range(self.chunk_s2c_min..=self.chunk_s2c_max)
        }
    }

    /// Per-packet random c2s delay sampled uniformly in
    /// `[iat_c2s_ms_min, iat_c2s_ms_max]` (ms).
    #[inline]
    pub fn sample_c2s_delay(&self, rng: &mut impl Rng) -> Duration {
        let ms = if self.iat_c2s_ms_min >= self.iat_c2s_ms_max {
            self.iat_c2s_ms
        } else {
            rng.gen_range(self.iat_c2s_ms_min..=self.iat_c2s_ms_max)
        };
        Duration::from_micros((ms * 1000.0) as u64)
    }

    /// Per-packet random s2c delay — see `sample_c2s_delay`.
    #[inline]
    pub fn sample_s2c_delay(&self, rng: &mut impl Rng) -> Duration {
        let ms = if self.iat_s2c_ms_min >= self.iat_s2c_ms_max {
            self.iat_s2c_ms
        } else {
            rng.gen_range(self.iat_s2c_ms_min..=self.iat_s2c_ms_max)
        };
        Duration::from_micros((ms * 1000.0) as u64)
    }

    /// Per-flow duration cap as a `Duration`.
    #[inline]
    pub fn duration(&self) -> Duration {
        Duration::from_secs_f64(self.duration_s.max(0.0))
    }

    /// Idle gap between bursts as a `Duration`.
    #[inline]
    pub fn burst_idle(&self) -> Duration {
        Duration::from_secs_f64(self.burst_idle_s.max(0.0))
    }

    /// Whether the profile requires the c2s side to send any application data.
    #[inline]
    pub fn has_c2s_traffic(&self) -> bool {
        self.chunk_c2s > 0 && self.bytes_c2s > 0
    }

    /// Whether the profile requires the s2c side to send any application data.
    #[inline]
    pub fn has_s2c_traffic(&self) -> bool {
        self.chunk_s2c > 0 && self.bytes_s2c > 0
    }

    /// Hard upper bound on packet count per direction (defence-in-depth).
    #[inline]
    pub fn max_packets(&self) -> usize {
        MAX_PACKETS_HARD_LIMIT
    }

    /// True when this profile is the special "no eval-side overrides" target.
    /// In that case the eval client/server must NOT pin FlowConfig nor apply
    /// any settings overrides — so `FlowConfig::random` runs and measures
    /// pure protocol-default blending behaviour.
    #[inline]
    pub fn is_raw_default(&self) -> bool {
        self.name == RAW_DEFAULT_PROFILE
    }

    /// True for the aggressively-tuned defaults target.
    #[inline]
    pub fn is_tuned_default(&self) -> bool {
        self.name == TUNED_DEFAULT_PROFILE
    }

    #[inline]
    pub fn is_unrestricted(&self) -> bool {
        self.is_raw_default() || self.is_tuned_default()
    }

    #[inline]
    pub fn is_bulk_upload(&self) -> bool {
        self.name == DEFAULT_PROFILE_NAME
    }
}

#[inline]
fn read_string(key: &str, default: &str) -> Result<String, ProfileError> {
    Ok(var(key).unwrap_or_else(|_| default.to_string()))
}

#[inline]
fn read_usize(key: &str, default: usize) -> Result<usize, ProfileError> {
    match var(key) {
        Ok(val) => val
            .parse()
            .map_err(|e| ProfileError::Parse(format!("{key}={val:?}: {e}"))),
        Err(_) => Ok(default),
    }
}

#[inline]
fn read_f64(key: &str, default: f64) -> Result<f64, ProfileError> {
    match var(key) {
        Ok(val) => val
            .parse()
            .map_err(|e| ProfileError::Parse(format!("{key}={val:?}: {e}"))),
        Err(_) => Ok(default),
    }
}

/// Build *fake_header_len* U8 fake-header fields with field types sampled
/// from the eval-side weight distribution.  Mirrors the protocol's
/// `FakeHeaderConfig::random` field-construction logic, but reads weights
/// from this file's eval-side constants instead of `Settings`, so it works
/// for pinned `flow_config()` paths where we don't draw from `Settings`.
fn build_weighted_header_fields(fake_header_len: usize) -> Vec<FieldTypeHolder> {
    let mut rng = thread_rng();
    let weights = [
        EVAL_HDR_WEIGHT_RANDOM,
        EVAL_HDR_WEIGHT_CONSTANT,
        EVAL_HDR_WEIGHT_VOLATILE,
        EVAL_HDR_WEIGHT_SWITCHING,
        EVAL_HDR_WEIGHT_INCREMENTAL,
    ];
    let total: u32 = weights.iter().sum();
    let mut fields = Vec::with_capacity(fake_header_len);
    for _ in 0..fake_header_len {
        let mut pick = rng.gen_range(0..total);
        // Walk the weight array; subtract until we land in a bucket.
        let field = if check_bucket_takes(&mut pick, weights[0]) {
            FieldType::Random
        } else if check_bucket_takes(&mut pick, weights[1]) {
            FieldType::Constant {
                value: rng.r#gen::<u8>(),
            }
        } else if check_bucket_takes(&mut pick, weights[2]) {
            FieldType::Volatile {
                value: rng.r#gen::<u8>(),
                change_probability: rng
                    .gen_range(EVAL_HDR_VOLATILE_PROB_MIN..=EVAL_HDR_VOLATILE_PROB_MAX),
            }
        } else if check_bucket_takes(&mut pick, weights[3]) {
            let switch_timeout =
                rng.gen_range(EVAL_HDR_SWITCHING_MIN_MS..=EVAL_HDR_SWITCHING_MAX_MS);
            FieldType::Switching {
                value: rng.r#gen::<u8>(),
                next_switch: now_ms() + switch_timeout as u128,
                switch_timeout,
            }
        } else {
            FieldType::Incremental {
                value: rng.r#gen::<u8>(),
            }
        };
        fields.push(FieldTypeHolder::U8(field));
    }
    fields
}

/// `true` if *pick* falls inside the next *bucket*; otherwise subtract the
/// bucket width from *pick* and return `false`.  Lets us walk a weighted
/// sample with chained ifs without nested arithmetic in the conditions.
#[inline]
fn check_bucket_takes(pick: &mut u32, bucket: u32) -> bool {
    if *pick < bucket {
        true
    } else {
        *pick -= bucket;
        false
    }
}

/// Wall-clock milliseconds since the UNIX epoch — matches the protocol's
/// internal `unix_timestamp_ms()` helper used by `Switching` fields.
fn now_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0)
}
