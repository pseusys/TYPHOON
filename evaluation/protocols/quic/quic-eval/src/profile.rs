//! Profile-driven send pacing — a Rust port of the c2s half of
//! `evaluation/protocols/common/_profile.py`.  Reading the same `PROFILE_*` /
//! `INTER_PACKET_DELAY_MS` / `DELAY_EVERY_N` env vars keeps the QUIC sender
//! paced identically to every other protocol, so the fair, pacing-subtracted
//! metric applies to it unchanged.

use std::env::var;

pub struct ProfileConfig {
    pub chunk_c2s: usize,
    pub iat_c2s_ms: f64,
    pub bytes_c2s: usize,
    pub duration_s: f64,
    pub bursty: bool,
    pub burst_count: usize,
    pub burst_idle_s: f64,
    pub inter_batch_ms: f64,
    pub batch_size: usize,
}

fn env_usize(key: &str, default: usize) -> usize {
    var(key)
        .ok()
        .and_then(|v| v.parse::<f64>().ok())
        .map(|v| v as usize)
        .unwrap_or(default)
}

fn env_f64(key: &str, default: f64) -> f64 {
    var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

impl ProfileConfig {
    pub fn from_env() -> Self {
        Self {
            chunk_c2s: env_usize("PROFILE_CHUNK_C2S", 500).max(1),
            iat_c2s_ms: env_f64("PROFILE_IAT_C2S_MS", 0.0),
            bytes_c2s: env_usize("PROFILE_BYTES_C2S", 10_485_760),
            duration_s: env_f64("PROFILE_DURATION_S", 60.0),
            bursty: env_usize("PROFILE_BURSTY", 0) != 0,
            burst_count: env_usize("PROFILE_BURST_COUNT", 1).max(1),
            burst_idle_s: env_f64("PROFILE_BURST_IDLE_S", 0.0),
            inter_batch_ms: env_f64("INTER_PACKET_DELAY_MS", 40.0),
            batch_size: env_usize("DELAY_EVERY_N", 10).max(1),
        }
    }
}
