use std::collections::HashMap;
use std::env::var;
use std::ops::{Add, Index};

use log::warn;

pub mod keys {
    pub const TYPHOON_ID_LENGTH: &str = "TYPHOON_ID_LENGTH";

    pub const TYPHOON_RTT_ALPHA: &str = "TYPHOON_RTT_ALPHA";
    pub const TYPHOON_RTT_BETA: &str = "TYPHOON_RTT_BETA";
    pub const TYPHOON_RTT_DEFAULT: &str = "TYPHOON_RTT_DEFAULT";
    pub const TYPHOON_RTT_MIN: &str = "TYPHOON_RTT_MIN";
    pub const TYPHOON_RTT_MAX: &str = "TYPHOON_RTT_MAX";
    pub const TYPHOON_TIMEOUT_DEFAULT: &str = "TYPHOON_TIMEOUT_DEFAULT";
    pub const TYPHOON_TIMEOUT_MIN: &str = "TYPHOON_TIMEOUT_MIN";
    pub const TYPHOON_TIMEOUT_MAX: &str = "TYPHOON_TIMEOUT_MAX";
    pub const TYPHOON_TIMEOUT_RTT_FACTOR: &str = "TYPHOON_TIMEOUT_RTT_FACTOR";
    pub const TYPHOON_HEALTH_CHECK_NEXT_IN_MIN: &str = "TYPHOON_HEALTH_CHECK_NEXT_IN_MIN";
    pub const TYPHOON_HEALTH_CHECK_NEXT_IN_MAX: &str = "TYPHOON_HEALTH_CHECK_NEXT_IN_MAX";
    pub const TYPHOON_HANDSHAKE_NEXT_IN_FACTOR: &str = "TYPHOON_HANDSHAKE_NEXT_IN_FACTOR";
    pub const TYPHOON_MAX_RETRIES: &str = "TYPHOON_MAX_RETRIES";

    pub const TYPHOON_FAKE_BODY_LENGTH_MIN: &str = "TYPHOON_FAKE_BODY_LENGTH_MIN";
    pub const TYPHOON_FAKE_BODY_LENGTH_MAX: &str = "TYPHOON_FAKE_BODY_LENGTH_MAX";
    pub const TYPHOON_FAKE_BODY_SERVICE_PROBABILITY: &str = "TYPHOON_FAKE_BODY_SERVICE_PROBABILITY";
    pub const TYPHOON_FAKE_HEADER_LENGTH_MIN: &str = "TYPHOON_FAKE_HEADER_LENGTH_MIN";
    pub const TYPHOON_FAKE_HEADER_LENGTH_MAX: &str = "TYPHOON_FAKE_HEADER_LENGTH_MAX";
    pub const TYPHOON_FAKE_HEADER_PROBABILITY: &str = "TYPHOON_FAKE_HEADER_PROBABILITY";

    pub const TYPHOON_DECOY_REFERENCE_PACKET_RATE_DEFAULT: &str = "TYPHOON_DECOY_REFERENCE_PACKET_RATE_DEFAULT";
    pub const TYPHOON_DECOY_CURRENT_PACKET_RATE_DEFAULT: &str = "TYPHOON_DECOY_CURRENT_PACKET_RATE_DEFAULT";
    pub const TYPHOON_DECOY_CURRENT_BYTE_RATE_DEFAULT: &str = "TYPHOON_DECOY_CURRENT_BYTE_RATE_DEFAULT";
    pub const TYPHOON_DECOY_BYTE_RATE_CAP: &str = "TYPHOON_DECOY_BYTE_RATE_CAP";
    pub const TYPHOON_DECOY_BYTE_RATE_FACTOR: &str = "TYPHOON_DECOY_BYTE_RATE_FACTOR";
    pub const TYPHOON_DECOY_CURRENT_ALPHA: &str = "TYPHOON_DECOY_CURRENT_ALPHA";
    pub const TYPHOON_DECOY_REFERENCE_ALPHA: &str = "TYPHOON_DECOY_REFERENCE_ALPHA";
    pub const TYPHOON_DECOY_LENGTH_MAX: &str = "TYPHOON_DECOY_LENGTH_MAX";
    pub const TYPHOON_DECOY_LENGTH_MIN: &str = "TYPHOON_DECOY_LENGTH_MIN";
    pub const TYPHOON_DECOY_REFERENCE_BURST_FACTOR: &str = "TYPHOON_DECOY_REFERENCE_BURST_FACTOR";
    pub const TYPHOON_DECOY_BASE_RATE_RND: &str = "TYPHOON_DECOY_BASE_RATE_RND";

    pub const TYPHOON_DECOY_HEAVY_BASE_RATE: &str = "TYPHOON_DECOY_HEAVY_BASE_RATE";
    pub const TYPHOON_DECOY_HEAVY_QUIETNESS_FACTOR: &str = "TYPHOON_DECOY_HEAVY_QUIETNESS_FACTOR";
    pub const TYPHOON_DECOY_HEAVY_DELAY_MIN: &str = "TYPHOON_DECOY_HEAVY_DELAY_MIN";
    pub const TYPHOON_DECOY_HEAVY_DELAY_MAX: &str = "TYPHOON_DECOY_HEAVY_DELAY_MAX";
    pub const TYPHOON_DECOY_HEAVY_DELAY_DEFAULT: &str = "TYPHOON_DECOY_HEAVY_DELAY_DEFAULT";
    pub const TYPHOON_DECOY_HEAVY_BASE_LENGTH: &str = "TYPHOON_DECOY_HEAVY_BASE_LENGTH";
    pub const TYPHOON_DECOY_HEAVY_QUIETNESS_LENGTH: &str = "TYPHOON_DECOY_HEAVY_QUIETNESS_LENGTH";
    pub const TYPHOON_DECOY_HEAVY_DECOY_LENGTH_FACTOR: &str = "TYPHOON_DECOY_HEAVY_DECOY_LENGTH_FACTOR";

    pub const TYPHOON_DECOY_NOISY_BASE_RATE: &str = "TYPHOON_DECOY_NOISY_BASE_RATE";
    pub const TYPHOON_DECOY_NOISY_DELAY_MIN: &str = "TYPHOON_DECOY_NOISY_DELAY_MIN";
    pub const TYPHOON_DECOY_NOISY_DELAY_MAX: &str = "TYPHOON_DECOY_NOISY_DELAY_MAX";
    pub const TYPHOON_DECOY_NOISY_DELAY_DEFAULT: &str = "TYPHOON_DECOY_NOISY_DELAY_DEFAULT";
    pub const TYPHOON_DECOY_NOISY_DECOY_LENGTH_MIN: &str = "TYPHOON_DECOY_NOISY_DECOY_LENGTH_MIN";
    pub const TYPHOON_DECOY_NOISY_DECOY_LENGTH_JITTER: &str = "TYPHOON_DECOY_NOISY_DECOY_LENGTH_JITTER";

    pub const TYPHOON_DECOY_SPARSE_BASE_RATE: &str = "TYPHOON_DECOY_SPARSE_BASE_RATE";
    pub const TYPHOON_DECOY_SPARSE_RATE_FACTOR: &str = "TYPHOON_DECOY_SPARSE_RATE_FACTOR";
    pub const TYPHOON_DECOY_SPARSE_JITTER: &str = "TYPHOON_DECOY_SPARSE_JITTER";
    pub const TYPHOON_DECOY_SPARSE_DELAY_FACTOR: &str = "TYPHOON_DECOY_SPARSE_DELAY_FACTOR";
    pub const TYPHOON_DECOY_SPARSE_DELAY_MIN: &str = "TYPHOON_DECOY_SPARSE_DELAY_MIN";
    pub const TYPHOON_DECOY_SPARSE_DELAY_MAX: &str = "TYPHOON_DECOY_SPARSE_DELAY_MAX";
    pub const TYPHOON_DECOY_SPARSE_DELAY_DEFAULT: &str = "TYPHOON_DECOY_SPARSE_DELAY_DEFAULT";
    pub const TYPHOON_DECOY_SPARSE_LENGTH_FACTOR: &str = "TYPHOON_DECOY_SPARSE_LENGTH_FACTOR";
    pub const TYPHOON_DECOY_SPARSE_LENGTH_SIGMA: &str = "TYPHOON_DECOY_SPARSE_LENGTH_SIGMA";
    pub const TYPHOON_DECOY_SPARSE_LENGTH_MIN: &str = "TYPHOON_DECOY_SPARSE_LENGTH_MIN";
    pub const TYPHOON_DECOY_SPARSE_LENGTH_MAX: &str = "TYPHOON_DECOY_SPARSE_LENGTH_MAX";

    pub const TYPHOON_DECOY_SMOOTH_BASE_RATE: &str = "TYPHOON_DECOY_SMOOTH_BASE_RATE";
    pub const TYPHOON_DECOY_SMOOTH_QUIETNESS_FACTOR: &str = "TYPHOON_DECOY_SMOOTH_QUIETNESS_FACTOR";
    pub const TYPHOON_DECOY_SMOOTH_RATE_FACTOR: &str = "TYPHOON_DECOY_SMOOTH_RATE_FACTOR";
    pub const TYPHOON_DECOY_SMOOTH_JITTER: &str = "TYPHOON_DECOY_SMOOTH_JITTER";
    pub const TYPHOON_DECOY_SMOOTH_DELAY_FACTOR: &str = "TYPHOON_DECOY_SMOOTH_DELAY_FACTOR";
    pub const TYPHOON_DECOY_SMOOTH_DELAY_MIN: &str = "TYPHOON_DECOY_SMOOTH_DELAY_MIN";
    pub const TYPHOON_DECOY_SMOOTH_DELAY_MAX: &str = "TYPHOON_DECOY_SMOOTH_DELAY_MAX";
    pub const TYPHOON_DECOY_SMOOTH_DELAY_DEFAULT: &str = "TYPHOON_DECOY_SMOOTH_DELAY_DEFAULT";
    pub const TYPHOON_DECOY_SMOOTH_LENGTH_MIN: &str = "TYPHOON_DECOY_SMOOTH_LENGTH_MIN";
    pub const TYPHOON_DECOY_SMOOTH_LENGTH_MAX: &str = "TYPHOON_DECOY_SMOOTH_LENGTH_MAX";

    pub const TYPHOON_DECOY_MAINTENANCE_LENGTH_MIN: &str = "TYPHOON_DECOY_MAINTENANCE_LENGTH_MIN";
    pub const TYPHOON_DECOY_MAINTENANCE_LENGTH_MAX: &str = "TYPHOON_DECOY_MAINTENANCE_LENGTH_MAX";
    pub const TYPHOON_DECOY_MAINTENANCE_DELAY_MIN: &str = "TYPHOON_DECOY_MAINTENANCE_DELAY_MIN";
    pub const TYPHOON_DECOY_MAINTENANCE_DELAY_MAX: &str = "TYPHOON_DECOY_MAINTENANCE_DELAY_MAX";
    pub const TYPHOON_DECOY_MAINTENANCE_MODE_NONE_PROBABILITY: &str = "TYPHOON_DECOY_MAINTENANCE_MODE_NONE_PROBABILITY";

    pub const TYPHOON_DECOY_REPLICATION_PROBABILITY_MIN: &str = "TYPHOON_DECOY_REPLICATION_PROBABILITY_MIN";
    pub const TYPHOON_DECOY_REPLICATION_PROBABILITY_MAX: &str = "TYPHOON_DECOY_REPLICATION_PROBABILITY_MAX";
    pub const TYPHOON_DECOY_REPLICATION_PROBABILITY_REDUCE: &str = "TYPHOON_DECOY_REPLICATION_PROBABILITY_REDUCE";
    pub const TYPHOON_DECOY_REPLICATION_DELAY_MIN: &str = "TYPHOON_DECOY_REPLICATION_DELAY_MIN";
    pub const TYPHOON_DECOY_REPLICATION_DELAY_MAX: &str = "TYPHOON_DECOY_REPLICATION_DELAY_MAX";
    pub const TYPHOON_DECOY_REPLICATION_MODE_NONE_PROBABILITY: &str = "TYPHOON_DECOY_REPLICATION_MODE_NONE_PROBABILITY";

    pub const TYPHOON_DECOY_SUBHEADER_LENGTH_MIN: &str = "TYPHOON_DECOY_SUBHEADER_LENGTH_MIN";
    pub const TYPHOON_DECOY_SUBHEADER_LENGTH_MAX: &str = "TYPHOON_DECOY_SUBHEADER_LENGTH_MAX";

    pub const TAILOR_LENGTH: &str = "TAILOR_LENGTH";
    pub const FG_OFFSET: &str = "FG_OFFSET";
    pub const CD_OFFSET: &str = "CD_OFFSET";
    pub const TM_OFFSET: &str = "TM_OFFSET";
    pub const PN_OFFSET: &str = "PN_OFFSET";
    pub const PL_OFFSET: &str = "PL_OFFSET";
    pub const ID_OFFSET: &str = "ID_OFFSET";
}

mod values {
    pub const TYPHOON_ID_LENGTH: u64 = 16;

    pub const TYPHOON_RTT_ALPHA: f64 = 0.125;
    pub const TYPHOON_RTT_BETA: f64 = 0.25;
    pub const TYPHOON_RTT_DEFAULT: u64 = 5000;
    pub const TYPHOON_RTT_MIN: u64 = 1000;
    pub const TYPHOON_RTT_MAX: u64 = 8000;
    pub const TYPHOON_TIMEOUT_DEFAULT: u64 = 30000;
    pub const TYPHOON_TIMEOUT_MIN: u64 = 4000;
    pub const TYPHOON_TIMEOUT_MAX: u64 = 32000;
    pub const TYPHOON_TIMEOUT_RTT_FACTOR: f64 = 5.0;
    pub const TYPHOON_HEALTH_CHECK_NEXT_IN_MIN: u64 = 64000;
    pub const TYPHOON_HEALTH_CHECK_NEXT_IN_MAX: u64 = 256000;
    pub const TYPHOON_HANDSHAKE_NEXT_IN_FACTOR: f64 = 0.02;
    pub const TYPHOON_MAX_RETRIES: u64 = 12;

    pub const TYPHOON_FAKE_BODY_LENGTH_MIN: u64 = 0;
    pub const TYPHOON_FAKE_BODY_LENGTH_MAX: u64 = 256;
    pub const TYPHOON_FAKE_BODY_SERVICE_PROBABILITY: f64 = 5.0;
    pub const TYPHOON_FAKE_HEADER_LENGTH_MIN: u64 = 4;
    pub const TYPHOON_FAKE_HEADER_LENGTH_MAX: u64 = 32;
    pub const TYPHOON_FAKE_HEADER_PROBABILITY: f64 = 0.35;

    pub const TYPHOON_DECOY_REFERENCE_PACKET_RATE_DEFAULT: f64 = 200.0;
    pub const TYPHOON_DECOY_CURRENT_PACKET_RATE_DEFAULT: f64 = 200.0;
    pub const TYPHOON_DECOY_CURRENT_BYTE_RATE_DEFAULT: f64 = 5000.0;
    pub const TYPHOON_DECOY_BYTE_RATE_CAP: f64 = 1000000.0;
    pub const TYPHOON_DECOY_BYTE_RATE_FACTOR: f64 = 3.0;
    pub const TYPHOON_DECOY_CURRENT_ALPHA: f64 = 0.05;
    pub const TYPHOON_DECOY_REFERENCE_ALPHA: f64 = 0.001;
    pub const TYPHOON_DECOY_LENGTH_MAX: u64 = 1024;
    pub const TYPHOON_DECOY_LENGTH_MIN: u64 = 16;
    pub const TYPHOON_DECOY_REFERENCE_BURST_FACTOR: f64 = 3.0;
    pub const TYPHOON_DECOY_BASE_RATE_RND: f64 = 0.25;

    pub const TYPHOON_DECOY_HEAVY_BASE_RATE: f64 = 0.05;
    pub const TYPHOON_DECOY_HEAVY_QUIETNESS_FACTOR: f64 = 3.0;
    pub const TYPHOON_DECOY_HEAVY_DELAY_MIN: u64 = 5000;
    pub const TYPHOON_DECOY_HEAVY_DELAY_MAX: u64 = 120000;
    pub const TYPHOON_DECOY_HEAVY_DELAY_DEFAULT: u64 = 64000;
    pub const TYPHOON_DECOY_HEAVY_BASE_LENGTH: f64 = 0.7;
    pub const TYPHOON_DECOY_HEAVY_QUIETNESS_LENGTH: f64 = 0.3;
    pub const TYPHOON_DECOY_HEAVY_DECOY_LENGTH_FACTOR: f64 = 0.8;

    pub const TYPHOON_DECOY_NOISY_BASE_RATE: f64 = 3.0;
    pub const TYPHOON_DECOY_NOISY_DELAY_MIN: u64 = 10;
    pub const TYPHOON_DECOY_NOISY_DELAY_MAX: u64 = 1000;
    pub const TYPHOON_DECOY_NOISY_DELAY_DEFAULT: u64 = 500;
    pub const TYPHOON_DECOY_NOISY_DECOY_LENGTH_MIN: u64 = 128;
    pub const TYPHOON_DECOY_NOISY_DECOY_LENGTH_JITTER: f64 = 0.3;

    pub const TYPHOON_DECOY_SPARSE_BASE_RATE: f64 = 20.0;
    pub const TYPHOON_DECOY_SPARSE_RATE_FACTOR: f64 = 3.0;
    pub const TYPHOON_DECOY_SPARSE_JITTER: f64 = 0.15;
    pub const TYPHOON_DECOY_SPARSE_DELAY_FACTOR: f64 = 3.0;
    pub const TYPHOON_DECOY_SPARSE_DELAY_MIN: u64 = 20;
    pub const TYPHOON_DECOY_SPARSE_DELAY_MAX: u64 = 150;
    pub const TYPHOON_DECOY_SPARSE_DELAY_DEFAULT: u64 = 100;
    pub const TYPHOON_DECOY_SPARSE_LENGTH_FACTOR: f64 = 120.0;
    pub const TYPHOON_DECOY_SPARSE_LENGTH_SIGMA: f64 = 20.0;
    pub const TYPHOON_DECOY_SPARSE_LENGTH_MIN: u64 = 75;
    pub const TYPHOON_DECOY_SPARSE_LENGTH_MAX: u64 = 250;

    pub const TYPHOON_DECOY_SMOOTH_BASE_RATE: f64 = 0.3;
    pub const TYPHOON_DECOY_SMOOTH_QUIETNESS_FACTOR: f64 = 2.0;
    pub const TYPHOON_DECOY_SMOOTH_RATE_FACTOR: f64 = 3.0;
    pub const TYPHOON_DECOY_SMOOTH_JITTER: f64 = 0.2;
    pub const TYPHOON_DECOY_SMOOTH_DELAY_FACTOR: f64 = 2.0;
    pub const TYPHOON_DECOY_SMOOTH_DELAY_MIN: u64 = 300;
    pub const TYPHOON_DECOY_SMOOTH_DELAY_MAX: u64 = 10000;
    pub const TYPHOON_DECOY_SMOOTH_DELAY_DEFAULT: u64 = 5000;
    pub const TYPHOON_DECOY_SMOOTH_LENGTH_MIN: u64 = 48;
    pub const TYPHOON_DECOY_SMOOTH_LENGTH_MAX: u64 = 512;

    pub const TYPHOON_DECOY_MAINTENANCE_LENGTH_MIN: u64 = 8;
    pub const TYPHOON_DECOY_MAINTENANCE_LENGTH_MAX: u64 = 256;
    pub const TYPHOON_DECOY_MAINTENANCE_DELAY_MIN: u64 = 3000;
    pub const TYPHOON_DECOY_MAINTENANCE_DELAY_MAX: u64 = 720000;
    pub const TYPHOON_DECOY_MAINTENANCE_MODE_NONE_PROBABILITY: f64 = 3.0;

    pub const TYPHOON_DECOY_REPLICATION_PROBABILITY_MIN: f64 = 0.01;
    pub const TYPHOON_DECOY_REPLICATION_PROBABILITY_MAX: f64 = 0.1;
    pub const TYPHOON_DECOY_REPLICATION_PROBABILITY_REDUCE: f64 = 3.0;
    pub const TYPHOON_DECOY_REPLICATION_DELAY_MIN: u64 = 2500;
    pub const TYPHOON_DECOY_REPLICATION_DELAY_MAX: u64 = 10000;
    pub const TYPHOON_DECOY_REPLICATION_MODE_NONE_PROBABILITY: f64 = 3.0;

    pub const TYPHOON_DECOY_SUBHEADER_LENGTH_MIN: u64 = 4;
    pub const TYPHOON_DECOY_SUBHEADER_LENGTH_MAX: u64 = 16;

    pub const TAILOR_LENGTH: u64 = 16;
    pub const FG_OFFSET: u64 = 0;
    pub const CD_OFFSET: u64 = 1;
    pub const TM_OFFSET: u64 = 2;
    pub const PN_OFFSET: u64 = 6;
    pub const PL_OFFSET: u64 = 14;
    pub const ID_OFFSET: u64 = 16;
}

#[derive(Copy, Clone, Debug)]
pub enum SettingValue {
    Signed(i64),
    Unsigned(u64),
    Float(f64),
}

impl Add for SettingValue {
    type Output = Self;

    #[inline]
    fn add(self, rhs: Self) -> Self::Output {
        match (self, rhs) {
            (SettingValue::Signed(a), SettingValue::Signed(b)) => SettingValue::Signed(a + b),
            (SettingValue::Unsigned(a), SettingValue::Unsigned(b)) => SettingValue::Unsigned(a + b),
            (SettingValue::Float(a), SettingValue::Float(b)) => SettingValue::Float(a + b),
            (SettingValue::Signed(a), SettingValue::Unsigned(b)) => SettingValue::Float(a as f64 + b as f64),
            (SettingValue::Unsigned(a), SettingValue::Signed(b)) => SettingValue::Float(a as f64 + b as f64),
            (SettingValue::Signed(a), SettingValue::Float(b)) | (SettingValue::Float(b), SettingValue::Signed(a)) => SettingValue::Float(a as f64 + b),
            (SettingValue::Unsigned(a), SettingValue::Float(b)) | (SettingValue::Float(b), SettingValue::Unsigned(a)) => SettingValue::Float(a as f64 + b),
        }
    }
}

type DefaultMap = HashMap<&'static str, SettingValue>;

#[inline]
fn default_values_map() -> DefaultMap {
    let mut map = HashMap::new();
    map.insert(keys::TYPHOON_ID_LENGTH, SettingValue::Unsigned(values::TYPHOON_ID_LENGTH));
    map.insert(keys::TYPHOON_RTT_ALPHA, SettingValue::Float(values::TYPHOON_RTT_ALPHA));
    map.insert(keys::TYPHOON_RTT_BETA, SettingValue::Float(values::TYPHOON_RTT_BETA));
    map.insert(keys::TYPHOON_RTT_DEFAULT, SettingValue::Unsigned(values::TYPHOON_RTT_DEFAULT));
    map.insert(keys::TYPHOON_RTT_MIN, SettingValue::Unsigned(values::TYPHOON_RTT_MIN));
    map.insert(keys::TYPHOON_RTT_MAX, SettingValue::Unsigned(values::TYPHOON_RTT_MAX));
    map.insert(keys::TYPHOON_TIMEOUT_DEFAULT, SettingValue::Unsigned(values::TYPHOON_TIMEOUT_DEFAULT));
    map.insert(keys::TYPHOON_TIMEOUT_MIN, SettingValue::Unsigned(values::TYPHOON_TIMEOUT_MIN));
    map.insert(keys::TYPHOON_TIMEOUT_MAX, SettingValue::Unsigned(values::TYPHOON_TIMEOUT_MAX));
    map.insert(keys::TYPHOON_TIMEOUT_RTT_FACTOR, SettingValue::Float(values::TYPHOON_TIMEOUT_RTT_FACTOR));
    map.insert(keys::TYPHOON_HEALTH_CHECK_NEXT_IN_MIN, SettingValue::Unsigned(values::TYPHOON_HEALTH_CHECK_NEXT_IN_MIN));
    map.insert(keys::TYPHOON_HEALTH_CHECK_NEXT_IN_MAX, SettingValue::Unsigned(values::TYPHOON_HEALTH_CHECK_NEXT_IN_MAX));
    map.insert(keys::TYPHOON_HANDSHAKE_NEXT_IN_FACTOR, SettingValue::Float(values::TYPHOON_HANDSHAKE_NEXT_IN_FACTOR));
    map.insert(keys::TYPHOON_MAX_RETRIES, SettingValue::Unsigned(values::TYPHOON_MAX_RETRIES));
    map.insert(keys::TYPHOON_FAKE_BODY_LENGTH_MIN, SettingValue::Unsigned(values::TYPHOON_FAKE_BODY_LENGTH_MIN));
    map.insert(keys::TYPHOON_FAKE_BODY_LENGTH_MAX, SettingValue::Unsigned(values::TYPHOON_FAKE_BODY_LENGTH_MAX));
    map.insert(keys::TYPHOON_FAKE_BODY_SERVICE_PROBABILITY, SettingValue::Float(values::TYPHOON_FAKE_BODY_SERVICE_PROBABILITY));
    map.insert(keys::TYPHOON_FAKE_HEADER_LENGTH_MIN, SettingValue::Unsigned(values::TYPHOON_FAKE_HEADER_LENGTH_MIN));
    map.insert(keys::TYPHOON_FAKE_HEADER_LENGTH_MAX, SettingValue::Unsigned(values::TYPHOON_FAKE_HEADER_LENGTH_MAX));
    map.insert(keys::TYPHOON_FAKE_HEADER_PROBABILITY, SettingValue::Float(values::TYPHOON_FAKE_HEADER_PROBABILITY));
    map.insert(keys::TYPHOON_DECOY_REFERENCE_PACKET_RATE_DEFAULT, SettingValue::Float(values::TYPHOON_DECOY_REFERENCE_PACKET_RATE_DEFAULT));
    map.insert(keys::TYPHOON_DECOY_CURRENT_PACKET_RATE_DEFAULT, SettingValue::Float(values::TYPHOON_DECOY_CURRENT_PACKET_RATE_DEFAULT));
    map.insert(keys::TYPHOON_DECOY_CURRENT_BYTE_RATE_DEFAULT, SettingValue::Float(values::TYPHOON_DECOY_CURRENT_BYTE_RATE_DEFAULT));
    map.insert(keys::TYPHOON_DECOY_BYTE_RATE_CAP, SettingValue::Float(values::TYPHOON_DECOY_BYTE_RATE_CAP));
    map.insert(keys::TYPHOON_DECOY_BYTE_RATE_FACTOR, SettingValue::Float(values::TYPHOON_DECOY_BYTE_RATE_FACTOR));
    map.insert(keys::TYPHOON_DECOY_CURRENT_ALPHA, SettingValue::Float(values::TYPHOON_DECOY_CURRENT_ALPHA));
    map.insert(keys::TYPHOON_DECOY_REFERENCE_ALPHA, SettingValue::Float(values::TYPHOON_DECOY_REFERENCE_ALPHA));
    map.insert(keys::TYPHOON_DECOY_LENGTH_MAX, SettingValue::Unsigned(values::TYPHOON_DECOY_LENGTH_MAX));
    map.insert(keys::TYPHOON_DECOY_LENGTH_MIN, SettingValue::Unsigned(values::TYPHOON_DECOY_LENGTH_MIN));
    map.insert(keys::TYPHOON_DECOY_REFERENCE_BURST_FACTOR, SettingValue::Float(values::TYPHOON_DECOY_REFERENCE_BURST_FACTOR));
    map.insert(keys::TYPHOON_DECOY_BASE_RATE_RND, SettingValue::Float(values::TYPHOON_DECOY_BASE_RATE_RND));
    map.insert(keys::TYPHOON_DECOY_HEAVY_BASE_RATE, SettingValue::Float(values::TYPHOON_DECOY_HEAVY_BASE_RATE));
    map.insert(keys::TYPHOON_DECOY_HEAVY_QUIETNESS_FACTOR, SettingValue::Float(values::TYPHOON_DECOY_HEAVY_QUIETNESS_FACTOR));
    map.insert(keys::TYPHOON_DECOY_HEAVY_DELAY_MIN, SettingValue::Unsigned(values::TYPHOON_DECOY_HEAVY_DELAY_MIN));
    map.insert(keys::TYPHOON_DECOY_HEAVY_DELAY_MAX, SettingValue::Unsigned(values::TYPHOON_DECOY_HEAVY_DELAY_MAX));
    map.insert(keys::TYPHOON_DECOY_HEAVY_DELAY_DEFAULT, SettingValue::Unsigned(values::TYPHOON_DECOY_HEAVY_DELAY_DEFAULT));
    map.insert(keys::TYPHOON_DECOY_HEAVY_BASE_LENGTH, SettingValue::Float(values::TYPHOON_DECOY_HEAVY_BASE_LENGTH));
    map.insert(keys::TYPHOON_DECOY_HEAVY_QUIETNESS_LENGTH, SettingValue::Float(values::TYPHOON_DECOY_HEAVY_QUIETNESS_LENGTH));
    map.insert(keys::TYPHOON_DECOY_HEAVY_DECOY_LENGTH_FACTOR, SettingValue::Float(values::TYPHOON_DECOY_HEAVY_DECOY_LENGTH_FACTOR));
    map.insert(keys::TYPHOON_DECOY_NOISY_BASE_RATE, SettingValue::Float(values::TYPHOON_DECOY_NOISY_BASE_RATE));
    map.insert(keys::TYPHOON_DECOY_NOISY_DELAY_MIN, SettingValue::Unsigned(values::TYPHOON_DECOY_NOISY_DELAY_MIN));
    map.insert(keys::TYPHOON_DECOY_NOISY_DELAY_MAX, SettingValue::Unsigned(values::TYPHOON_DECOY_NOISY_DELAY_MAX));
    map.insert(keys::TYPHOON_DECOY_NOISY_DELAY_DEFAULT, SettingValue::Unsigned(values::TYPHOON_DECOY_NOISY_DELAY_DEFAULT));
    map.insert(keys::TYPHOON_DECOY_NOISY_DECOY_LENGTH_MIN, SettingValue::Unsigned(values::TYPHOON_DECOY_NOISY_DECOY_LENGTH_MIN));
    map.insert(keys::TYPHOON_DECOY_NOISY_DECOY_LENGTH_JITTER, SettingValue::Float(values::TYPHOON_DECOY_NOISY_DECOY_LENGTH_JITTER));
    map.insert(keys::TYPHOON_DECOY_SPARSE_BASE_RATE, SettingValue::Float(values::TYPHOON_DECOY_SPARSE_BASE_RATE));
    map.insert(keys::TYPHOON_DECOY_SPARSE_RATE_FACTOR, SettingValue::Float(values::TYPHOON_DECOY_SPARSE_RATE_FACTOR));
    map.insert(keys::TYPHOON_DECOY_SPARSE_JITTER, SettingValue::Float(values::TYPHOON_DECOY_SPARSE_JITTER));
    map.insert(keys::TYPHOON_DECOY_SPARSE_DELAY_FACTOR, SettingValue::Float(values::TYPHOON_DECOY_SPARSE_DELAY_FACTOR));
    map.insert(keys::TYPHOON_DECOY_SPARSE_DELAY_MIN, SettingValue::Unsigned(values::TYPHOON_DECOY_SPARSE_DELAY_MIN));
    map.insert(keys::TYPHOON_DECOY_SPARSE_DELAY_MAX, SettingValue::Unsigned(values::TYPHOON_DECOY_SPARSE_DELAY_MAX));
    map.insert(keys::TYPHOON_DECOY_SPARSE_DELAY_DEFAULT, SettingValue::Unsigned(values::TYPHOON_DECOY_SPARSE_DELAY_DEFAULT));
    map.insert(keys::TYPHOON_DECOY_SPARSE_LENGTH_FACTOR, SettingValue::Float(values::TYPHOON_DECOY_SPARSE_LENGTH_FACTOR));
    map.insert(keys::TYPHOON_DECOY_SPARSE_LENGTH_SIGMA, SettingValue::Float(values::TYPHOON_DECOY_SPARSE_LENGTH_SIGMA));
    map.insert(keys::TYPHOON_DECOY_SPARSE_LENGTH_MIN, SettingValue::Unsigned(values::TYPHOON_DECOY_SPARSE_LENGTH_MIN));
    map.insert(keys::TYPHOON_DECOY_SPARSE_LENGTH_MAX, SettingValue::Unsigned(values::TYPHOON_DECOY_SPARSE_LENGTH_MAX));
    map.insert(keys::TYPHOON_DECOY_SMOOTH_BASE_RATE, SettingValue::Float(values::TYPHOON_DECOY_SMOOTH_BASE_RATE));
    map.insert(keys::TYPHOON_DECOY_SMOOTH_QUIETNESS_FACTOR, SettingValue::Float(values::TYPHOON_DECOY_SMOOTH_QUIETNESS_FACTOR));
    map.insert(keys::TYPHOON_DECOY_SMOOTH_RATE_FACTOR, SettingValue::Float(values::TYPHOON_DECOY_SMOOTH_RATE_FACTOR));
    map.insert(keys::TYPHOON_DECOY_SMOOTH_JITTER, SettingValue::Float(values::TYPHOON_DECOY_SMOOTH_JITTER));
    map.insert(keys::TYPHOON_DECOY_SMOOTH_DELAY_FACTOR, SettingValue::Float(values::TYPHOON_DECOY_SMOOTH_DELAY_FACTOR));
    map.insert(keys::TYPHOON_DECOY_SMOOTH_DELAY_MIN, SettingValue::Unsigned(values::TYPHOON_DECOY_SMOOTH_DELAY_MIN));
    map.insert(keys::TYPHOON_DECOY_SMOOTH_DELAY_MAX, SettingValue::Unsigned(values::TYPHOON_DECOY_SMOOTH_DELAY_MAX));
    map.insert(keys::TYPHOON_DECOY_SMOOTH_DELAY_DEFAULT, SettingValue::Unsigned(values::TYPHOON_DECOY_SMOOTH_DELAY_DEFAULT));
    map.insert(keys::TYPHOON_DECOY_SMOOTH_LENGTH_MIN, SettingValue::Unsigned(values::TYPHOON_DECOY_SMOOTH_LENGTH_MIN));
    map.insert(keys::TYPHOON_DECOY_SMOOTH_LENGTH_MAX, SettingValue::Unsigned(values::TYPHOON_DECOY_SMOOTH_LENGTH_MAX));
    map.insert(keys::TYPHOON_DECOY_MAINTENANCE_LENGTH_MIN, SettingValue::Unsigned(values::TYPHOON_DECOY_MAINTENANCE_LENGTH_MIN));
    map.insert(keys::TYPHOON_DECOY_MAINTENANCE_LENGTH_MAX, SettingValue::Unsigned(values::TYPHOON_DECOY_MAINTENANCE_LENGTH_MAX));
    map.insert(keys::TYPHOON_DECOY_MAINTENANCE_DELAY_MIN, SettingValue::Unsigned(values::TYPHOON_DECOY_MAINTENANCE_DELAY_MIN));
    map.insert(keys::TYPHOON_DECOY_MAINTENANCE_DELAY_MAX, SettingValue::Unsigned(values::TYPHOON_DECOY_MAINTENANCE_DELAY_MAX));
    map.insert(keys::TYPHOON_DECOY_MAINTENANCE_MODE_NONE_PROBABILITY, SettingValue::Float(values::TYPHOON_DECOY_MAINTENANCE_MODE_NONE_PROBABILITY));
    map.insert(keys::TYPHOON_DECOY_REPLICATION_PROBABILITY_MIN, SettingValue::Float(values::TYPHOON_DECOY_REPLICATION_PROBABILITY_MIN));
    map.insert(keys::TYPHOON_DECOY_REPLICATION_PROBABILITY_MAX, SettingValue::Float(values::TYPHOON_DECOY_REPLICATION_PROBABILITY_MAX));
    map.insert(keys::TYPHOON_DECOY_REPLICATION_PROBABILITY_REDUCE, SettingValue::Float(values::TYPHOON_DECOY_REPLICATION_PROBABILITY_REDUCE));
    map.insert(keys::TYPHOON_DECOY_REPLICATION_DELAY_MIN, SettingValue::Unsigned(values::TYPHOON_DECOY_REPLICATION_DELAY_MIN));
    map.insert(keys::TYPHOON_DECOY_REPLICATION_DELAY_MAX, SettingValue::Unsigned(values::TYPHOON_DECOY_REPLICATION_DELAY_MAX));
    map.insert(keys::TYPHOON_DECOY_REPLICATION_MODE_NONE_PROBABILITY, SettingValue::Float(values::TYPHOON_DECOY_REPLICATION_MODE_NONE_PROBABILITY));
    map.insert(keys::TYPHOON_DECOY_SUBHEADER_LENGTH_MIN, SettingValue::Unsigned(values::TYPHOON_DECOY_SUBHEADER_LENGTH_MIN));
    map.insert(keys::TYPHOON_DECOY_SUBHEADER_LENGTH_MAX, SettingValue::Unsigned(values::TYPHOON_DECOY_SUBHEADER_LENGTH_MAX));
    map
}

#[inline]
fn environment_values_map(mut default_values_map: DefaultMap) -> DefaultMap {
    for (key, value) in default_values_map.iter_mut() {
        *value = match value {
            SettingValue::Signed(_) => match var(*key) {
                Ok(res) => match res.parse::<i64>() {
                    Ok(res) => SettingValue::Signed(res),
                    Err(_) => {
                        warn!("Environment variable '{key}' set to value '{res}' that can not be parsed as 64bit signed integer, skipping...");
                        *value
                    },
                },
                Err(_) => *value,
            },
            SettingValue::Unsigned(_) => match var(*key) {
                Ok(res) => match res.parse::<u64>() {
                    Ok(res) => SettingValue::Unsigned(res),
                    Err(_) => {
                        warn!("Environment variable '{key}' set to value '{res}' that can not be parsed as 64bit unsigned integer, skipping...");
                        *value
                    },
                },
                Err(_) => *value,
            },
            SettingValue::Float(_) => match var(*key) {
                Ok(res) => match res.parse::<f64>() {
                    Ok(res) => SettingValue::Float(res),
                    Err(_) => {
                        warn!("Environment variable '{key}' set to value '{res}' that can not be parsed as 64bit floating point number, skipping...");
                        *value
                    },
                },
                Err(_) => *value,
            },
        };
    }
    default_values_map
}

pub struct SettingsBuilder {
    map: DefaultMap
}

impl SettingsBuilder {
    #[inline]
    pub fn update(mut self, key: &'static str, value: &SettingValue) -> Self {
        self.map.insert(key, *value);
        self
    }

    #[inline]
    pub fn extend(mut self, update: DefaultMap) -> Self {
        self.map.extend(update);
        self
    }

    fn finalize(mut self) -> Settings {
        self.map.insert(keys::TAILOR_LENGTH, SettingValue::Unsigned(values::TAILOR_LENGTH) + self.map[keys::TYPHOON_ID_LENGTH]);
        self.map.insert(keys::FG_OFFSET, SettingValue::Unsigned(values::FG_OFFSET));
        self.map.insert(keys::CD_OFFSET, SettingValue::Unsigned(values::CD_OFFSET));
        self.map.insert(keys::TM_OFFSET, SettingValue::Unsigned(values::TM_OFFSET));
        self.map.insert(keys::PN_OFFSET, SettingValue::Unsigned(values::PN_OFFSET));
        self.map.insert(keys::PL_OFFSET, SettingValue::Unsigned(values::PL_OFFSET));
        self.map.insert(keys::ID_OFFSET, SettingValue::Unsigned(values::ID_OFFSET));
        Settings { 
            map: self.map,
        }
    }
}

impl Default for SettingsBuilder {
    #[inline]
    fn default() -> Self {
        Self { 
            map: environment_values_map(default_values_map()),
        }
    }
}

pub struct Settings {
    pub(crate) map: DefaultMap
}

impl Index<&str> for Settings {
    type Output = SettingValue;

    fn index(&self, index: &str) -> &Self::Output {
        &self.map[index]
    }
}

impl Default for Settings {
    #[inline]
    fn default() -> Self {
        SettingsBuilder::default().finalize()
    }
}
