//! Static setting keys and protocol constants.

/// `TYPHOON_*` setting keys, each overridable at runtime via an environment variable of the same name.
pub mod keys {
    use super::super::override_map::Key;

    // RTT settings
    /// EWMA smoothing factor for the RTT mean.
    pub const RTT_ALPHA: Key<f64> = Key::new("TYPHOON_RTT_ALPHA", 0.125);
    /// EWMA smoothing factor for the RTT variance.
    pub const RTT_BETA: Key<f64> = Key::new("TYPHOON_RTT_BETA", 0.25);
    /// Fallback RTT (milliseconds) used before any health-check round trip has been measured.
    pub const RTT_DEFAULT: Key<u64> = Key::new("TYPHOON_RTT_DEFAULT", 5000);
    /// Lower clamp (milliseconds) for both the smoothed RTT and individual RTT samples.
    pub const RTT_MIN: Key<u64> = Key::new("TYPHOON_RTT_MIN", 200);
    /// Upper clamp (milliseconds) for both the smoothed RTT and individual RTT samples.
    pub const RTT_MAX: Key<u64> = Key::new("TYPHOON_RTT_MAX", 8000);

    // Timeout settings
    /// Fallback timeout (milliseconds) used before RTT is available, i.e. for the handshake and first health check.
    pub const TIMEOUT_DEFAULT: Key<u64> = Key::new("TYPHOON_TIMEOUT_DEFAULT", 30000);
    /// Lower clamp (milliseconds) for the computed timeout.
    pub const TIMEOUT_MIN: Key<u64> = Key::new("TYPHOON_TIMEOUT_MIN", 4000);
    /// Upper clamp (milliseconds) for the computed timeout.
    pub const TIMEOUT_MAX: Key<u64> = Key::new("TYPHOON_TIMEOUT_MAX", 32000);
    /// Multiplier applied to `smooth_RTT + RTT_variance` to derive the timeout once RTT is available.
    pub const TIMEOUT_RTT_FACTOR: Key<f64> = Key::new("TYPHOON_TIMEOUT_RTT_FACTOR", 5.0);

    // Health check settings
    /// Lower clamp (milliseconds) for the random "next in" delay between health check packets.
    pub const HEALTH_CHECK_NEXT_IN_MIN: Key<u64> = Key::new("TYPHOON_HEALTH_CHECK_NEXT_IN_MIN", 64_000);
    /// Upper clamp (milliseconds) for the random "next in" delay between health check packets.
    pub const HEALTH_CHECK_NEXT_IN_MAX: Key<u64> = Key::new("TYPHOON_HEALTH_CHECK_NEXT_IN_MAX", 256_000);
    /// Multiplier applied to the health-check "next in" delay to derive the handshake response delay.
    pub const HANDSHAKE_NEXT_IN_FACTOR: Key<f64> = Key::new("TYPHOON_HANDSHAKE_NEXT_IN_FACTOR", 0.02);
    /// Number of consecutive missed health-check/handshake round trips tolerated before the connection decays.
    pub const MAX_RETRIES: Key<u64> = Key::new("TYPHOON_MAX_RETRIES", 12);

    // Send-bytes chunking jitter
    /// Two-sided jitter fraction applied when sampling the per-chunk size for `send_bytes`.
    pub const SEND_BYTES_JITTER: Key<f64> = Key::new("TYPHOON_SEND_BYTES_JITTER", 0.2);
    /// Target chunk size (bytes) for `send_bytes` fragmentation; `0` means "saturate the MTU" (use `max_data_payload`).
    pub const SEND_BYTES_CHUNK: Key<u64> = Key::new("TYPHOON_SEND_BYTES_CHUNK", 0);

    // Fake body/header settings
    /// Lower clamp (bytes) for `random`-mode fake body length.
    pub const FAKE_BODY_LENGTH_MIN: Key<u64> = Key::new("TYPHOON_FAKE_BODY_LENGTH_MIN", 32);
    /// Upper clamp (bytes) for `random`-mode fake body length.
    pub const FAKE_BODY_LENGTH_MAX: Key<u64> = Key::new("TYPHOON_FAKE_BODY_LENGTH_MAX", 512);
    /// Lower clamp (bytes) when sampling the per-flow constant used by `constant`-mode fake bodies.
    pub const FAKE_BODY_CONSTANT_LENGTH_MIN: Key<u64> = Key::new("TYPHOON_FAKE_BODY_CONSTANT_LENGTH_MIN", 256);
    /// Upper clamp (bytes) when sampling the per-flow constant used by `constant`-mode fake bodies.
    pub const FAKE_BODY_CONSTANT_LENGTH_MAX: Key<u64> = Key::new("TYPHOON_FAKE_BODY_CONSTANT_LENGTH_MAX", 1400);
    /// Lower clamp (bytes) for total fake header length.
    pub const FAKE_HEADER_LENGTH_MIN: Key<u64> = Key::new("TYPHOON_FAKE_HEADER_LENGTH_MIN", 4);
    /// Upper clamp (bytes) for total fake header length.
    pub const FAKE_HEADER_LENGTH_MAX: Key<u64> = Key::new("TYPHOON_FAKE_HEADER_LENGTH_MAX", 32);
    /// Probability that a flow is given a fake header at all.
    pub const FAKE_HEADER_PROBABILITY: Key<f64> = Key::new("TYPHOON_FAKE_HEADER_PROBABILITY", 0.60);

    // Per-flow probability that a generated decoy packet bypasses the trailer step
    /// Lower clamp when sampling a flow's fallthrough probability (chance a decoy packet skips the trailer step entirely).
    pub const DECOY_FALLTHROUGH_PACKETS_MIN: Key<f64> = Key::new("TYPHOON_DECOY_FALLTHROUGH_PACKETS_MIN", 0.0);
    /// Upper clamp when sampling a flow's fallthrough probability.
    pub const DECOY_FALLTHROUGH_PACKETS_MAX: Key<f64> = Key::new("TYPHOON_DECOY_FALLTHROUGH_PACKETS_MAX", 0.25);

    // Fake body mode selection weights.
    /// Selection weight for `FakeBodyMode::Empty`.
    pub const FAKE_BODY_WEIGHT_EMPTY: Key<u64> = Key::new("TYPHOON_FAKE_BODY_WEIGHT_EMPTY", 1);
    /// Selection weight for `FakeBodyMode::Random`.
    pub const FAKE_BODY_WEIGHT_RANDOM: Key<u64> = Key::new("TYPHOON_FAKE_BODY_WEIGHT_RANDOM", 5);
    /// Selection weight for `FakeBodyMode::Constant`.
    pub const FAKE_BODY_WEIGHT_CONSTANT: Key<u64> = Key::new("TYPHOON_FAKE_BODY_WEIGHT_CONSTANT", 1);
    /// Selection weight for the `service` fake-body variant (random length, applied only to maintenance-substream decoys).
    pub const FAKE_BODY_WEIGHT_SERVICE: Key<u64> = Key::new("TYPHOON_FAKE_BODY_WEIGHT_SERVICE", 1);

    // Fake header field type selection weights
    /// Selection weight for `random`-type fake header fields.
    pub const FAKE_HEADER_FIELD_WEIGHT_RANDOM: Key<u64> = Key::new("TYPHOON_FAKE_HEADER_FIELD_WEIGHT_RANDOM", 1);
    /// Selection weight for `constant`-type fake header fields.
    pub const FAKE_HEADER_FIELD_WEIGHT_CONSTANT: Key<u64> = Key::new("TYPHOON_FAKE_HEADER_FIELD_WEIGHT_CONSTANT", 1);
    /// Selection weight for `volatile`-type fake header fields.
    pub const FAKE_HEADER_FIELD_WEIGHT_VOLATILE: Key<u64> = Key::new("TYPHOON_FAKE_HEADER_FIELD_WEIGHT_VOLATILE", 1);
    /// Selection weight for `switching`-type fake header fields.
    pub const FAKE_HEADER_FIELD_WEIGHT_SWITCHING: Key<u64> = Key::new("TYPHOON_FAKE_HEADER_FIELD_WEIGHT_SWITCHING", 1);
    /// Selection weight for `incremental`-type fake header fields.
    pub const FAKE_HEADER_FIELD_WEIGHT_INCREMENTAL: Key<u64> = Key::new("TYPHOON_FAKE_HEADER_FIELD_WEIGHT_INCREMENTAL", 1);

    // Volatile field-type change probability range (per-field draw at flow init).
    /// Lower clamp when sampling a `volatile` field's per-packet change probability.
    pub const FAKE_HEADER_VOLATILE_CHANGE_PROB_MIN: Key<f64> = Key::new("TYPHOON_FAKE_HEADER_VOLATILE_CHANGE_PROB_MIN", 0.01);
    /// Upper clamp when sampling a `volatile` field's per-packet change probability.
    pub const FAKE_HEADER_VOLATILE_CHANGE_PROB_MAX: Key<f64> = Key::new("TYPHOON_FAKE_HEADER_VOLATILE_CHANGE_PROB_MAX", 0.20);
    // Switching field-type timeout range in milliseconds (per-field draw at flow init).
    /// Lower clamp (milliseconds) when sampling a `switching` field's switch timeout.
    pub const FAKE_HEADER_SWITCHING_TIMEOUT_MIN_MS: Key<u64> = Key::new("TYPHOON_FAKE_HEADER_SWITCHING_TIMEOUT_MIN_MS", 1000);
    /// Upper clamp (milliseconds) when sampling a `switching` field's switch timeout.
    pub const FAKE_HEADER_SWITCHING_TIMEOUT_MAX_MS: Key<u64> = Key::new("TYPHOON_FAKE_HEADER_SWITCHING_TIMEOUT_MAX_MS", 30000);

    // Decoy general settings
    /// Initial value (ms between packets) for a flow's long-term reference transmission rate, before any traffic has been observed.
    pub const DECOY_REFERENCE_PACKET_RATE_DEFAULT: Key<f64> = Key::new("TYPHOON_DECOY_REFERENCE_PACKET_RATE_DEFAULT", 200.0);
    /// Initial value (ms between packets) for a flow's current transmission rate, before any traffic has been observed.
    pub const DECOY_CURRENT_PACKET_RATE_DEFAULT: Key<f64> = Key::new("TYPHOON_DECOY_CURRENT_PACKET_RATE_DEFAULT", 1.0);
    /// Initial value (bytes) for a flow's current byte-rate estimate, before any traffic has been observed.
    pub const DECOY_CURRENT_BYTE_RATE_DEFAULT: Key<f64> = Key::new("TYPHOON_DECOY_CURRENT_BYTE_RATE_DEFAULT", 5000.0);
    /// Refill rate (bytes/second) of the per-flow decoy byte-rate budget.
    pub const DECOY_BYTE_RATE_CAP: Key<f64> = Key::new("TYPHOON_DECOY_BYTE_RATE_CAP", 1_000_000.0);
    /// Multiplier on `DECOY_BYTE_RATE_CAP` giving the maximum burst size of the decoy byte-rate budget.
    pub const DECOY_BYTE_RATE_FACTOR: Key<f64> = Key::new("TYPHOON_DECOY_BYTE_RATE_FACTOR", 3.0);
    /// EWMA smoothing factor for a flow's current packet/byte rate estimate.
    pub const DECOY_CURRENT_ALPHA: Key<f64> = Key::new("TYPHOON_DECOY_CURRENT_ALPHA", 0.05);
    /// EWMA smoothing factor for a flow's long-term reference rate estimate.
    pub const DECOY_REFERENCE_ALPHA: Key<f64> = Key::new("TYPHOON_DECOY_REFERENCE_ALPHA", 0.001);
    /// Global upper clamp (bytes) for any decoy packet length, across all communication modes.
    pub const DECOY_LENGTH_MAX: Key<u64> = Key::new("TYPHOON_DECOY_LENGTH_MAX", 1400);
    /// Global lower clamp (bytes) for any decoy packet length, across all communication modes.
    pub const DECOY_LENGTH_MIN: Key<u64> = Key::new("TYPHOON_DECOY_LENGTH_MIN", 64);
    /// Two-sided jitter fraction applied to every communication mode's base decoy rate.
    pub const DECOY_BASE_RATE_RND: Key<f64> = Key::new("TYPHOON_DECOY_BASE_RATE_RND", 0.25);

    // Decoy heavy settings
    /// Base decoy emission rate (packets/second) for heavy mode.
    pub const DECOY_HEAVY_BASE_RATE: Key<f64> = Key::new("TYPHOON_DECOY_HEAVY_BASE_RATE", 0.1);
    /// Exponent applied to the quietness index in heavy mode's rate formula.
    pub const DECOY_HEAVY_QUIETNESS_FACTOR: Key<f64> = Key::new("TYPHOON_DECOY_HEAVY_QUIETNESS_FACTOR", 3.0);
    /// Lower clamp (milliseconds) for heavy mode's decoy delay; the hard ceiling on heavy mode's decoy rate.
    pub const DECOY_HEAVY_DELAY_MIN: Key<u64> = Key::new("TYPHOON_DECOY_HEAVY_DELAY_MIN", 5000);
    /// Upper clamp (milliseconds) for heavy mode's decoy delay.
    pub const DECOY_HEAVY_DELAY_MAX: Key<u64> = Key::new("TYPHOON_DECOY_HEAVY_DELAY_MAX", 300_000);
    /// Fallback delay (milliseconds) used when heavy mode's computed rate is non-positive.
    pub const DECOY_HEAVY_DELAY_DEFAULT: Key<u64> = Key::new("TYPHOON_DECOY_HEAVY_DELAY_DEFAULT", 64000);
    /// Base fraction of `packet_length_cap` used as the starting point for heavy mode's decoy length.
    pub const DECOY_HEAVY_BASE_LENGTH: Key<f64> = Key::new("TYPHOON_DECOY_HEAVY_BASE_LENGTH", 0.7);
    /// Additional fraction of `packet_length_cap` added to heavy mode's base length as quietness increases.
    pub const DECOY_HEAVY_QUIETNESS_LENGTH: Key<f64> = Key::new("TYPHOON_DECOY_HEAVY_QUIETNESS_LENGTH", 0.3);
    /// Lower bound, as a fraction of the computed base length, when sampling heavy mode's decoy length.
    pub const DECOY_HEAVY_DECOY_LENGTH_FACTOR: Key<f64> = Key::new("TYPHOON_DECOY_HEAVY_DECOY_LENGTH_FACTOR", 0.8);
    /// Lower clamp (bytes) for heavy mode's decoy length.
    pub const DECOY_HEAVY_LENGTH_MIN: Key<u64> = Key::new("TYPHOON_DECOY_HEAVY_LENGTH_MIN", 560);

    // Decoy noisy settings
    /// Base decoy emission rate (packets/second) for noisy mode.
    pub const DECOY_NOISY_BASE_RATE: Key<f64> = Key::new("TYPHOON_DECOY_NOISY_BASE_RATE", 5.0);
    /// Lower clamp (milliseconds) for noisy mode's decoy delay; the hard ceiling on noisy mode's decoy rate.
    pub const DECOY_NOISY_DELAY_MIN: Key<u64> = Key::new("TYPHOON_DECOY_NOISY_DELAY_MIN", 30);
    /// Upper clamp (milliseconds) for noisy mode's decoy delay.
    pub const DECOY_NOISY_DELAY_MAX: Key<u64> = Key::new("TYPHOON_DECOY_NOISY_DELAY_MAX", 2000);
    /// Fallback delay (milliseconds) used when noisy mode's computed rate is non-positive.
    pub const DECOY_NOISY_DELAY_DEFAULT: Key<u64> = Key::new("TYPHOON_DECOY_NOISY_DELAY_DEFAULT", 500);
    /// Lower clamp (bytes) for noisy mode's decoy length.
    pub const DECOY_NOISY_DECOY_LENGTH_MIN: Key<u64> = Key::new("TYPHOON_DECOY_NOISY_DECOY_LENGTH_MIN", 64);
    /// Upper clamp (bytes) for noisy mode's decoy length; deliberately well below `DECOY_LENGTH_MAX` to keep noisy decoys small.
    pub const DECOY_NOISY_LENGTH_MAX: Key<u64> = Key::new("TYPHOON_DECOY_NOISY_LENGTH_MAX", 800);
    /// Standard-deviation fraction (of the computed mean) used when sampling noisy mode's decoy length.
    pub const DECOY_NOISY_DECOY_LENGTH_JITTER: Key<f64> = Key::new("TYPHOON_DECOY_NOISY_DECOY_LENGTH_JITTER", 0.3);

    // Decoy sparse settings
    /// Base decoy emission rate (packets/second) for sparse mode.
    pub const DECOY_SPARSE_BASE_RATE: Key<f64> = Key::new("TYPHOON_DECOY_SPARSE_BASE_RATE", 20.0);
    /// Exponent factor scaling how strongly real traffic suppresses sparse mode's rate.
    pub const DECOY_SPARSE_RATE_FACTOR: Key<f64> = Key::new("TYPHOON_DECOY_SPARSE_RATE_FACTOR", 3.0);
    /// Two-sided jitter fraction applied to sparse mode's decoy delay.
    pub const DECOY_SPARSE_JITTER: Key<f64> = Key::new("TYPHOON_DECOY_SPARSE_JITTER", 0.15);
    /// Factor scaling how much sparse mode's delay grows with the current-to-reference packet-rate ratio.
    pub const DECOY_SPARSE_DELAY_FACTOR: Key<f64> = Key::new("TYPHOON_DECOY_SPARSE_DELAY_FACTOR", 3.0);
    /// Lower clamp (milliseconds) for sparse mode's decoy delay; the hard ceiling on sparse mode's decoy rate.
    pub const DECOY_SPARSE_DELAY_MIN: Key<u64> = Key::new("TYPHOON_DECOY_SPARSE_DELAY_MIN", 30);
    /// Upper clamp (milliseconds) for sparse mode's decoy delay.
    pub const DECOY_SPARSE_DELAY_MAX: Key<u64> = Key::new("TYPHOON_DECOY_SPARSE_DELAY_MAX", 2000);
    /// Fallback delay (milliseconds) used when sparse mode's computed rate is non-positive.
    pub const DECOY_SPARSE_DELAY_DEFAULT: Key<u64> = Key::new("TYPHOON_DECOY_SPARSE_DELAY_DEFAULT", 100);
    /// Scale factor for sparse mode's mean decoy length.
    pub const DECOY_SPARSE_LENGTH_FACTOR: Key<f64> = Key::new("TYPHOON_DECOY_SPARSE_LENGTH_FACTOR", 700.0);
    /// Standard deviation (bytes) for sparse mode's Gaussian-sampled decoy length.
    pub const DECOY_SPARSE_LENGTH_SIGMA: Key<f64> = Key::new("TYPHOON_DECOY_SPARSE_LENGTH_SIGMA", 250.0);
    /// Lower clamp (bytes) for sparse mode's decoy length.
    pub const DECOY_SPARSE_LENGTH_MIN: Key<u64> = Key::new("TYPHOON_DECOY_SPARSE_LENGTH_MIN", 64);
    /// Upper clamp (bytes) for sparse mode's decoy length.
    pub const DECOY_SPARSE_LENGTH_MAX: Key<u64> = Key::new("TYPHOON_DECOY_SPARSE_LENGTH_MAX", 1400);

    // Decoy smooth settings
    /// Base decoy emission rate (packets/second) for smooth mode.
    pub const DECOY_SMOOTH_BASE_RATE: Key<f64> = Key::new("TYPHOON_DECOY_SMOOTH_BASE_RATE", 0.3);
    /// Exponent applied to the quietness index in smooth mode's rate formula.
    pub const DECOY_SMOOTH_QUIETNESS_FACTOR: Key<f64> = Key::new("TYPHOON_DECOY_SMOOTH_QUIETNESS_FACTOR", 2.0);
    /// Exponent factor scaling how strongly real traffic suppresses smooth mode's rate.
    pub const DECOY_SMOOTH_RATE_FACTOR: Key<f64> = Key::new("TYPHOON_DECOY_SMOOTH_RATE_FACTOR", 3.0);
    /// Two-sided jitter fraction applied to smooth mode's decoy delay.
    pub const DECOY_SMOOTH_JITTER: Key<f64> = Key::new("TYPHOON_DECOY_SMOOTH_JITTER", 0.2);
    /// Factor scaling how much smooth mode's delay grows with the current-to-reference packet-rate ratio.
    pub const DECOY_SMOOTH_DELAY_FACTOR: Key<f64> = Key::new("TYPHOON_DECOY_SMOOTH_DELAY_FACTOR", 2.0);
    /// Lower clamp (milliseconds) for smooth mode's decoy delay; the hard ceiling on smooth mode's decoy rate.
    pub const DECOY_SMOOTH_DELAY_MIN: Key<u64> = Key::new("TYPHOON_DECOY_SMOOTH_DELAY_MIN", 300);
    /// Upper clamp (milliseconds) for smooth mode's decoy delay.
    pub const DECOY_SMOOTH_DELAY_MAX: Key<u64> = Key::new("TYPHOON_DECOY_SMOOTH_DELAY_MAX", 300_000);
    /// Fallback delay (milliseconds) used when smooth mode's computed rate is non-positive.
    pub const DECOY_SMOOTH_DELAY_DEFAULT: Key<u64> = Key::new("TYPHOON_DECOY_SMOOTH_DELAY_DEFAULT", 5000);
    /// Lower clamp (bytes) for smooth mode's decoy length.
    pub const DECOY_SMOOTH_LENGTH_MIN: Key<u64> = Key::new("TYPHOON_DECOY_SMOOTH_LENGTH_MIN", 48);
    /// Upper clamp (bytes) for smooth mode's decoy length.
    pub const DECOY_SMOOTH_LENGTH_MAX: Key<u64> = Key::new("TYPHOON_DECOY_SMOOTH_LENGTH_MAX", 1100);

    // Decoy maintenance settings
    /// Lower clamp (bytes) for maintenance-substream decoy packet length.
    pub const DECOY_MAINTENANCE_LENGTH_MIN: Key<u64> = Key::new("TYPHOON_DECOY_MAINTENANCE_LENGTH_MIN", 250);
    /// Upper clamp (bytes) for maintenance-substream decoy packet length.
    pub const DECOY_MAINTENANCE_LENGTH_MAX: Key<u64> = Key::new("TYPHOON_DECOY_MAINTENANCE_LENGTH_MAX", 250);
    /// Lower clamp (milliseconds) for the maintenance substream's emission delay.
    pub const DECOY_MAINTENANCE_DELAY_MIN: Key<u64> = Key::new("TYPHOON_DECOY_MAINTENANCE_DELAY_MIN", 3000);
    /// Upper clamp (milliseconds) for the maintenance substream's emission delay.
    pub const DECOY_MAINTENANCE_DELAY_MAX: Key<u64> = Key::new("TYPHOON_DECOY_MAINTENANCE_DELAY_MAX", 720_000);

    // Decoy maintenance mode selection weights
    /// Selection weight for disabling the maintenance substream (`MaintenanceMode::None`).
    pub const DECOY_MAINTENANCE_WEIGHT_NONE: Key<u64> = Key::new("TYPHOON_DECOY_MAINTENANCE_WEIGHT_NONE", 3);
    /// Selection weight for `MaintenanceMode::Random` (delay and length both re-sampled every cycle).
    pub const DECOY_MAINTENANCE_WEIGHT_RANDOM: Key<u64> = Key::new("TYPHOON_DECOY_MAINTENANCE_WEIGHT_RANDOM", 1);
    /// Selection weight for `MaintenanceMode::Timed` (fixed delay, random length).
    pub const DECOY_MAINTENANCE_WEIGHT_TIMED: Key<u64> = Key::new("TYPHOON_DECOY_MAINTENANCE_WEIGHT_TIMED", 1);
    /// Selection weight for `MaintenanceMode::Sized` (random delay, fixed length).
    pub const DECOY_MAINTENANCE_WEIGHT_SIZED: Key<u64> = Key::new("TYPHOON_DECOY_MAINTENANCE_WEIGHT_SIZED", 1);
    /// Selection weight for `MaintenanceMode::Both` (fixed delay and fixed length).
    pub const DECOY_MAINTENANCE_WEIGHT_BOTH: Key<u64> = Key::new("TYPHOON_DECOY_MAINTENANCE_WEIGHT_BOTH", 1);

    // Decoy replication settings
    /// Lower clamp when sampling a provider's initial replication continuation probability.
    pub const DECOY_REPLICATION_PROBABILITY_MIN: Key<f64> = Key::new("TYPHOON_DECOY_REPLICATION_PROBABILITY_MIN", 0.01);
    /// Upper clamp when sampling a provider's initial replication continuation probability.
    pub const DECOY_REPLICATION_PROBABILITY_MAX: Key<f64> = Key::new("TYPHOON_DECOY_REPLICATION_PROBABILITY_MAX", 0.1);
    /// Divisor applied to the replication continuation probability after every replica sent, so each chain dies out geometrically.
    pub const DECOY_REPLICATION_PROBABILITY_REDUCE: Key<f64> = Key::new("TYPHOON_DECOY_REPLICATION_PROBABILITY_REDUCE", 3.0);
    /// Lower clamp (milliseconds) for the delay between replicated packets within a replication chain.
    pub const DECOY_REPLICATION_DELAY_MIN: Key<u64> = Key::new("TYPHOON_DECOY_REPLICATION_DELAY_MIN", 2500);
    /// Upper clamp (milliseconds) for the delay between replicated packets within a replication chain.
    pub const DECOY_REPLICATION_DELAY_MAX: Key<u64> = Key::new("TYPHOON_DECOY_REPLICATION_DELAY_MAX", 10000);

    // Decoy replication mode selection weights
    /// Selection weight for disabling replication (`ReplicationMode::None`).
    pub const DECOY_REPLICATION_WEIGHT_NONE: Key<u64> = Key::new("TYPHOON_DECOY_REPLICATION_WEIGHT_NONE", 3);
    /// Selection weight for replicating only maintenance-substream packets (`ReplicationMode::Maintenance`).
    pub const DECOY_REPLICATION_WEIGHT_MAINTENANCE: Key<u64> = Key::new("TYPHOON_DECOY_REPLICATION_WEIGHT_MAINTENANCE", 1);
    /// Selection weight for replicating every eligible decoy packet (`ReplicationMode::All`).
    pub const DECOY_REPLICATION_WEIGHT_ALL: Key<u64> = Key::new("TYPHOON_DECOY_REPLICATION_WEIGHT_ALL", 1);

    // Decoy subheader settings
    /// Lower clamp (bytes) for the generated fake subheader's total length.
    pub const DECOY_SUBHEADER_LENGTH_MIN: Key<u64> = Key::new("TYPHOON_DECOY_SUBHEADER_LENGTH_MIN", 4);
    /// Upper clamp (bytes) for the generated fake subheader's total length.
    pub const DECOY_SUBHEADER_LENGTH_MAX: Key<u64> = Key::new("TYPHOON_DECOY_SUBHEADER_LENGTH_MAX", 16);

    // Decoy subheader mode selection weights
    /// Selection weight for disabling the decoy subheader (`SubheaderMode::None`).
    pub const DECOY_SUBHEADER_WEIGHT_NONE: Key<u64> = Key::new("TYPHOON_DECOY_SUBHEADER_WEIGHT_NONE", 1);
    /// Selection weight for applying the subheader only to maintenance-substream packets (`SubheaderMode::Maintenance`).
    pub const DECOY_SUBHEADER_WEIGHT_MAINTENANCE: Key<u64> = Key::new("TYPHOON_DECOY_SUBHEADER_WEIGHT_MAINTENANCE", 1);
    /// Selection weight for applying the subheader to every decoy packet (`SubheaderMode::All`).
    pub const DECOY_SUBHEADER_WEIGHT_ALL: Key<u64> = Key::new("TYPHOON_DECOY_SUBHEADER_WEIGHT_ALL", 1);

    // Decoy provider (communication mode) selection weights
    /// Selection weight for `SimpleDecoyProvider` in `random_decoy_factory`.
    pub const DECOY_PROVIDER_WEIGHT_SIMPLE: Key<u64> = Key::new("TYPHOON_DECOY_PROVIDER_WEIGHT_SIMPLE", 2);
    /// Selection weight for `SparseDecoyProvider` in `random_decoy_factory`.
    pub const DECOY_PROVIDER_WEIGHT_SPARSE: Key<u64> = Key::new("TYPHOON_DECOY_PROVIDER_WEIGHT_SPARSE", 2);
    /// Selection weight for `NoisyDecoyProvider` in `random_decoy_factory`.
    pub const DECOY_PROVIDER_WEIGHT_NOISY: Key<u64> = Key::new("TYPHOON_DECOY_PROVIDER_WEIGHT_NOISY", 1);
    /// Selection weight for `SmoothDecoyProvider` in `random_decoy_factory`.
    pub const DECOY_PROVIDER_WEIGHT_SMOOTH: Key<u64> = Key::new("TYPHOON_DECOY_PROVIDER_WEIGHT_SMOOTH", 3);
    /// Selection weight for `HeavyDecoyProvider` in `random_decoy_factory`.
    pub const DECOY_PROVIDER_WEIGHT_HEAVY: Key<u64> = Key::new("TYPHOON_DECOY_PROVIDER_WEIGHT_HEAVY", 1);

    // Channel capacity settings
    /// Capacity of the per-flow drain channel (packets buffered between drain task and route task).
    /// Excess packets are dropped by the drain task to keep the socket buffer empty.
    pub const DRAIN_CHANNEL_CAPACITY: Key<u64> = Key::new("TYPHOON_DRAIN_CHANNEL_CAPACITY", 8192);

    // Debug settings
    /// Number of probes sent during the throughput phase.
    pub const DEBUG_PROBE_COUNT: Key<u64> = Key::new("TYPHOON_DEBUG_PROBE_COUNT", 10);
    /// Payload size in bytes of each throughput probe.
    pub const DEBUG_PROBE_SIZE: Key<u64> = Key::new("TYPHOON_DEBUG_PROBE_SIZE", 65000);
    /// Per-probe receive timeout in milliseconds.
    pub const DEBUG_PROBE_TIMEOUT: Key<u64> = Key::new("TYPHOON_DEBUG_PROBE_TIMEOUT", 5000);
}

/// Fixed protocol constants: buffer sizes, default lengths, and trailer field byte offsets.
pub mod consts {
    /// Number of buffers pre-allocated when a `BytePool` is created.
    pub const DEFAULT_POOL_INITIAL_SIZE: usize = 128;
    /// Default maximum main-data capacity (bytes) of a single pooled buffer.
    pub const DEFAULT_POOL_CAPACITY: usize = 2 << 15;
    /// Default network MTU (bytes) assumed when sizing buffers.
    pub const DEFAULT_TYPHOON_MTU_LENGTH: usize = 1500;
    /// Default length (bytes) of the trailer's `ID` field.
    pub const DEFAULT_TYPHOON_ID_LENGTH: usize = 16;
    /// Length (bytes) of the fixed-size part of the trailer, excluding the `ID` field.
    pub const TRAILER_LENGTH: usize = 16;
    /// Byte offset of the `FG` (flags) field within the trailer.
    pub const FG_OFFSET: usize = 0;
    /// Byte offset of the `CD` (code) field within the trailer.
    pub const CD_OFFSET: usize = 1;
    /// Byte offset of the `TM` (time) field within the trailer.
    pub const TM_OFFSET: usize = 2;
    /// Byte offset of the `PN` (packet number) field within the trailer.
    pub const PN_OFFSET: usize = 6;
    /// Byte offset of the `PL` (payload length) field within the trailer.
    pub const PL_OFFSET: usize = 14;
    /// Byte offset of the `ID` (identity) field within the trailer.
    pub const ID_OFFSET: usize = 16;
}
