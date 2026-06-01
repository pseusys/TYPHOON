"""
Single source of truth for traffic profiles used across all evaluation parts.

A profile fixes the per-flow shape of generated traffic (packet sizes, IATs,
direction asymmetry, session duration, plus TYPHOON-specific FlowConfig
overrides).  Profiles are characterised by their parameter shape, not by any
mimicry claim — the names describe what the traffic *looks like*, not what
it pretends to be.

The catalogue is shared by:
  * `shared/orchestrator.py` — writes per-run env files for client/server containers.
  * `protocols/typhoon/src/profile.rs` — Rust mirror; values must stay in sync.
  * `self/traffic_compare.py`, `self/use_case_compare.py` — Part 1 sweeps.
  * `background/corpus.py` — Part 3 corpus orchestrator.
  * `background/ml_blending.py` — flow labelling for the open-world detector.

All numerical values are starting defaults; they can be tuned in place during
implementation as Docker / aioquic / sipp behaviour requires.
"""

from dataclasses import dataclass, field
from enum import Enum
from random import Random
from typing import Final


class FakeBodyMode(Enum):
    """Mirror of `typhoon::flow::FakeBodyMode` for env-file serialisation."""

    EMPTY = "empty"
    CONSTANT = "constant"
    RANDOM = "random"
    RANDOM_SERVICE = "random_service"  # `service:true` — fake body only on service packets


@dataclass(frozen=True)
class Range:
    """Inclusive numerical range for per-run uniform sampling."""

    lo: float
    hi: float

    def sample(self, rng: Random) -> float:
        return rng.uniform(self.lo, self.hi)


@dataclass(frozen=True)
class IntRange:
    """Inclusive integer range for per-run uniform sampling."""

    lo: int
    hi: int

    def sample(self, rng: Random) -> int:
        return rng.randint(self.lo, self.hi)


@dataclass(frozen=True)
class Profile:
    """A traffic profile.  Each field is either a fixed value or a Range to sample from."""

    name: str
    description: str
    # Per-packet application-payload size (bytes).
    chunk_c2s: IntRange
    chunk_s2c: IntRange
    # Inter-arrival time per direction (milliseconds).
    iat_c2s_ms: Range
    iat_s2c_ms: Range
    # Total application bytes to transfer per direction.
    bytes_c2s: IntRange
    bytes_s2c: IntRange
    # Wall-clock cap for the whole flow (seconds) — overrides bytes_* if reached first.
    duration_s: Range
    # TYPHOON-specific FlowConfig override (ignored by background generators).
    fake_body_mode: FakeBodyMode
    fake_body_constant_len: int = 0      # used when fake_body_mode == CONSTANT
    fake_body_random_min: int = 0        # used when fake_body_mode == RANDOM*
    fake_body_random_max: int = 0
    fake_header_len: IntRange = field(default_factory=lambda: IntRange(8, 16))
    # Bursty flows: emit a chunk for `burst_active_s`, idle for `burst_idle_s`, repeat.
    bursty: bool = False
    burst_count: int = 1
    burst_idle_s: Range = field(default_factory=lambda: Range(0.0, 0.0))
    # Silent flows: TYPHOON's eval-side overrides set every DECOY_*_BASE_RATE
    # to 0 so no decoy traffic is generated.  Used by the silent_idle profile.
    decoys_enabled: bool = True
    # Future-work knob: per-profile identity-byte length override.  Currently
    # not wired through the protocol (would require a refactor of
    # IdentityType::length); recorded so callers can plan for it.
    id_length: int = 16


# ── Profile catalogue ────────────────────────────────────────────────────────

# Parameter ranges below derive from real-world UDP traffic measurement
# studies; see the project's internal traffic-capture rationale notes for
# citations and source breakdowns.

PROFILES: Final[dict[str, Profile]] = {
    "as_voice": Profile(
        name="as_voice",
        description="Mimics RTP voice (G.711 / Opus): symmetric 160 B payload + 12 B RTP header at 50 pps.",
        # Chunk 76-112 sits *below* max_user_payload (≈ 112 B with ShortIdentity
        # and RANDOM_SERVICE) so each `send_bytes` call produces exactly ONE
        # wire packet.  Previously chunk 150-170 > max_user_payload (≈ 100 B
        # with constant body=200), so every `send_bytes` got split into two
        # back-to-back packets — that's what produced the bimodal IAT
        # distribution (50 % sub-ms intra-split, 50 % 20 ms inter-send).
        # With this range and overhead ≈ 88 B, wire = 164-200 B per packet,
        # matching real rtp_voice's measured 164-200 B spread.
        chunk_c2s=IntRange(76, 112),
        chunk_s2c=IntRange(76, 112),
        iat_c2s_ms=Range(20.0, 20.0),
        iat_s2c_ms=Range(20.0, 20.0),
        bytes_c2s=IntRange(50_000, 200_000),
        bytes_s2c=IntRange(50_000, 200_000),
        duration_s=Range(30.0, 120.0),
        # RANDOM_SERVICE: data packets carry NO body padding (wire = chunk +
        # overhead) — so size variance comes from the chunk range above, not
        # from body padding.  Service packets (handshake / health-check) still
        # get random padding so they don't reveal themselves by being a
        # different fixed size from data packets.
        fake_body_mode=FakeBodyMode.RANDOM_SERVICE,
        fake_body_random_min=0,
        fake_body_random_max=100,
        # Pinned to exactly RTP header length so per-packet header size has
        # zero variance (matches real voice-over-RTP fingerprint).
        fake_header_len=IntRange(12, 12),
    ),
    "as_video": Profile(
        name="as_video",
        description="Mimics RTP video (H.264 720p @ 30 fps): symmetric, per-frame bursts of 1–20 packets, 33 ms frame interval, wide per-packet size variance.",
        # Lowered hi 1100 → 1000 so wire packets cluster nearer rtp_video's
        # gauss(1100, 100) mean of ~1100 B (with body + overhead, wire ≈
        # chunk + 100 = 1000-1100 B vs the previous 1100-1200).
        chunk_c2s=IntRange(900, 1000),
        chunk_s2c=IntRange(900, 1000),
        # Intra-burst IAT 0-2 ms, inter-burst 28-38 ms (tight RTP-video frame
        # rhythm).  Widening (0-5 ms / 20-80 ms) helped as_video_bursty
        # recover lost iat_std, but pushed as_video into a new
        # `iat_std −2.3σ` / `iat_p95 −2.4σ` gap — because as_video has both
        # directions sending bursts, the wider per-flow burst_idle range
        # produced flows whose IATs sample a narrower sub-range than real
        # bidirectional rtp_video sees from naturally-interleaved s2c+c2s
        # traffic.  Rolling back as_video to the tight values; keeping
        # as_video_bursty widened (it benefitted from the change).
        iat_c2s_ms=Range(0.0, 2.0),
        iat_s2c_ms=Range(0.0, 2.0),
        bytes_c2s=IntRange(2_000_000, 8_000_000),
        bytes_s2c=IntRange(2_000_000, 8_000_000),
        duration_s=Range(30.0, 120.0),
        fake_body_mode=FakeBodyMode.RANDOM,
        # Tightened max 100 → 50: pulls size_mean down ~25 B (closer to real
        # RTP video's ~1080 B mean) without giving up per-packet variance.
        fake_body_random_min=0,
        fake_body_random_max=50,
        fake_header_len=IntRange(8, 16),
        bursty=True,
        burst_count=60,
        burst_idle_s=Range(0.028, 0.038),
    ),
    "as_quic_d": Profile(
        name="as_quic_d",
        description="Mimics QUIC HTTP/3 download: handshake-only c2s, large s2c data flow capped under MTU=1450, second small-packet mode supplied by sparse decoys.",
        # No c2s user data — only handshake / health-check packets remain.
        # Matches the "pure download" scenario where the client requests once
        # and receives all data; closer to one-shot HTTP GET semantics than
        # full QUIC with ACK frames (which we can't reach below the 76 B
        # service-packet floor anyway).
        chunk_c2s=IntRange(0, 0),
        chunk_s2c=IntRange(1100, 1200),
        iat_c2s_ms=Range(0.0, 0.0),
        iat_s2c_ms=Range(0.0, 2.0),
        bytes_c2s=IntRange(0, 0),
        bytes_s2c=IntRange(10_000_000, 30_000_000),
        duration_s=Range(15.0, 60.0),
        # EMPTY body — every wire packet is exactly chunk + fake_header +
        # overhead, no random body padding inflating size.  Combined with
        # the eval-side MTU=1450 + SEND_BYTES_JITTER=0.1, wire s2c packets
        # land tightly under MTU like real QUIC.  The bimodal small-packet
        # mode comes from the SparseDecoyProvider override in eval_client.
        fake_body_mode=FakeBodyMode.EMPTY,
        fake_header_len=IntRange(22, 28),
    ),
    "as_quic_u": Profile(
        name="as_quic_u",
        description="Mimics QUIC HTTP/3 upload: handshake-only s2c, large c2s data flow capped under MTU=1450, second small-packet mode supplied by sparse decoys.",
        chunk_c2s=IntRange(1100, 1200),
        chunk_s2c=IntRange(0, 0),
        iat_c2s_ms=Range(0.0, 2.0),
        iat_s2c_ms=Range(0.0, 0.0),
        bytes_c2s=IntRange(10_000_000, 30_000_000),
        bytes_s2c=IntRange(0, 0),
        duration_s=Range(15.0, 60.0),
        # See as_quic_d for the rationale on EMPTY body + MTU + decoys.
        fake_body_mode=FakeBodyMode.EMPTY,
        fake_header_len=IntRange(22, 28),
    ),
    "as_video_bursty": Profile(
        name="as_video_bursty",
        description="Mimics asymmetric RTP video (broadcast / streaming): c2s-only frame bursts at 30 fps; mirrors as_video's frame interval but drops the s2c return path.",
        # See as_video for the chunk-range rationale.
        chunk_c2s=IntRange(900, 1000),
        chunk_s2c=IntRange(0, 0),
        # See as_video — intra-burst IAT widened 0-2 → 0-5 ms and burst_idle
        # widened 28-38 → 20-80 ms to add the per-burst variance real RTP
        # video has from natural jitter.  Previous tight ranges produced
        # iat_std −2.4σ and iat_p95 −2.5σ (TYPHOON too regular).
        iat_c2s_ms=Range(0.0, 5.0),
        iat_s2c_ms=Range(0.0, 0.0),
        bytes_c2s=IntRange(3_000_000, 5_000_000),
        bytes_s2c=IntRange(0, 0),
        duration_s=Range(40.0, 60.0),
        fake_body_mode=FakeBodyMode.RANDOM,
        fake_body_random_min=0,
        fake_body_random_max=50,
        fake_header_len=IntRange(8, 16),
        bursty=True,
        burst_count=60,
        burst_idle_s=Range(0.020, 0.080),
    ),
    "silent_idle": Profile(
        name="silent_idle",
        description="Silent connection: no application data, no decoy traffic — just the session handshake.  Models an idle VPN-style tunnel where the user is connected but doing nothing.",
        chunk_c2s=IntRange(0, 0),
        chunk_s2c=IntRange(0, 0),
        iat_c2s_ms=Range(0.0, 0.0),
        iat_s2c_ms=Range(0.0, 0.0),
        bytes_c2s=IntRange(0, 0),
        bytes_s2c=IntRange(0, 0),
        duration_s=Range(30.0, 90.0),
        fake_body_mode=FakeBodyMode.EMPTY,
        fake_header_len=IntRange(8, 16),
        decoys_enabled=False,
        id_length=4,  # signal — not yet honoured by Rust side; logged only.
    ),
    "raw_default": Profile(
        name="raw_default",
        description=(
            "Open-ended diversity baseline.  Both client and server emit "
            "random-sized packets at random intervals drawn per packet from "
            "broad uniform ranges (size 40–1400 B, IAT 0.5–200 ms) and "
            "FlowConfig::random + the protocol-default decoy provider + "
            "default settings are used unchanged (no eval-side pinning).  "
            "Mirrors the `unknown` background generator's parameter space so "
            "the (raw_default, unknown) pair demonstrates that TYPHOON's "
            "defaults blend with arbitrary long-tail UDP rather than any one "
            "natural class.  The chunk/IAT *ranges* are passed to the Rust "
            "eval binaries via PROFILE_CHUNK_*_MIN/MAX and PROFILE_IAT_*_MIN/MAX_MS "
            "env vars; the binaries resample per packet only when the profile "
            "name is `raw_default`, so tuned profiles' single-shape behaviour "
            "is preserved."
        ),
        chunk_c2s=IntRange(40, 1400),
        chunk_s2c=IntRange(40, 1400),
        iat_c2s_ms=Range(0.5, 200.0),
        iat_s2c_ms=Range(0.5, 200.0),
        bytes_c2s=IntRange(100_000, 5_000_000),
        bytes_s2c=IntRange(100_000, 5_000_000),
        duration_s=Range(15.0, 90.0),
        # These fields are *signals only* for raw_default — the Rust client/server
        # skip pinning when `is_raw_default()` and let `FlowConfig::random` choose
        # body / header / decoy provider randomly per flow.
        fake_body_mode=FakeBodyMode.RANDOM,
        fake_header_len=IntRange(0, 0),
    ),
    "tuned_default": Profile(
        name="tuned_default",
        description=(
            "Same per-packet randomization and FlowConfig::random freedom as "
            "raw_default, but the Rust eval binaries apply blending-oriented "
            "settings overrides on top: SEND_BYTES_JITTER=0.8, "
            "DECOY_FALLTHROUGH_PACKETS_MAX=0.75, and decoy emission rates "
            "multiplied by 3.  Used to demonstrate how much closer to the "
            "`unknown` long-tail distribution TYPHOON can get without "
            "touching the performance-oriented protocol defaults."
        ),
        chunk_c2s=IntRange(40, 1400),
        chunk_s2c=IntRange(40, 1400),
        iat_c2s_ms=Range(0.5, 200.0),
        iat_s2c_ms=Range(0.5, 200.0),
        bytes_c2s=IntRange(100_000, 5_000_000),
        bytes_s2c=IntRange(100_000, 5_000_000),
        duration_s=Range(15.0, 90.0),
        fake_body_mode=FakeBodyMode.RANDOM,
        fake_header_len=IntRange(0, 0),
    ),
}


# Default profile when nothing is specified — deliberately the simplest, most
# extensively used pattern.
DEFAULT_PROFILE: Final[str] = "as_quic_u"


# ── Per-service IP allocation (Part 3) ───────────────────────────────────────

# Each service slot occupies one IP on each `/24`.  Slot 0 is TYPHOON; slots
# 1..8 are background generators.  The corpus orchestrator writes the active
# slot map into per-run metadata.json so the ML labeller can map flows back
# to source classes by (src_ip, dst_ip).

NET_LEFT_PREFIX: Final[str]  = "172.20.0."
NET_RIGHT_PREFIX: Final[str] = "172.21.0."
OBSERVER_LEFT_IP: Final[str]  = NET_LEFT_PREFIX + "2"
OBSERVER_RIGHT_IP: Final[str] = NET_RIGHT_PREFIX + "2"


@dataclass(frozen=True)
class ServiceSlot:
    """A pre-allocated IP slot for one client/server pair in the Part 3 corpus."""

    name: str
    suffix: int  # IP host part on both /24 networks (e.g. 10 → .10)

    @property
    def client_ip(self) -> str:
        return NET_LEFT_PREFIX + str(self.suffix)

    @property
    def server_ip(self) -> str:
        return NET_RIGHT_PREFIX + str(self.suffix)


SERVICE_SLOTS: Final[dict[str, ServiceSlot]] = {
    "typhoon":       ServiceSlot("typhoon",       10),
    "quic_download": ServiceSlot("quic_download", 11),
    "quic_upload":   ServiceSlot("quic_upload",   12),
    "dns":           ServiceSlot("dns",           13),
    "rtp_voice":     ServiceSlot("rtp_voice",     14),
    "rtp_video":     ServiceSlot("rtp_video",     15),
    "gaming":        ServiceSlot("gaming",        16),
    "wireguard_idle":ServiceSlot("wireguard_idle",17),
    "control_plane": ServiceSlot("control_plane", 18),
    "unknown":       ServiceSlot("unknown",       19),
}

# Slots that model the long-tail "private / custom / legacy UDP" protocols a
# real censor cannot enumerate.  By policy these labels must **never** appear
# in any open-set classifier's training set — they exist solely to populate
# the held-out unknown-class evaluation bucket (see ml_open_world Tests D/E).
HELD_OUT_BG_CLASSES: Final[frozenset[str]] = frozenset({"unknown"})


# Per-class sampling weights for the corpus orchestrator (uniform inclusion
# probability after R6 — kept here as a single source if we ever want
# weighting).  Currently uniform; see `background/corpus.py:_sample_generators`.
GENERATOR_WEIGHTS: Final[dict[str, float]] = {
    "quic_download":  1.0,
    "quic_upload":    1.0,
    "dns":            1.0,
    "rtp_voice":      1.0,
    "rtp_video":      1.0,
    "gaming":         1.0,
    "wireguard_idle": 1.0,
    "control_plane":  1.0,
    "unknown":        1.0,
}


# ── Background-class natural parameter profiles ──────────────────────────────

# Each background generator samples its own parameters from this catalogue,
# *independent* of which TYPHOON profile the run is exercising.  Earlier the
# corpus passed TYPHOON's profile env to every container, which warped real
# flows (e.g. `quic_download` running with `as_voice` parameters became a
# tiny request-response, not real QUIC) and made the bg-class distribution
# heterogeneous along profile axes.  Sourcing each bg generator from its own
# distribution restores realistic per-class traffic.
#
# Parameter ranges:
#   * QUIC up/down — Bajpai PAM 2017, CESNET-QUIC22, RFC 9000 §14.1
#   * DNS — APNIC measurement notes
#   * RTP voice — Cisco VoIP bandwidth ref (G.711 / Opus)
#   * RTP video — Cisco TelePresence + WebRTC RFC 8831
#   * Gaming — Chambers et al. UCSB
#   * WireGuard idle — Donenfeld NDSS 2017 (60 B keepalive every 25 s)
#   * Control plane — RFCs (NTP / mDNS / STUN)


@dataclass(frozen=True)
class BackgroundProfile:
    """Per-class natural-traffic profile for a background generator.

    Holds only the parameters the generators actually read via
    ``ProfileEnv.from_env()`` — no TYPHOON-specific FlowConfig fields, no
    decoy/identity knobs.  Mirrors the env-var schema in
    ``background/common/profile_env.py``.
    """

    name: str
    chunk_c2s: IntRange
    chunk_s2c: IntRange
    iat_c2s_ms: Range
    iat_s2c_ms: Range
    bytes_c2s: IntRange
    bytes_s2c: IntRange
    duration_s: Range
    bursty: bool = False
    burst_count: int = 1
    burst_idle_s: Range = field(default_factory=lambda: Range(0.0, 0.0))


BACKGROUND_PROFILES: Final[dict[str, BackgroundProfile]] = {
    "quic_download": BackgroundProfile(
        name="quic_download",
        # Bimodal: small ACKs c2s + MTU-bounded data s2c.
        chunk_c2s=IntRange(40, 100),
        chunk_s2c=IntRange(1100, 1450),
        iat_c2s_ms=Range(1.0, 50.0),
        iat_s2c_ms=Range(0.0, 2.0),
        bytes_c2s=IntRange(20_000, 500_000),
        bytes_s2c=IntRange(5_000_000, 50_000_000),
        duration_s=Range(15.0, 90.0),
    ),
    "quic_upload": BackgroundProfile(
        name="quic_upload",
        chunk_c2s=IntRange(1100, 1450),
        chunk_s2c=IntRange(40, 100),
        iat_c2s_ms=Range(0.0, 2.0),
        iat_s2c_ms=Range(1.0, 50.0),
        bytes_c2s=IntRange(5_000_000, 50_000_000),
        bytes_s2c=IntRange(20_000, 500_000),
        duration_s=Range(15.0, 90.0),
    ),
    "dns": BackgroundProfile(
        name="dns",
        # Single-shot small queries; sparse and short-lived.
        chunk_c2s=IntRange(60, 200),
        chunk_s2c=IntRange(0, 0),
        iat_c2s_ms=Range(50.0, 2_000.0),
        iat_s2c_ms=Range(0.0, 0.0),
        bytes_c2s=IntRange(2_000, 50_000),
        bytes_s2c=IntRange(0, 0),
        duration_s=Range(5.0, 30.0),
    ),
    "rtp_voice": BackgroundProfile(
        name="rtp_voice",
        # G.711 / Opus: 200 B every 20 ms in both directions.
        chunk_c2s=IntRange(160, 200),
        chunk_s2c=IntRange(160, 200),
        iat_c2s_ms=Range(20.0, 20.0),
        iat_s2c_ms=Range(20.0, 20.0),
        bytes_c2s=IntRange(50_000, 500_000),
        bytes_s2c=IntRange(50_000, 500_000),
        duration_s=Range(30.0, 120.0),
    ),
    "rtp_video": BackgroundProfile(
        name="rtp_video",
        # Cisco TelePresence: ~1100 B at 30 fps frame intervals; bursty.
        chunk_c2s=IntRange(1000, 1200),
        chunk_s2c=IntRange(1000, 1200),
        iat_c2s_ms=Range(28.0, 38.0),
        iat_s2c_ms=Range(28.0, 38.0),
        bytes_c2s=IntRange(2_000_000, 20_000_000),
        bytes_s2c=IntRange(2_000_000, 20_000_000),
        duration_s=Range(30.0, 120.0),
        bursty=True,
        burst_count=10,
        burst_idle_s=Range(0.020, 0.040),
    ),
    "gaming": BackgroundProfile(
        name="gaming",
        # Chambers UCSB: c2s 60–300 B, s2c 40–60 B, 16–60 ms IAT.
        chunk_c2s=IntRange(60, 300),
        chunk_s2c=IntRange(40, 60),
        iat_c2s_ms=Range(16.0, 60.0),
        iat_s2c_ms=Range(16.0, 60.0),
        bytes_c2s=IntRange(10_000, 500_000),
        bytes_s2c=IntRange(10_000, 200_000),
        duration_s=Range(30.0, 180.0),
    ),
    "wireguard_idle": BackgroundProfile(
        name="wireguard_idle",
        # Persistent-keepalive only: 60 B every 25 s.
        chunk_c2s=IntRange(60, 60),
        chunk_s2c=IntRange(60, 60),
        iat_c2s_ms=Range(25_000.0, 25_000.0),
        iat_s2c_ms=Range(25_000.0, 25_000.0),
        bytes_c2s=IntRange(60, 600),
        bytes_s2c=IntRange(60, 600),
        duration_s=Range(60.0, 180.0),
    ),
    "control_plane": BackgroundProfile(
        name="control_plane",
        # NTP / mDNS / STUN: small packets, sparse IATs.
        chunk_c2s=IntRange(60, 500),
        chunk_s2c=IntRange(0, 0),
        iat_c2s_ms=Range(1_000.0, 60_000.0),
        iat_s2c_ms=Range(0.0, 0.0),
        bytes_c2s=IntRange(60, 5_000),
        bytes_s2c=IntRange(0, 0),
        duration_s=Range(60.0, 180.0),
    ),
    "unknown": BackgroundProfile(
        # Synthetic long-tail "private / custom / legacy UDP" class.  Only
        # `duration_s` is honoured by the generator; every other parameter
        # is drawn from the generator's own broad parameter space at run
        # time (see evaluation/background/unknown/unknown.py).  The unknown
        # class is held out of every supervised classifier — see
        # `HELD_OUT_BG_CLASSES`.
        name="unknown",
        chunk_c2s=IntRange(0, 0),
        chunk_s2c=IntRange(0, 0),
        iat_c2s_ms=Range(0.0, 0.0),
        iat_s2c_ms=Range(0.0, 0.0),
        bytes_c2s=IntRange(0, 0),
        bytes_s2c=IntRange(0, 0),
        duration_s=Range(30.0, 120.0),
    ),
}


# Network-wide chaos parameter ranges, applied via the chaos sidecar's tc/netem
# qdisc.  Ranges are anchored to public internet-measurement studies; the comments per parameter cite
# the binding constraint.
CHAOS_LATENCY_MS: Final[Range]  = Range(10.0, 100.0)
# Jitter is sampled relative to the per-run latency (see corpus._sample_chaos);
# this Range is the *fraction* of latency used for the jitter ceiling.
CHAOS_JITTER_FRACTION: Final[Range] = Range(0.0, 0.5)
# Loss capped at 1.0 % — aioquic destabilises under sustained higher loss.
# Real residential / mobile loss rates (Paxson 1999; Bauer 2009) sit in
# 0.05–1 % range, so this also matches measured wild-internet rates.
CHAOS_LOSS_PCT: Final[Range]    = Range(0.0, 1.0)
# Duplicate rate.  Bellardo & Savage IMC 2005 measure 0.001–0.1 % duplicates
# on real transit links; we extend slightly to 0.2 % so chaos can probe the
# top of the realistic range without crossing into synthetic-stress territory.
CHAOS_DUPLICATE_PCT: Final[Range] = Range(0.0, 0.2)
# Reorder rate.  Paxson 1999 and Pucha et al. SIGCOMM 2003 report 0.1–2 %
# on multi-path routes; Bellardo & Savage 2005 corroborate.  netem requires
# delay > 0 to actually emit reordered packets — `CHAOS_LATENCY_MS.lo = 10`
# guarantees we always have a non-zero base delay.
CHAOS_REORDER_PCT: Final[Range] = Range(0.0, 1.5)


def profile_to_env(profile: Profile, rng: Random) -> dict[str, str]:
    """Sample per-run values from a profile and return env-var dict for both client and server.

    Emits both the per-run sampled values (``PROFILE_CHUNK_C2S``, ``PROFILE_IAT_C2S_MS``,
    etc.) and the underlying range bounds (``PROFILE_CHUNK_C2S_MIN/MAX``,
    ``PROFILE_IAT_C2S_MIN/MAX_MS``, etc.).  The Rust eval binaries only consult
    the MIN/MAX bounds for the ``raw_default`` profile, where they drive
    per-packet resampling; tuned profiles ignore the bounds and use the
    single sampled value, preserving their fixed-shape design intent.
    """
    return {
        "TRAFFIC_PROFILE":          profile.name,
        "PROFILE_CHUNK_C2S":        str(profile.chunk_c2s.sample(rng)),
        "PROFILE_CHUNK_S2C":        str(profile.chunk_s2c.sample(rng)),
        "PROFILE_CHUNK_C2S_MIN":    str(profile.chunk_c2s.lo),
        "PROFILE_CHUNK_C2S_MAX":    str(profile.chunk_c2s.hi),
        "PROFILE_CHUNK_S2C_MIN":    str(profile.chunk_s2c.lo),
        "PROFILE_CHUNK_S2C_MAX":    str(profile.chunk_s2c.hi),
        "PROFILE_IAT_C2S_MS":       f"{profile.iat_c2s_ms.sample(rng):.3f}",
        "PROFILE_IAT_S2C_MS":       f"{profile.iat_s2c_ms.sample(rng):.3f}",
        "PROFILE_IAT_C2S_MIN_MS":   f"{profile.iat_c2s_ms.lo:.3f}",
        "PROFILE_IAT_C2S_MAX_MS":   f"{profile.iat_c2s_ms.hi:.3f}",
        "PROFILE_IAT_S2C_MIN_MS":   f"{profile.iat_s2c_ms.lo:.3f}",
        "PROFILE_IAT_S2C_MAX_MS":   f"{profile.iat_s2c_ms.hi:.3f}",
        "PROFILE_BYTES_C2S":        str(profile.bytes_c2s.sample(rng)),
        "PROFILE_BYTES_S2C":        str(profile.bytes_s2c.sample(rng)),
        "PROFILE_DURATION_S":       f"{profile.duration_s.sample(rng):.3f}",
        "PROFILE_FAKE_BODY_MODE":   profile.fake_body_mode.value,
        "PROFILE_FAKE_BODY_CONST":  str(profile.fake_body_constant_len),
        "PROFILE_FAKE_BODY_MIN":    str(profile.fake_body_random_min),
        "PROFILE_FAKE_BODY_MAX":    str(profile.fake_body_random_max),
        "PROFILE_FAKE_HEADER_LEN":  str(profile.fake_header_len.sample(rng)),
        "PROFILE_BURSTY":           "1" if profile.bursty else "0",
        "PROFILE_BURST_COUNT":      str(profile.burst_count),
        "PROFILE_BURST_IDLE_S":     f"{profile.burst_idle_s.sample(rng):.3f}",
        "PROFILE_DECOYS_ENABLED":   "1" if profile.decoys_enabled else "0",
        "PROFILE_ID_LENGTH":        str(profile.id_length),
    }


def bg_profile_to_env(bg_profile: BackgroundProfile, rng: Random) -> dict[str, str]:
    """Sample per-run values from a background profile and return env-var dict for the generator container.

    Emits the same ``PROFILE_*`` env keys consumed by
    ``background/common/profile_env.py:ProfileEnv.from_env`` — bg generators
    need no code change to pick these up; the corpus orchestrator just sends
    bg-specific values instead of TYPHOON's profile env.
    """
    return {
        "TRAFFIC_PROFILE":     bg_profile.name,
        "PROFILE_CHUNK_C2S":   str(bg_profile.chunk_c2s.sample(rng)),
        "PROFILE_CHUNK_S2C":   str(bg_profile.chunk_s2c.sample(rng)),
        "PROFILE_IAT_C2S_MS":  f"{bg_profile.iat_c2s_ms.sample(rng):.3f}",
        "PROFILE_IAT_S2C_MS":  f"{bg_profile.iat_s2c_ms.sample(rng):.3f}",
        "PROFILE_BYTES_C2S":   str(bg_profile.bytes_c2s.sample(rng)),
        "PROFILE_BYTES_S2C":   str(bg_profile.bytes_s2c.sample(rng)),
        "PROFILE_DURATION_S":  f"{bg_profile.duration_s.sample(rng):.3f}",
        "PROFILE_BURSTY":      "1" if bg_profile.bursty else "0",
        "PROFILE_BURST_COUNT": str(bg_profile.burst_count),
        "PROFILE_BURST_IDLE_S": f"{bg_profile.burst_idle_s.sample(rng):.3f}",
    }
