"""Single source of truth for traffic profiles, used across all evaluation parts.

A profile fixes the per-flow shape of generated traffic (sizes, IATs, direction
asymmetry, session duration, plus TYPHOON-specific FlowConfig overrides).
Profile names describe parameter shape, not a mimicry claim.

Shared by `shared/orchestrator.py`, `protocols/typhoon/src/profile.rs`
(Rust mirror — values must stay in sync), `self/traffic_compare.py`,
`self/use_case_compare.py`, `background/corpus.py`, `background/ml_blending.py`.
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
        # chunk_c2s/s2c must stay below max_user_payload (~112 B with
        # ShortIdentity + RANDOM_SERVICE) so each send_bytes emits one wire
        # packet, not a split pair.
        chunk_c2s=IntRange(76, 112),
        chunk_s2c=IntRange(76, 112),
        iat_c2s_ms=Range(20.0, 20.0),
        iat_s2c_ms=Range(20.0, 20.0),
        bytes_c2s=IntRange(50_000, 200_000),
        bytes_s2c=IntRange(50_000, 200_000),
        duration_s=Range(30.0, 120.0),
        # RANDOM_SERVICE leaves data packets unpadded; service packets still
        # get random padding so they don't stand out by being a fixed size.
        fake_body_mode=FakeBodyMode.RANDOM_SERVICE,
        fake_body_random_min=0,
        fake_body_random_max=100,
        fake_header_len=IntRange(12, 12),
    ),
    "as_video": Profile(
        name="as_video",
        description="Mimics RTP video (H.264 720p @ 30 fps): symmetric, per-frame bursts of 1–20 packets, 33 ms frame interval, wide per-packet size variance.",
        chunk_c2s=IntRange(900, 1000),
        chunk_s2c=IntRange(900, 1000),
        iat_c2s_ms=Range(0.0, 2.0),
        iat_s2c_ms=Range(0.0, 2.0),
        bytes_c2s=IntRange(2_000_000, 8_000_000),
        bytes_s2c=IntRange(2_000_000, 8_000_000),
        duration_s=Range(30.0, 120.0),
        fake_body_mode=FakeBodyMode.RANDOM,
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
        chunk_c2s=IntRange(0, 0),
        chunk_s2c=IntRange(1100, 1200),
        iat_c2s_ms=Range(0.0, 0.0),
        iat_s2c_ms=Range(0.0, 2.0),
        bytes_c2s=IntRange(0, 0),
        bytes_s2c=IntRange(10_000_000, 30_000_000),
        duration_s=Range(15.0, 60.0),
        # EMPTY body + eval-side MTU=1450 + SEND_BYTES_JITTER=0.1 keep wire
        # s2c packets tight under MTU. Bimodal small-packet mode comes from
        # the SparseDecoyProvider override in eval_client.
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
        fake_body_mode=FakeBodyMode.EMPTY,
        fake_header_len=IntRange(22, 28),
    ),
    "as_video_bursty": Profile(
        name="as_video_bursty",
        description="Mimics asymmetric RTP video (broadcast / streaming): c2s-only frame bursts at 30 fps; mirrors as_video's frame interval but drops the s2c return path.",
        chunk_c2s=IntRange(900, 1000),
        chunk_s2c=IntRange(0, 0),
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
    "bulk_upload": Profile(
        name="bulk_upload",
        description="Operational-comparison default for `poe capture --all`",
        chunk_c2s=IntRange(1100, 1200),
        chunk_s2c=IntRange(0, 0),
        iat_c2s_ms=Range(4.0, 4.0),
        iat_s2c_ms=Range(0.0, 0.0),
        bytes_c2s=IntRange(10_000_000, 10_000_000),
        bytes_s2c=IntRange(0, 0),
        duration_s=Range(600.0, 600.0),
        fake_body_mode=FakeBodyMode.RANDOM,
    ),
    "raw_default": Profile(
        name="raw_default",
        description="Open-ended diversity baseline: per-packet random size 40–1400 B and IAT 0.5–200 ms, FlowConfig::random + protocol-default decoys (no eval-side pinning). Mirrors the `unknown` background generator's parameter space.",
        chunk_c2s=IntRange(40, 1400),
        chunk_s2c=IntRange(40, 1400),
        iat_c2s_ms=Range(0.5, 200.0),
        iat_s2c_ms=Range(0.5, 200.0),
        bytes_c2s=IntRange(100_000, 5_000_000),
        bytes_s2c=IntRange(100_000, 5_000_000),
        duration_s=Range(15.0, 90.0),
        # Signals only — Rust binaries skip pinning for is_raw_default().
        fake_body_mode=FakeBodyMode.RANDOM,
        fake_header_len=IntRange(0, 0),
    ),
    "tuned_default": Profile(
        name="tuned_default",
        description="Same per-packet randomization as raw_default with blending-oriented eval overrides: SEND_BYTES_JITTER=0.8, DECOY_FALLTHROUGH_PACKETS_MAX=0.75, 3× decoy emission rates.",
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


# Default profile when nothing is specified.
DEFAULT_PROFILE: Final[str] = "bulk_upload"

# Profiles eligible for the Part 3 background-blending corpus schedule.
# `bulk_upload` is Part 2's operational-comparison default: it has no
# `PROFILE_TARGET_CLASS` mimicry target, a degenerate (non-randomized)
# bytes_c2s/duration_s budget, and no s2c traffic, so pooling it with the
# camouflage profiles would dilute what Part 3's classifiers actually measure.
PART3_PROFILES: Final[tuple[str, ...]] = tuple(name for name in PROFILES if name != "bulk_upload")

# Class label TYPHOON flows carry throughout Part 3 (corpus `ip_map`, ML
# feature labels, HELD_OUT_BG_CLASSES comparisons) — single source of truth
# so `background/corpus.py`, `background/ml_blending.py`, and
# `background/dist_plot.py` don't each define their own copy.
TYPHOON_CLASS: Final[str] = "typhoon"


# ── Per-service IP allocation (Part 3) ───────────────────────────────────────

# Each service slot occupies one IP on each `/24`.  Every corpus run now
# instantiates every slot below simultaneously (all `PART3_PROFILES` TYPHOON
# instances + all `BACKGROUND_PROFILES` classes) — see `background/corpus.py`.
# The corpus orchestrator writes the active slot map into per-run
# metadata.json so the ML labeller can map flows back to source classes by
# (src_ip, dst_ip).

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


# Background-class slots (suffixes 11-19) plus one slot per `PART3_PROFILES`
# TYPHOON mimicry profile (suffixes 20-27) — each profile gets its own
# dedicated client/server pair + IP so all 8 can run concurrently within one
# corpus run without colliding, mirroring the background generators.
SERVICE_SLOTS: Final[dict[str, ServiceSlot]] = {
    "quic_download": ServiceSlot("quic_download", 11),
    "quic_upload":   ServiceSlot("quic_upload",   12),
    "dns":           ServiceSlot("dns",           13),
    "rtp_voice":     ServiceSlot("rtp_voice",     14),
    "rtp_video":     ServiceSlot("rtp_video",     15),
    "gaming":        ServiceSlot("gaming",        16),
    "wireguard_idle":ServiceSlot("wireguard_idle",17),
    "control_plane": ServiceSlot("control_plane", 18),
    "unknown":       ServiceSlot("unknown",       19),
    **{name: ServiceSlot(name, 20 + i) for i, name in enumerate(PART3_PROFILES)},
}

# Slots that model the long-tail "private / custom / legacy UDP" protocols a
# real censor cannot enumerate.  By policy these labels must **never** appear
# in any open-set classifier's training set — they exist solely to populate
# the held-out unknown-class evaluation bucket (see ml_open_world Tests D/E).
HELD_OUT_BG_CLASSES: Final[frozenset[str]] = frozenset({"unknown"})


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
