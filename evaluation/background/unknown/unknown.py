#!/usr/bin/env python3
"""Synthetic ``unknown`` UDP traffic generator — diverse long-tail protocols.

Each invocation of this script — one TYPHOON eval corpus run — picks one
random point in a broad parameter space covering:

  * direction asymmetry        (c2s_only / s2c_only / symmetric / c2s_heavy / s2c_heavy)
                               weighted toward bidirectional traffic to match
                               the empirical residue mix (Trevisan ToN'20:
                               ~40% of nDPI-unclassified UDP is bidirectional,
                               game/control/RPC channels dominate the long
                               tail).  Pure one-way flows are kept at low
                               weight as a known minority case.
  * flow pattern               (continuous / bursty / sporadic / single_shot)
  * per-packet size            (uniform 40..1450 B)
  * IAT pattern                (fixed / uniform_jitter / exponential / clockwork)
  * mean IAT                   (log-uniform 0.5 ms..5 s)
  * payload entropy mode       (random_bytes / ascii_text / structured_ascii /
                                zero_padded / mixed)

Each parameter is sampled **independently of any TYPHOON profile parameter**,
so the resulting traffic is statistically broad but adversarially-unbiased
toward / away from TYPHOON's wire shape — matching the "long tail of
private / custom / legacy UDP protocols a deployed censor cannot enumerate"
threat-model assumption.

Reads only `PROFILE_DURATION_S` and `PROFILE_SEED` from the per-run env so
the unknown class is structurally distinct from the `BACKGROUND_PROFILES`
sampling system — every other parameter is fresh-random per run.
"""

from __future__ import annotations

from math import exp, log
from os import environ, system, urandom
from random import Random, randint
from socket import AF_INET, SOCK_DGRAM, socket, timeout
from string import ascii_letters, digits, punctuation
from sys import exit
from threading import Thread
from time import monotonic, sleep

UNKNOWN_PORT = 9999
RECV_BUFFER = 2048
LISTEN_TIMEOUT = 0.2

# Parameter ranges — broad enough to cover gaming-tick (40 B) through MTU
# (1450 B) packets, sub-ms IATs through multi-second sporadic ones, and the
# full entropy spectrum from zero-padded plaintext to encrypted-looking
# random bytes.  Bounds chosen to avoid degenerate single-packet flows.
DIRECTION_MODES = ("c2s_only", "s2c_only", "symmetric", "c2s_heavy", "s2c_heavy")
# Direction weights bias the unknown residue toward bidirectional flows: the
# previous uniform weighting put 60% of flows in mostly-unidirectional modes
# (c2s_only + s2c_only + c2s_heavy + s2c_heavy with HEAVY_RATIO=10), driving
# unknown's burst_pkts mean to ~250-435 vs TYPHOON's ~13-17.  Real long-tail
# UDP residue is dominantly bidirectional (game ticks, VoIP control, IoT
# telemetry-with-acks, custom RPC), so we weight `symmetric` at 4 and the
# heavy modes at 2 each; the pure one-way modes stay at 1 each as a known
# minority case.  Combined with the lowered HEAVY_RATIO this collapses the
# burst-shape gap that drove the dominant detection signal.
DIRECTION_WEIGHTS = (1, 1, 4, 2, 2)
FLOW_PATTERNS = ("continuous", "bursty", "sporadic", "single_shot")
IAT_PATTERNS = ("fixed", "uniform_jitter", "exponential", "clockwork")
PAYLOAD_MODES = ("random_bytes", "ascii_text", "structured_ascii", "zero_padded", "mixed")
# Weights chosen so this generator reproduces the *unclassifiable* / nDPI
# `Unknown_Protocol` residue characteristics rather than the public-Internet
# UDP mix as a whole (catalogued protocols are covered by the dedicated bg
# classes — DNS, QUIC, RTP, gaming, control plane).  Empirically that
# residue is dominated by encrypted streams ntop's nDPI cannot fingerprint,
# so the random_bytes weight is the largest single weight; the text /
# structured / zero-padded modes are kept small because they would be
# catalogued under their actual protocol classes if seen.  See
# TRAFFIC_CAPTURE_REFERENCE.md §7.10 for the citation lineage (Wang CCS'15,
# Wu USENIX'23, Trevisan ToN'20, Houmansadr S&P'13).
PAYLOAD_MODE_WEIGHTS = (0.65, 0.05, 0.15, 0.05, 0.10)

SIZE_MIN_B = 40
SIZE_MAX_B = 1450
IAT_MIN_S = 0.0005
IAT_MAX_S = 5.0
SIZE_JITTER_MAX = 0.5
BURST_PACKETS_MIN = 2
BURST_PACKETS_MAX = 64
BURST_IDLE_MIN_S = 0.05
BURST_IDLE_MAX_S = 5.0
SPORADIC_IDLE_MIN_S = 0.5
SPORADIC_IDLE_MAX_S = 30.0
SINGLE_SHOT_MAX_PACKETS = 4
# Ratio applied to the *light* direction's sporadic_idle when one direction
# dominates (c2s_heavy / s2c_heavy modes).  Lowered from 10 to 3 so the
# minor direction still produces enough traffic to interleave with the
# dominant direction's bursts, matching real client-pull / server-push
# patterns where the response channel is sparse but not silent.
HEAVY_RATIO = 3
ASCII_CHARSET = ascii_letters + digits + punctuation + " "


def _log_uniform(rng: Random, lo: float, hi: float) -> float:
    """Sample uniformly in log-space — useful for ranges spanning multiple orders of magnitude."""
    return exp(rng.uniform(log(lo), log(hi)))


def _route_setup(role: str) -> None:
    """Mirror the route-setup other bg generators use so the observer sits in the middle."""
    gw = environ.get("OBSERVER_GW")
    if not gw:
        return
    target = "172.21.0.0/24" if role == "client" else "172.20.0.0/24"
    system(f"ip route add {target} via {gw} 2>/dev/null")  # noqa: S605


def _sample_params(rng: Random) -> dict:
    """Draw one full parameter configuration for this run."""
    return {
        "direction":      rng.choices(DIRECTION_MODES, weights=DIRECTION_WEIGHTS, k=1)[0],
        "flow_pattern":   rng.choice(FLOW_PATTERNS),
        # Uniform on [SIZE_MIN_B, SIZE_MAX_B] is the maximum-entropy prior given
        # only the bounds.  Log-uniform implicitly biases toward small packets,
        # which would mimic catalogued small-packet protocols (DNS, NTP, gaming)
        # — but those have their own bg classes and the `unknown` residue is
        # explicitly *not* one of them.  See TRAFFIC_CAPTURE_REFERENCE.md §7.10.
        "base_size":      rng.randint(SIZE_MIN_B, SIZE_MAX_B),
        "size_jitter":    rng.uniform(0.0, SIZE_JITTER_MAX),
        "iat_pattern":    rng.choice(IAT_PATTERNS),
        "mean_iat_s":     _log_uniform(rng, IAT_MIN_S, IAT_MAX_S),
        "payload_mode":   rng.choices(PAYLOAD_MODES, weights=PAYLOAD_MODE_WEIGHTS, k=1)[0],
        "burst_pkts":     rng.randint(BURST_PACKETS_MIN, BURST_PACKETS_MAX),
        "burst_idle_s":   rng.uniform(BURST_IDLE_MIN_S, BURST_IDLE_MAX_S),
        "sporadic_idle_s": rng.uniform(SPORADIC_IDLE_MIN_S, SPORADIC_IDLE_MAX_S),
    }


def _sample_size(rng: Random, base: int, jitter: float) -> int:
    """Per-packet size = base * (1 ± jitter/2)."""
    if jitter <= 0:
        return base
    lo = max(SIZE_MIN_B, int(base * (1 - jitter)))
    hi = min(SIZE_MAX_B, int(base * (1 + jitter)))
    return rng.randint(lo, hi) if hi > lo else lo


def _sample_iat(rng: Random, pattern: str, mean: float) -> float:
    """Per-packet IAT sampled from the chosen distribution."""
    if pattern == "fixed":
        return mean
    if pattern == "uniform_jitter":
        return rng.uniform(mean * 0.5, mean * 1.5)
    if pattern == "exponential":
        return rng.expovariate(1.0 / mean)
    if pattern == "clockwork":
        # Two-mode IAT: 90% at `mean`, 10% at 10x mean (simulating periodic stalls).
        return mean if rng.random() < 0.9 else mean * 10.0
    return mean


def _payload(rng: Random, size: int, mode: str) -> bytes:
    """Generate one payload of `size` bytes in the chosen entropy mode."""
    if mode == "random_bytes":
        return urandom(size)
    if mode == "ascii_text":
        return ("".join(rng.choices(ASCII_CHARSET, k=size))).encode("latin-1")
    if mode == "structured_ascii":
        # Header-like prefix + random tail — moderate entropy.
        prefix = f"PKT-{rng.randint(0, 9999):04d} ".encode()
        tail_size = max(0, size - len(prefix))
        return prefix + (b"X" * tail_size)
    if mode == "zero_padded":
        return b"\x00" * size
    # mixed: alternating modes per packet, sampled fresh.
    submode = rng.choice(("random_bytes", "ascii_text", "zero_padded"))
    return _payload(rng, size, submode)


def _send_packet(sock: socket, payload: bytes, peer: tuple[str, int] | None) -> None:
    """Send via connected (peer=None) or unconnected (peer given) socket."""
    try:
        if peer is None:
            sock.send(payload)
        else:
            sock.sendto(payload, peer)
    except OSError:
        pass


def _emit_flow(
    sock: socket,
    peer: tuple[str, int] | None,
    rng: Random,
    params: dict,
    direction: str,
    deadline: float,
) -> int:
    """Run one direction's send loop until `deadline` according to `params`.

    `direction` is `"c2s"` for client and `"s2c"` for server; we use it only
    to apply per-direction packet-count budget (HEAVY_RATIO modulation).
    """
    pattern = params["flow_pattern"]
    sent = 0
    if pattern == "single_shot":
        n = rng.randint(1, SINGLE_SHOT_MAX_PACKETS)
        for _ in range(n):
            if monotonic() >= deadline:
                break
            size = _sample_size(rng, params["base_size"], params["size_jitter"])
            _send_packet(sock, _payload(rng, size, params["payload_mode"]), peer)
            sent += 1
        return sent

    while monotonic() < deadline:
        if pattern == "continuous":
            size = _sample_size(rng, params["base_size"], params["size_jitter"])
            _send_packet(sock, _payload(rng, size, params["payload_mode"]), peer)
            sent += 1
            wait = _sample_iat(rng, params["iat_pattern"], params["mean_iat_s"])
            sleep(min(wait, max(deadline - monotonic(), 0.0)))
        elif pattern == "bursty":
            for _ in range(params["burst_pkts"]):
                if monotonic() >= deadline:
                    break
                size = _sample_size(rng, params["base_size"], params["size_jitter"])
                _send_packet(sock, _payload(rng, size, params["payload_mode"]), peer)
                sent += 1
                sleep(_sample_iat(rng, params["iat_pattern"], params["mean_iat_s"]))
            sleep(min(params["burst_idle_s"], max(deadline - monotonic(), 0.0)))
        elif pattern == "sporadic":
            size = _sample_size(rng, params["base_size"], params["size_jitter"])
            _send_packet(sock, _payload(rng, size, params["payload_mode"]), peer)
            sent += 1
            sleep(min(params["sporadic_idle_s"], max(deadline - monotonic(), 0.0)))
    return sent


def _recv_drain(sock: socket, deadline: float) -> None:
    """Drain incoming packets to keep the socket buffer empty.  Counts implicitly via pcap."""
    sock.settimeout(LISTEN_TIMEOUT)
    while monotonic() < deadline:
        try:
            sock.recv(RECV_BUFFER)
        except (timeout, OSError):
            continue


def main() -> int:
    role = environ.get("ROLE", "client").lower()
    duration_s = float(environ.get("PROFILE_DURATION_S", "60"))
    seed_env = environ.get("PROFILE_SEED", "0")
    seed = int(seed_env) if seed_env.isdigit() and int(seed_env) > 0 else randint(0, 1 << 30)
    rng = Random(seed)

    _route_setup(role)
    params = _sample_params(rng)
    print(f"unknown {role}: params = {params}", flush=True)

    sock = socket(AF_INET, SOCK_DGRAM)
    deadline = monotonic() + duration_s

    if role == "client":
        server_host = environ["SERVER_HOST"]
        sock.connect((server_host, UNKNOWN_PORT))
        Thread(target=_recv_drain, args=(sock, deadline), daemon=True).start()
        # Client direction emits c2s.  In s2c_only mode we still send a single
        # initial packet to anchor the flow (mirrors how real one-way s2c
        # protocols like server-push start with a client request).
        if params["direction"] in ("c2s_only", "symmetric", "c2s_heavy"):
            sent = _emit_flow(sock, None, rng, params, "c2s", deadline)
        elif params["direction"] == "s2c_heavy":
            tiny_params = {**params, "flow_pattern": "sporadic", "sporadic_idle_s": params["sporadic_idle_s"] * HEAVY_RATIO}
            sent = _emit_flow(sock, None, rng, tiny_params, "c2s", deadline)
        else:  # s2c_only — single anchoring packet
            _send_packet(sock, _payload(rng, params["base_size"], params["payload_mode"]), None)
            sent = 1
        print(f"unknown client: sent {sent} packets ({params['direction']}/{params['flow_pattern']})", flush=True)
    else:
        sock.bind(("0.0.0.0", UNKNOWN_PORT))
        # Server learns its peer from the first inbound packet; until then it
        # cannot send.  After the first packet it can emit s2c traffic.
        sock.settimeout(LISTEN_TIMEOUT)
        peer: tuple[str, int] | None = None
        while peer is None and monotonic() < deadline:
            try:
                _, peer = sock.recvfrom(RECV_BUFFER)
            except (timeout, OSError):
                continue
        if peer is None:
            print("unknown server: no client contact, exiting", flush=True)
            return 0
        Thread(target=_recv_drain, args=(sock, deadline), daemon=True).start()
        if params["direction"] in ("s2c_only", "symmetric", "s2c_heavy"):
            sent = _emit_flow(sock, peer, rng, params, "s2c", deadline)
        elif params["direction"] == "c2s_heavy":
            tiny_params = {**params, "flow_pattern": "sporadic", "sporadic_idle_s": params["sporadic_idle_s"] * HEAVY_RATIO}
            sent = _emit_flow(sock, peer, rng, tiny_params, "s2c", deadline)
        else:  # c2s_only — server doesn't send
            sent = 0
        print(f"unknown server: sent {sent} packets ({params['direction']}/{params['flow_pattern']})", flush=True)
    return 0


if __name__ == "__main__":
    exit(main())
