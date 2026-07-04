"""
Per-pcap statistics for TYPHOON protocol evaluation.

Parses a pcap captured by the observer (tcpdump -i any) and computes stats
in three directions: client → server (c2s), server → client (s2c), and combined.

Direction filtering uses original IP addresses only:
  C → S: src=172.20.0.10  (pre-SNAT; avoids counting the masqueraded copy on eth1)
  S → C: src=172.21.0.10  (un-NATed copy forwarded to client)

This gives exactly one copy of each packet regardless of which interface it
was captured on, so no deduplication is needed.

Size measurement: the size field stored per packet is the *transport payload*
length (UDP payload, or TCP segment data) — the bytes above the IP+UDP/TCP
headers.  This excludes a constant 28 B (UDP) or 40+ B (TCP) per-packet
overhead that would otherwise leak transport-layer signal into the
protocol-level statistics.
"""

from collections import Counter
from math import log2
from pathlib import Path

import numpy as np
from scapy.layers.inet import IP, TCP, UDP
from scapy.packet import Packet, Raw
from scapy.utils import PcapReader

from typhoon_eval.shared.protocols import HandshakeSniffer, PacketRecord

CLIENT_IP = "172.20.0.10"
SERVER_IP = "172.21.0.10"

# Fallback: all packets captured within this many seconds of the first packet
# are considered part of the handshake phase when no per-protocol sniffer is set.
_HANDSHAKE_WINDOW_S = 5.0


def _entropy(data: bytes) -> float:
    """Shannon entropy of a byte sequence in bits (0–8)."""
    if not data:
        return 0.0
    counts = Counter(data)
    n = len(data)
    return max(0.0, -sum((c / n) * log2(c / n) for c in counts.values()))


def _size_entropy(sizes: np.ndarray) -> float:
    """Normalized Shannon entropy of the packet-size distribution, scaled to [0, 8].

    Divides raw entropy by log2(n_unique_sizes) so the result is always in [0, 8]
    regardless of how many distinct sizes appear.  A value of 8 means the observed
    sizes are as uniformly distributed as possible; 0 means all packets share one size.
    """
    counts = Counter(int(s) for s in sizes)
    n_unique = len(counts)
    if n_unique <= 1:
        return 0.0
    n = len(sizes)
    raw = -sum((c / n) * log2(c / n) for c in counts.values())
    return raw / log2(n_unique) * 8.0


def _app_payload(pkt: Packet) -> bytes:
    """Return the application-layer bytes of an IP packet (above TCP/UDP header)."""
    if Raw in pkt:
        return bytes(pkt[Raw])
    if UDP in pkt:
        return bytes(pkt[UDP].payload)
    if TCP in pkt:
        return bytes(pkt[TCP].payload)
    return b""


def _stats_for(
    records: list[tuple[float, int, bytes]],
    transfer_bytes: int | None,
    handshake_end_ts: float | None,
) -> dict:
    """
    Compute all metrics for a list of (timestamp, ip_size, app_payload) records.
    transfer_bytes is the application payload the client intended to send;
    used only to compute overhead_ratio (None if unknown).
    handshake_end_ts is the end of the handshake window (first-packet ts +
    _HANDSHAKE_WINDOW_S); used to split entropy into handshake vs data phases.
    """
    if not records:
        return {}

    ts_arr = np.array([r[0] for r in records])
    sz_arr = np.array([r[1] for r in records], dtype=np.int64)

    iats_ms = np.diff(np.sort(ts_arr)) * 1000.0

    all_payload = b"".join(r[2] for r in records)
    if handshake_end_ts is not None:
        hs_payload  = b"".join(r[2] for r in records if r[0] <  handshake_end_ts)
        data_payload = b"".join(r[2] for r in records if r[0] >= handshake_end_ts)
    else:
        hs_payload, data_payload = b"", all_payload

    iat_mean = float(iats_ms.mean()) if len(iats_ms) else 0.0
    iat_std  = float(iats_ms.std())  if len(iats_ms) else 0.0

    result: dict = {
        "packet_count": int(len(records)),
        "byte_count":   int(sz_arr.sum()),
        "transmission_time_s": float(ts_arr.max() - ts_arr.min()),
        "packet_size": {
            "mean":    float(sz_arr.mean()),
            "std":     float(sz_arr.std()),
            "min":     int(sz_arr.min()),
            "max":     int(sz_arr.max()),
            "p5":      float(np.percentile(sz_arr,  5)),
            "p25":     float(np.percentile(sz_arr, 25)),
            "p50":     float(np.percentile(sz_arr, 50)),
            "p75":     float(np.percentile(sz_arr, 75)),
            "p95":     float(np.percentile(sz_arr, 95)),
            "p99":     float(np.percentile(sz_arr, 99)),
            "entropy": _size_entropy(sz_arr),
        },
        "iat_ms": {
            "mean":    iat_mean,
            "std":     iat_std,
            "p5":      float(np.percentile(iats_ms,  5)) if len(iats_ms) else 0.0,
            "p50":     float(np.percentile(iats_ms, 50)) if len(iats_ms) else 0.0,
            "p95":     float(np.percentile(iats_ms, 95)) if len(iats_ms) else 0.0,
            "p99":     float(np.percentile(iats_ms, 99)) if len(iats_ms) else 0.0,
            "entropy": _size_entropy(np.round(iats_ms).astype(np.int64)) if len(iats_ms) else 0.0,
        },
        "entropy": {
            "all":       _entropy(all_payload),
            "handshake": _entropy(hs_payload)   if hs_payload   else None,
            "data":      _entropy(data_payload) if data_payload else None,
        },
        "burstiness":      iat_std / iat_mean if iat_mean > 0 else 0.0,
        "size_regularity": float(len(np.unique(sz_arr))) / len(sz_arr),
    }

    if transfer_bytes:
        total = int(sz_arr.sum())
        result["overhead_ratio"]      = (total - transfer_bytes) / transfer_bytes
        result["goodput_efficiency"]  = transfer_bytes / total if total > 0 else 0.0

    return result


def parse_pcap(path: Path) -> tuple[list[PacketRecord], list[PacketRecord]]:
    """
    Parse *path* and return (c2s, s2c) lists of (timestamp_s, transport_payload_size, app_payload).

    Direction is determined by IP address:
      c2s: src=CLIENT_IP, dst=SERVER_IP
      s2c: src=SERVER_IP, dst=CLIENT_IP

    The size field is the transport-layer payload length (UDP payload, or TCP
    segment data).  Pure control packets (TCP SYN/ACK with no data) get size 0.
    IP and UDP/TCP header bytes are excluded from the size statistic.
    """
    c2s: list[PacketRecord] = []
    s2c: list[PacketRecord] = []

    with PcapReader(str(path)) as reader:
        for pkt in reader:
            if IP not in pkt:
                continue
            ip = pkt[IP]
            src, dst = ip.src, ip.dst

            if src == CLIENT_IP and dst == SERVER_IP:
                bucket = c2s
            elif src == SERVER_IP and dst == CLIENT_IP:
                bucket = s2c
            else:
                continue

            payload = _app_payload(pkt)
            bucket.append((float(pkt.time), len(payload), payload))

    return c2s, s2c


def handshake_end(
    c2s_records: list[PacketRecord],
    s2c_records: list[PacketRecord],
    sniffer: HandshakeSniffer | None = None,
) -> float | None:
    """Return handshake end timestamp, using *sniffer* if given or the global window."""
    if not c2s_records and not s2c_records:
        return None
    if sniffer is not None:
        result = sniffer(c2s_records, s2c_records)
        if result is not None:
            return result
    first_ts = min(r[0] for r in (c2s_records + s2c_records))
    return first_ts + _HANDSHAKE_WINDOW_S


def _fair_transfer(
    stats: dict,
    transfer_bytes: int | None,
    pacing_s: float | None,
) -> None:
    """Annotate a direction's stats in place with the fair transfer metric.

    ``transmission_time_s`` is the pcap wire span for the direction — from the
    first data packet leaving the client to the last one reaching the server,
    so it charges every protocol for all processing that gates the wire (kernel
    driver, userspace crypto, batching), regardless of where it happens.
    Subtracting the deliberate ``pacing_s`` (the same sleep the sender injected)
    yields the *active* transfer time; goodput is then transfer_bytes over that.

    This is measurement-symmetric across in-process senders (TYPHOON, whose
    send path is fully on the measured clock) and cross-process tunnels (whose
    client-side ``transfer_time_s`` stops at the local kernel buffer and hides
    their crypto/forward cost).
    """
    if not stats or pacing_s is None:
        return
    span = stats.get("transmission_time_s", 0.0)
    active = max(span - pacing_s, 1e-6)
    stats["pacing_s"] = pacing_s
    stats["active_time_s"] = active
    if transfer_bytes:
        stats["fair_goodput_mbps"] = transfer_bytes * 8 / active / 1_000_000


def analyze_pcap(
    path: Path,
    transfer_bytes: int | None = None,
    handshake_sniffer: HandshakeSniffer | None = None,
    pacing_c2s_s: float | None = None,
    pacing_s2c_s: float | None = None,
) -> dict[str, dict]:
    """
    Parse *path* and return {"c2s": {...}, "s2c": {...}, "all": {...}}.

    Each value is a dict of computed metrics (empty dict if no packets in that
    direction).  transfer_bytes is used only for the overhead_ratio field.
    handshake_sniffer overrides the default time-window handshake detection.
    pacing_c2s_s / pacing_s2c_s are the deliberate sender sleeps (seconds) for
    each direction; when given, the direction's stats gain ``active_time_s`` and
    ``fair_goodput_mbps`` — the pacing-subtracted, cross-protocol-fair metric.
    """
    c2s, s2c = parse_pcap(path)

    all_records = c2s + s2c
    first_ts  = min(r[0] for r in all_records) if all_records else 0.0
    hs_end_ts = handshake_end(c2s, s2c, handshake_sniffer)

    result = {
        "c2s": _stats_for(c2s,         transfer_bytes, hs_end_ts),
        "s2c": _stats_for(s2c,         None,           hs_end_ts),
        "all": _stats_for(all_records, transfer_bytes, hs_end_ts),
    }

    # Direction-aware metrics (injected into "all" only).
    all_stats = result["all"]
    if all_stats:
        c2s_bytes = result["c2s"].get("byte_count", 0)
        s2c_bytes = result["s2c"].get("byte_count", 0)
        all_stats["direction_asymmetry"] = c2s_bytes / s2c_bytes if s2c_bytes > 0 else 0.0

        signed = sorted(
            [(r[0], r[1]) for r in c2s] + [(r[0], -r[1]) for r in s2c],
            key=lambda x: x[0],
        )
        first100 = [int(sz) for _, sz in signed[:100]]
        all_stats["first_n_sizes"] = first100 + [0] * (100 - len(first100))

        iat_seq: list[float] = [0.0]
        for i in range(1, min(100, len(signed))):
            dt_ms = (signed[i][0] - signed[i - 1][0]) * 1000.0
            sign = 1.0 if signed[i][1] > 0 else -1.0
            iat_seq.append(round(sign * dt_ms, 4))
        all_stats["first_n_iats"] = iat_seq + [0.0] * (100 - len(iat_seq))

        # Burst features: contiguous same-direction runs.
        dirs = [1 if sz > 0 else -1 for _, sz in signed]
        bursts: list[tuple[int, int]] = []
        if dirs:
            cur_dir, pkt_cnt, byte_cnt = dirs[0], 1, abs(signed[0][1])
            for i in range(1, len(dirs)):
                if dirs[i] == cur_dir:
                    pkt_cnt += 1
                    byte_cnt += abs(signed[i][1])
                else:
                    bursts.append((pkt_cnt, byte_cnt))
                    cur_dir, pkt_cnt, byte_cnt = dirs[i], 1, abs(signed[i][1])
            bursts.append((pkt_cnt, byte_cnt))

        burst_count = len(bursts)
        all_stats["burst_count"]      = burst_count
        all_stats["mean_burst_pkt"]   = sum(b[0] for b in bursts) / burst_count if burst_count else 0.0
        all_stats["mean_burst_bytes"] = sum(b[1] for b in bursts) / burst_count if burst_count else 0.0

        if hs_end_ts is not None:
            total_bytes = all_stats["byte_count"]
            hs_bytes    = sum(abs(sz) for ts, sz in signed if ts < hs_end_ts)
            hs_pkt_count = sum(1 for ts, _ in signed if ts < hs_end_ts)
            all_stats["hs_duration_s"] = hs_end_ts - first_ts
            all_stats["hs_pkt_count"]  = hs_pkt_count
            all_stats["hs_byte_frac"]  = hs_bytes / total_bytes if total_bytes else 0.0

    # Fair, pacing-subtracted transfer metric per direction; surface the
    # data-bearing direction's result into "all" for the summary/plots.
    _fair_transfer(result["c2s"], transfer_bytes, pacing_c2s_s)
    _fair_transfer(result["s2c"], None, pacing_s2c_s)
    if all_stats:
        data_dir = result["c2s"] if result["c2s"].get("active_time_s") else result["s2c"]
        if data_dir.get("active_time_s") is not None:
            all_stats["active_time_s"]    = data_dir["active_time_s"]
            all_stats["pacing_s"]         = data_dir.get("pacing_s")
            all_stats["fair_goodput_mbps"] = data_dir.get("fair_goodput_mbps")

    return result
