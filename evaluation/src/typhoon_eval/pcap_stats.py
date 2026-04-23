"""
Per-pcap statistics for TYPHOON protocol evaluation.

Parses a pcap captured by the observer (tcpdump -i any) and computes stats
in three directions: client→server (c2s), server→client (s2c), and combined.

Direction filtering uses original IP addresses only:
  C→S: src=172.20.0.10  (pre-SNAT; avoids counting the masqueraded copy on eth1)
  S→C: src=172.21.0.10  (un-NATed copy forwarded to client)

This gives exactly one copy of each packet regardless of which interface it
was captured on, so no deduplication is needed.
"""

import math
from collections import Counter
from pathlib import Path

import numpy as np
from scapy.layers.inet import IP, UDP
from scapy.packet import Packet, Raw
from scapy.utils import PcapReader

CLIENT_IP = "172.20.0.10"
SERVER_IP = "172.21.0.10"

# Packets with IP payload larger than this in the C→S direction mark the end
# of the handshake phase and the start of bulk data transfer.
_HANDSHAKE_THRESHOLD = 500


def _entropy(data: bytes) -> float:
    """Shannon entropy of a byte sequence in bits (0–8)."""
    if not data:
        return 0.0
    counts = Counter(data)
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _app_payload(pkt: Packet) -> bytes:
    """Return the application-layer bytes of an IP packet (above TCP/UDP header)."""
    if Raw in pkt:
        return bytes(pkt[Raw])
    if UDP in pkt:
        return bytes(pkt[UDP].payload)
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
    handshake_end_ts is the timestamp of the first large C→S packet;
    used to split entropy into handshake vs data phases.
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

    result: dict = {
        "packet_count": int(len(records)),
        "byte_count":   int(sz_arr.sum()),
        "transmission_time_s": float(ts_arr.max() - ts_arr.min()),
        "packet_size": {
            "mean": float(sz_arr.mean()),
            "std":  float(sz_arr.std()),
            "min":  int(sz_arr.min()),
            "max":  int(sz_arr.max()),
            "p25":  float(np.percentile(sz_arr, 25)),
            "p50":  float(np.percentile(sz_arr, 50)),
            "p75":  float(np.percentile(sz_arr, 75)),
            "p95":  float(np.percentile(sz_arr, 95)),
            "p99":  float(np.percentile(sz_arr, 99)),
        },
        "iat_ms": {
            "mean": float(iats_ms.mean()) if len(iats_ms) else 0.0,
            "std":  float(iats_ms.std())  if len(iats_ms) else 0.0,
            "p50":  float(np.percentile(iats_ms, 50)) if len(iats_ms) else 0.0,
            "p95":  float(np.percentile(iats_ms, 95)) if len(iats_ms) else 0.0,
            "p99":  float(np.percentile(iats_ms, 99)) if len(iats_ms) else 0.0,
        },
        "entropy": {
            "all":       _entropy(all_payload),
            "handshake": _entropy(hs_payload)   if hs_payload   else None,
            "data":      _entropy(data_payload) if data_payload else None,
        },
    }

    if transfer_bytes:
        result["overhead_ratio"] = (int(sz_arr.sum()) - transfer_bytes) / transfer_bytes

    return result


def analyze_pcap(path: Path, transfer_bytes: int | None = None) -> dict[str, dict]:
    """
    Parse *path* and return {"c2s": {...}, "s2c": {...}, "all": {...}}.

    Each value is a dict of computed metrics (empty dict if no packets in that
    direction).  transfer_bytes is used only for the overhead_ratio field.
    """
    c2s: list[tuple[float, int, bytes]] = []
    s2c: list[tuple[float, int, bytes]] = []

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

            bucket.append((float(pkt.time), len(ip), _app_payload(pkt)))

    # Handshake boundary: timestamp of the first large C→S packet.
    handshake_end_ts: float | None = None
    for ts, sz, _ in c2s:
        if sz > _HANDSHAKE_THRESHOLD:
            handshake_end_ts = ts
            break

    all_records = c2s + s2c
    return {
        "c2s": _stats_for(c2s,         transfer_bytes, handshake_end_ts),
        "s2c": _stats_for(s2c,         None,           handshake_end_ts),
        "all": _stats_for(all_records, transfer_bytes, handshake_end_ts),
    }
