"""Aggregation and statistics for the Part 3 distribution comparison.

Pure compute layer for ``dist_plot``: walks the corpus into per-flow records,
computes the per-flow-averaged (macro) histograms / CDFs / Barradas moment
statistics, and builds the machine-readable JSON companion documents.  No
matplotlib here — the drawing and CLI live in ``dist_plot.py``.
"""

from __future__ import annotations

from collections import defaultdict
from json import loads
from pathlib import Path

import numpy as np
from rich.console import Console
from scapy.layers.inet import IP, UDP
from scapy.utils import PcapReader

from typhoon_eval.background.features import (
    BARRADAS_HIST_BIN_WIDTH,
    BARRADAS_HIST_MAX,
    BARRADAS_HIST_N_BINS,
    DIRECTIONS,
    PERCENTILES,
    TYPHOON_CLASS,
    _compute_bursts_per_direction,
)
from typhoon_eval.shared.pcap_stats import _entropy

console = Console()

# Number of packets per flow retained in the packet-index diagnostic (plot + JSON).
POSITION_PLOT_PACKETS = 200
# First N packets per flow used for payload-entropy calculation — matches
# Barradas USENIX'18 (and our features `_features_stats`).
PAYLOAD_ENTROPY_WINDOW = 200
# Minimum packets per flow required to compute IATs, percentiles, or burst stats.
MIN_SAMPLES_FOR_STATS = 2

# Direction encoding for ``per_flow_combined`` arrays.
_DIR_ID_C2S = np.int8(0)
_DIR_ID_S2C = np.int8(1)
_DIR_ID_TO_NAME = {0: "c2s", 1: "s2c"}

# Per-flow record types after ingest.  Both are tuples of NumPy arrays:
#   * ``FlowRec``      = ``(times_s: float64[N], sizes_B: int32[N])``
#   * ``CombinedRec``  = ``(times_s: float64[N], sizes_B: int32[N], dirs: int8[N])``
FlowRec = tuple[np.ndarray, np.ndarray]
CombinedRec = tuple[np.ndarray, np.ndarray, np.ndarray]


def _load_corpus_packets(
    corpus_root: Path,
) -> tuple[
    dict[tuple[str, str], int],
    dict[tuple[str, str], list[FlowRec]],
    dict[str, list[CombinedRec]],
    dict[tuple[str, str], list[float]],
]:
    """Walk every run dir and assemble per-flow records in three layouts.

    Returns ``(n_packets_by_pair, per_flow_by_class_dir,
    per_flow_combined_by_class, payload_entropy_per_flow_by_class_dir)``:

    * ``n_packets_by_pair[(class_key, direction)] = int`` — running count
      of accepted packets per (class, direction).  Used for the summary
      line only; storing the underlying tuples roughly doubled peak
      memory on large corpora for zero plotting benefit.
    * ``per_flow[(class_key, direction)] = [FlowRec, ...]`` — list of one
      ``FlowRec = (times_s, sizes_B)`` per wire flow.  Each pair of NumPy
      arrays describes one (run, server_port, direction) flow.  TYPHOON's
      1–3 flows per measurement appear as 1–3 separate entries here,
      matching what a passive observer would see in production.  Used by
      the macro-averaging dist-plot helpers and the packet-index
      diagnostic.
    * ``per_flow_combined[class_key] = [CombinedRec, ...]`` — list of
      ``CombinedRec = (times_s, sizes_B, dir_ids)`` per wire flow, with
      both directions interleaved and sorted by timestamp.  Used for
      burst statistics.
    * ``payload_entropy_per_flow[(class_key, direction)] = [entropy, ...]``
      — one Shannon-entropy value per wire flow per direction.

    Server-port discovery is automatic: for each packet, whichever side
    matches the protocol's ``server_ip`` from ``ip_map`` contributes its
    UDP port number as the flow's server-port discriminator.  Background
    classes typically expose one server port and contribute one flow per
    run; TYPHOON exposes up to three (``eval_server.rs::PORTS``) and the
    client may open any subset of them, so it contributes 1–3 flows per
    run uniformly.
    """

    n_packets_by_pair: dict[tuple[str, str], int] = defaultdict(int)
    per_flow: dict[tuple[str, str], list[FlowRec]] = defaultdict(list)
    per_flow_combined: dict[str, list[CombinedRec]] = defaultdict(list)
    payload_entropy_per_flow: dict[tuple[str, str], list[float]] = defaultdict(list)

    run_dirs = sorted(corpus_root.glob("run_*"))
    n_total = len(run_dirs)
    for i, run_dir in enumerate(run_dirs, start=1):
        if i % 100 == 0 or i == n_total:
            console.print(f"  walked {i}/{n_total} runs", highlight=False)
        meta_path = run_dir / "metadata.json"
        if not meta_path.exists():
            continue
        meta = loads(meta_path.read_text())
        ip_map = meta.get("ip_map", {})
        typhoon_profile = meta.get("typhoon_profile", "unknown")
        # Map every IP in the slot table to (class_key, role) so we can
        # classify each captured packet's direction without an explicit pair.
        ip_to_key_role: dict[str, tuple[str, str]] = {}
        for cls, slot in ip_map.items():
            key = f"typhoon::{typhoon_profile}" if cls == TYPHOON_CLASS else cls
            ip_to_key_role[slot["client_ip"]] = (key, "client")
            ip_to_key_role[slot["server_ip"]] = (key, "server")

        for pcap in run_dir.glob("*.pcap"):
            # Per-(class_key, server_port, direction) packet buffers — one wire
            # flow per server port.  These are scratch buffers that live for the
            # duration of this pcap; we convert them to compact NumPy arrays
            # before transferring ownership to the persistent dicts below.
            ts_buf:   dict[tuple[str, int, str], list[float]] = defaultdict(list)
            size_buf: dict[tuple[str, int, str], list[int]]   = defaultdict(list)
            comb_ts_buf:   dict[tuple[str, int], list[float]] = defaultdict(list)
            comb_size_buf: dict[tuple[str, int], list[int]]   = defaultdict(list)
            comb_dir_buf:  dict[tuple[str, int], list[int]]   = defaultdict(list)
            payloads_in_pcap: dict[tuple[str, int, str], list[bytes]] = defaultdict(list)
            with PcapReader(str(pcap)) as reader:
                for pkt in reader:
                    if IP not in pkt or UDP not in pkt:
                        # TYPHOON is UDP-only — skip ICMP / ARP / IPv6-ND / TCP
                        # observer noise that would otherwise land in the
                        # zero-length-payload bin and create a fake discriminator.
                        continue
                    ip_layer = pkt[IP]
                    src_meta = ip_to_key_role.get(ip_layer.src)
                    dst_meta = ip_to_key_role.get(ip_layer.dst)
                    if src_meta is None or dst_meta is None or src_meta[0] != dst_meta[0]:
                        continue
                    class_key = src_meta[0]
                    udp_layer = pkt[UDP]
                    if src_meta[1] == "client" and dst_meta[1] == "server":
                        direction = "c2s"
                        dir_id = _DIR_ID_C2S
                        server_port = int(udp_layer.dport)
                    elif src_meta[1] == "server" and dst_meta[1] == "client":
                        direction = "s2c"
                        dir_id = _DIR_ID_S2C
                        server_port = int(udp_layer.sport)
                    else:
                        continue
                    payload_bytes = bytes(udp_layer.payload)
                    payload_size = len(payload_bytes)
                    ts = float(pkt.time)
                    flow_key = (class_key, server_port, direction)
                    comb_key = (class_key, server_port)
                    ts_buf[flow_key].append(ts)
                    size_buf[flow_key].append(payload_size)
                    comb_ts_buf[comb_key].append(ts)
                    comb_size_buf[comb_key].append(payload_size)
                    comb_dir_buf[comb_key].append(dir_id)
                    if len(payloads_in_pcap[flow_key]) < PAYLOAD_ENTROPY_WINDOW:
                        payloads_in_pcap[flow_key].append(payload_bytes)

            for flow_key, tlist in ts_buf.items():
                if len(tlist) < MIN_SAMPLES_FOR_STATS:
                    continue
                cls, _port, direction = flow_key
                times  = np.asarray(tlist,           dtype=np.float64)
                sizes  = np.asarray(size_buf[flow_key], dtype=np.int32)
                order  = np.argsort(times, kind="stable")
                times  = times[order]
                sizes  = sizes[order]
                pair_key = (cls, direction)
                n_packets_by_pair[pair_key] += len(times)
                per_flow[pair_key].append((times, sizes))
                payload_entropy_per_flow[pair_key].append(
                    _entropy(b"".join(payloads_in_pcap[flow_key])),
                )
            for comb_key, tlist in comb_ts_buf.items():
                if len(tlist) < MIN_SAMPLES_FOR_STATS:
                    continue
                cls, _port = comb_key
                times = np.asarray(tlist,                 dtype=np.float64)
                sizes = np.asarray(comb_size_buf[comb_key], dtype=np.int32)
                dirs  = np.asarray(comb_dir_buf[comb_key],  dtype=np.int8)
                order = np.argsort(times, kind="stable")
                per_flow_combined[cls].append((times[order], sizes[order], dirs[order]))

    return n_packets_by_pair, per_flow, per_flow_combined, payload_entropy_per_flow


def _iats_ms_from_times(times: np.ndarray) -> np.ndarray:
    """Inter-arrival times in milliseconds from one flow's timestamp-sorted array."""
    if len(times) < MIN_SAMPLES_FOR_STATS:
        return np.array([])
    return np.diff(times) * 1000.0


def _burst_per_flow(
    per_flow_combined: list[CombinedRec],
) -> dict[str, dict[str, list[np.ndarray]]]:
    """Per-flow burst pkts/bytes arrays for each direction (one ndarray per flow).

    Returns ``{direction: {"pkts": [flow0_pkts, flow1_pkts, …], "bytes": [...]}}``
    so downstream macro-averaging can treat each flow as a single sample.

    ``_compute_bursts_per_direction`` lives in ``features`` and still takes
    ``list[(ts, size, direction_str)]``, so we materialise that representation
    one flow at a time — bounded scope, no corpus-wide memory blow-up.
    """
    out: dict[str, dict[str, list[np.ndarray]]] = {d: {"pkts": [], "bytes": []} for d in DIRECTIONS}
    for times, sizes, dirs in per_flow_combined:
        timeline = [
            (float(t), int(s), _DIR_ID_TO_NAME[int(d)])
            for t, s, d in zip(times, sizes, dirs, strict=True)
        ]
        bursts = _compute_bursts_per_direction(timeline)
        for d in DIRECTIONS:
            if len(bursts[d]["pkts"]) > 0:
                out[d]["pkts"].append(bursts[d]["pkts"])
                out[d]["bytes"].append(bursts[d]["bytes"])
    return out


def _per_flow_sizes(per_flow_records: list[FlowRec]) -> list[np.ndarray]:
    """One ndarray of packet sizes per flow."""
    return [sizes for _times, sizes in per_flow_records if len(sizes) > 0]


def _per_flow_iats(per_flow_records: list[FlowRec]) -> list[np.ndarray]:
    """One ndarray of intra-flow IATs (ms) per flow.  Flows with <2 packets are dropped."""
    return [a for a in (_iats_ms_from_times(times) for times, _sizes in per_flow_records) if len(a) > 0]


def _total_per_flow_concat(
    per_flow_combined: list[CombinedRec],
) -> list[FlowRec]:
    """Per-flow combined records reduced to (times, sizes) for total-flow IAT stats."""
    return [(times, sizes) for times, sizes, _dirs in per_flow_combined]


def _macro_hist_density(per_flow_vals: list[np.ndarray], edges: np.ndarray) -> np.ndarray:
    """Per-flow normalized histogram averaged across flows (equal weight per flow)."""
    bin_widths = np.diff(edges)
    densities: list[np.ndarray] = []
    for vals in per_flow_vals:
        if len(vals) == 0:
            continue
        counts, _ = np.histogram(vals, bins=edges)
        total = counts.sum()
        if total == 0:
            continue
        densities.append(counts / total / bin_widths)
    if not densities:
        return np.zeros(len(edges) - 1)
    return np.mean(densities, axis=0)


def _macro_cdf(per_flow_vals: list[np.ndarray], x_grid: np.ndarray) -> np.ndarray:
    """Per-flow ECDF evaluated on `x_grid`, averaged across flows."""
    cdfs: list[np.ndarray] = []
    for vals in per_flow_vals:
        if len(vals) == 0:
            continue
        sorted_vals = np.sort(vals)
        cdfs.append(np.searchsorted(sorted_vals, x_grid, side="right") / len(sorted_vals))
    if not cdfs:
        return np.zeros(len(x_grid))
    return np.mean(cdfs, axis=0)


def _macro_stats(per_flow_vals: list[np.ndarray]) -> dict[str, object]:
    """Per-flow Barradas stats averaged across flows.

    Empty flows are skipped.  Each surviving flow contributes equal weight to
    every reported metric, matching what the per-flow classifier sees.
    """
    per_flow: list[dict[str, float]] = []
    for vals in per_flow_vals:
        if len(vals) == 0:
            continue
        arr = vals.astype(np.float64)
        mean = float(arr.mean())
        std = float(arr.std())
        if std > 0:
            z = (arr - mean) / std
            skew = float(np.mean(z ** 3))
            kurt = float(np.mean(z ** 4) - 3.0)
        else:
            skew = kurt = 0.0
        per_flow.append({
            "n":       float(len(vals)),
            "mean":    mean,
            "std":     std,
            "var":     float(arr.var()),
            "min":     float(arr.min()),
            "max":     float(arr.max()),
            "kurt":    kurt,
            "skew":    skew,
            **{f"p{p}": float(np.percentile(arr, p)) for p in PERCENTILES},
        })
    if not per_flow:
        return {"n_flows": 0, "n_packets": 0}
    keys = ("mean", "std", "var", "min", "max", "kurt", "skew")
    out: dict[str, object] = {
        "n_flows":   len(per_flow),
        "n_packets": int(sum(s["n"] for s in per_flow)),
    }
    for k in keys:
        out[k] = float(np.mean([s[k] for s in per_flow]))
    out["deciles"] = {f"p{p}": float(np.mean([s[f"p{p}"] for s in per_flow])) for p in PERCENTILES}
    return out


def _stats_line(per_flow_vals: list[np.ndarray]) -> str:
    """One-line per-flow-averaged summary used in the figure suptitle."""
    s = _macro_stats(per_flow_vals)
    if s["n_flows"] == 0:
        return "flows=0"
    return (
        f"flows={s['n_flows']} packets={s['n_packets']} mean={s['mean']:.1f} std={s['std']:.1f} "
        f"min={s['min']:.1f} max={s['max']:.1f} kurt={s['kurt']:+.2f} skew={s['skew']:+.2f}  "
        f"p10={s['deciles']['p10']:.1f} p50={s['deciles']['p50']:.1f} p90={s['deciles']['p90']:.1f}"
    )


def _macro_5b_histogram(per_flow_sizes_total: list[np.ndarray]) -> np.ndarray:
    """Per-flow normalized 5-byte-bin packet-length histogram averaged across flows."""
    edges = np.arange(0, BARRADAS_HIST_MAX + BARRADAS_HIST_BIN_WIDTH, BARRADAS_HIST_BIN_WIDTH)
    fractions: list[np.ndarray] = []
    for sizes in per_flow_sizes_total:
        if len(sizes) == 0:
            continue
        counts, _ = np.histogram(sizes, bins=edges)
        total = counts.sum()
        if total == 0:
            continue
        fractions.append(counts.astype(np.float64) / total)
    if not fractions:
        return np.zeros(BARRADAS_HIST_N_BINS)
    return np.mean(fractions, axis=0)


def _pair_to_json(
    profile: str,
    target: str,
    typhoon_per_flow_by_dir: dict[str, list[list[tuple[float, int]]]],
    target_per_flow_by_dir: dict[str, list[list[tuple[float, int]]]],
    typhoon_per_flow_combined: list[list[tuple[float, int, str]]],
    target_per_flow_combined: list[list[tuple[float, int, str]]],
    typhoon_payload_entropy_by_dir: dict[str, list[float]],
    target_payload_entropy_by_dir: dict[str, list[float]],
) -> dict[str, object]:
    """Full Barradas-aligned JSON companion document for one ``(profile, target)`` pair.

    Every reported statistic is computed per-flow first, then averaged across
    flows so each flow has equal weight — matching what the per-flow Barradas
    classifier sees.  The 5-byte-bin histogram is similarly the per-flow
    normalized histogram averaged across flows.
    """
    directions_block: dict[str, object] = {}

    for direction in DIRECTIONS:
        t_flows = typhoon_per_flow_by_dir.get(direction, [])
        g_flows = target_per_flow_by_dir.get(direction, [])
        t_sizes = _per_flow_sizes(t_flows)
        g_sizes = _per_flow_sizes(g_flows)
        t_iats  = _per_flow_iats(t_flows)
        g_iats  = _per_flow_iats(g_flows)
        # Per-flow payload entropy already arrives as one value per flow, so
        # we wrap each value as its own 1-length array to reuse `_macro_stats`.
        t_pe = [np.array([e]) for e in typhoon_payload_entropy_by_dir.get(direction, [])]
        g_pe = [np.array([e]) for e in target_payload_entropy_by_dir.get(direction, [])]
        directions_block[direction] = {
            "size":                     {"typhoon": _macro_stats(t_sizes), "target": _macro_stats(g_sizes)},
            "iat_ms":                   {"typhoon": _macro_stats(t_iats),  "target": _macro_stats(g_iats)},
            "payload_entropy_per_flow": {"typhoon": _macro_stats(t_pe),    "target": _macro_stats(g_pe)},
        }

    t_bursts = _burst_per_flow(typhoon_per_flow_combined)
    g_bursts = _burst_per_flow(target_per_flow_combined)
    for direction in DIRECTIONS:
        directions_block[direction]["burst_pkts"] = {
            "typhoon": _macro_stats(t_bursts[direction]["pkts"]),
            "target":  _macro_stats(g_bursts[direction]["pkts"]),
        }
        directions_block[direction]["burst_bytes"] = {
            "typhoon": _macro_stats(t_bursts[direction]["bytes"]),
            "target":  _macro_stats(g_bursts[direction]["bytes"]),
        }

    t_total_per_flow = _total_per_flow_concat(typhoon_per_flow_combined)
    g_total_per_flow = _total_per_flow_concat(target_per_flow_combined)
    t_total_sizes = _per_flow_sizes(t_total_per_flow)
    g_total_sizes = _per_flow_sizes(g_total_per_flow)
    t_total_iats  = _per_flow_iats(t_total_per_flow)
    g_total_iats  = _per_flow_iats(g_total_per_flow)
    directions_block["total"] = {
        "size":   {"typhoon": _macro_stats(t_total_sizes), "target": _macro_stats(g_total_sizes)},
        "iat_ms": {"typhoon": _macro_stats(t_total_iats),  "target": _macro_stats(g_total_iats)},
    }

    return {
        "profile": profile,
        "target":  target,
        "directions": directions_block,
        "histogram_5b": {
            "bin_width":  BARRADAS_HIST_BIN_WIDTH,
            "n_bins":     BARRADAS_HIST_N_BINS,
            "max_size":   BARRADAS_HIST_MAX,
            "aggregation": "per-flow density averaged across flows",
            "typhoon":    _macro_5b_histogram(t_total_sizes).tolist(),
            "target":     _macro_5b_histogram(g_total_sizes).tolist(),
        },
    }


def _packet_index_to_json(
    profile_to_flows: dict[tuple[str, str], list[FlowRec]],
) -> dict[str, object]:
    """Build the JSON companion document for the packet-index diagnostic.

    Truncates each flow to :data:`POSITION_PLOT_PACKETS` packets so the JSON
    matches what the figure plots.  Schema:

    .. code-block:: json

        {
          "max_packets_per_flow": 200,
          "profiles": {
            "as_quic_d": {
              "c2s": [[size_pkt0, size_pkt1, …], …],
              "s2c": [[…], …]
            },
            …
          }
        }
    """
    profiles = sorted({prof for prof, _ in profile_to_flows})
    out: dict[str, object] = {"max_packets_per_flow": POSITION_PLOT_PACKETS, "profiles": {}}
    profiles_block: dict[str, dict[str, list[list[int]]]] = {}
    for prof in profiles:
        per_dir: dict[str, list[list[int]]] = {}
        for direction in DIRECTIONS:
            flows = profile_to_flows.get((prof, direction), [])
            per_dir[direction] = [
                sizes[:POSITION_PLOT_PACKETS].tolist()
                for _times, sizes in flows
            ]
        profiles_block[prof] = per_dir
    out["profiles"] = profiles_block
    return out
