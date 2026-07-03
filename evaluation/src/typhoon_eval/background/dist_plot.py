"""Distribution comparison plots for Part 3 corpus.

For each ``(TYPHOON profile, target natural class)`` pair, produces a 4 × 3
panel grid — rows are size c2s, size s2c, IAT c2s, IAT s2c; columns are
histogram, CDF, and a deciles comparison (p10…p90) — so the Barradas-style
percentile feature set is visually grounded alongside the raw distributions.

Each row is annotated with full Barradas summary statistics (min, max, mean,
std, var, kurt, skew + deciles) for both classes so the feature gaps
highlighted by Test A's z-score table are visible as density / tail / decile
differences in the underlying distributions.

Plus, per TYPHOON profile, a per-flow ``packet-index → size`` and
``packet-index → IAT`` plot over the first 200 packets, drawing c2s and s2c
in separate colours so direction-specific packet-index patterns are visible.

Every PNG is emitted alongside a machine-readable ``.json`` companion file
holding the same statistics in a structured form (Barradas moments + deciles
per direction per metric, packet-index sequences per profile per direction).
This lets downstream consumers reproduce the comparison numerically without
re-parsing pcaps.  Use ``--no-json`` to suppress the JSON output.
"""

from __future__ import annotations

from collections import defaultdict
from json import dumps, loads
from pathlib import Path
from sys import exit

import numpy as np
from click import Path as ClickPath
from click import command, option
from matplotlib import pyplot as plt
from matplotlib.axes import Axes
from rich.console import Console
from scapy.layers.inet import IP, UDP
from scapy.utils import PcapReader

from typhoon_eval.background.ml_blending import (
    BARRADAS_HIST_BIN_WIDTH,
    BARRADAS_HIST_MAX,
    BARRADAS_HIST_N_BINS,
    DIRECTIONS,
    PERCENTILES,
    TYPHOON_CLASS,
    _compute_bursts_per_direction,
)

# (TYPHOON profile, target natural class) mapping — imported rather than
# redefined so this module's plots always compare the same pair Test A
# actually trains on.  A previously-duplicated copy of this dict had drifted
# (`silent_idle` pointed at `dns` here vs. `wireguard_idle` in Test A),
# silently comparing distributions against the wrong natural class.
from typhoon_eval.background.ml_open_world import PROFILE_TARGET_CLASS
from typhoon_eval.shared.pcap_stats import _entropy

console = Console()

# Number of packets per flow to plot in the packet-index diagnostic.
POSITION_PLOT_PACKETS = 200
# Histogram bins for size / IAT.
SIZE_BINS = 80
IAT_BINS = 80
# Clamp IAT axis to this percentile so a few network-stall outliers don't
# squash the bulk of the distribution into one bin.
IAT_AXIS_PCTILE = 99
# First N packets per flow used for payload-entropy calculation — matches
# Barradas USENIX'18 (and our ml_blending `_features_stats`).
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
      arrays describes one (run, server_port, direction) flow, matching
      what a passive observer would see in production.  Used by the
      macro-averaging dist-plot helpers and the packet-index diagnostic.
    * ``per_flow_combined[class_key] = [CombinedRec, ...]`` — list of
      ``CombinedRec = (times_s, sizes_B, dir_ids)`` per wire flow, with
      both directions interleaved and sorted by timestamp.  Used for
      burst statistics.
    * ``payload_entropy_per_flow[(class_key, direction)] = [entropy, ...]``
      — one Shannon-entropy value per wire flow per direction.

    Server-port discovery is automatic: for each packet, whichever side
    matches a slot's ``server_ip`` in ``ip_map`` contributes its UDP port
    number as the flow's server-port discriminator.  Every slot — each
    background class and each concurrently-running TYPHOON profile
    instance — normally exposes one server port per run and so contributes
    one flow per run uniformly.  ``raw_default``/``tuned_default`` are the
    exception: they exercise the protocol's genuine auto-fill flow selection
    (1 to ``eval_server.rs::PORTS`` addresses, each independently
    randomised — see `eval_client.rs`), so a single run of either profile
    may contribute 1–3 flows here.
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
        # Map every IP in the slot table to (class_key, role) so we can
        # classify each captured packet's direction without an explicit pair.
        # TYPHOON slots get a per-profile display key so its 8 concurrently
        # running profiles don't collapse into one "typhoon" bucket.
        ip_to_key_role: dict[str, tuple[str, str]] = {}
        for map_key, slot in ip_map.items():
            cls = slot.get("class", map_key)
            key = f"typhoon::{slot['profile']}" if cls == TYPHOON_CLASS else cls
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

    ``_compute_bursts_per_direction`` lives in ``ml_blending`` and still takes
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


def _draw_overlay_hist(ax: Axes, typhoon_vals: list[np.ndarray], target_vals: list[np.ndarray],
                       bins: int, x_max: float | None, xlabel: str,
                       typhoon_label: str, target_label: str) -> None:
    """Draw a per-flow-averaged histogram panel comparing TYPHOON to its target class."""
    if x_max is not None and x_max > 0:
        edges = np.linspace(0, x_max, bins + 1)
    elif typhoon_vals or target_vals:
        all_vals = np.concatenate([v for v in (*typhoon_vals, *target_vals) if len(v)]) if any(len(v) for v in (*typhoon_vals, *target_vals)) else np.array([0.0, 1.0])
        edges = np.linspace(float(all_vals.min()), float(all_vals.max()) or 1.0, bins + 1)
    else:
        edges = np.linspace(0.0, 1.0, bins + 1)
    centers = 0.5 * (edges[:-1] + edges[1:])
    width = edges[1] - edges[0]
    g_density = _macro_hist_density(target_vals,  edges)
    t_density = _macro_hist_density(typhoon_vals, edges)
    drew_any = False
    if g_density.any():
        ax.bar(centers, g_density, width=width, alpha=0.55, label=target_label, color="#3a7bd5", align="center")
        drew_any = True
    if t_density.any():
        ax.bar(centers, t_density, width=width, alpha=0.55, label=typhoon_label, color="#d54a3a", align="center")
        drew_any = True
    if x_max is not None:
        ax.set_xlim(0, x_max)
    ax.set_xlabel(xlabel)
    ax.set_ylabel("density (per-flow avg)")
    if drew_any:
        ax.legend(loc="upper right", fontsize=8)
    ax.grid(alpha=0.25, linestyle="--")


def _draw_overlay_cdf(ax: Axes, typhoon_vals: list[np.ndarray], target_vals: list[np.ndarray],
                      x_max: float | None, xlabel: str,
                      typhoon_label: str, target_label: str) -> None:
    """Draw a per-flow-averaged ECDF panel."""
    all_arrays = [v for v in (*typhoon_vals, *target_vals) if len(v)]
    if not all_arrays:
        return
    pooled = np.concatenate(all_arrays)
    upper = float(x_max) if (x_max is not None and x_max > 0) else float(pooled.max() or 1.0)
    x_grid = np.linspace(0.0, upper, 512)
    drew_any = False
    for vals, label, colour in (
        (target_vals,  target_label,  "#3a7bd5"),
        (typhoon_vals, typhoon_label, "#d54a3a"),
    ):
        cdf = _macro_cdf(vals, x_grid)
        if cdf.any():
            ax.plot(x_grid, cdf, label=label, color=colour, linewidth=1.5)
            drew_any = True
    if x_max is not None:
        ax.set_xlim(0, x_max)
    ax.set_ylim(0, 1)
    ax.set_xlabel(xlabel)
    ax.set_ylabel("cumulative (per-flow avg)")
    if drew_any:
        ax.legend(loc="lower right", fontsize=8)
    ax.grid(alpha=0.25, linestyle="--")


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


def _draw_deciles_overlay(ax: Axes, typhoon_vals: list[np.ndarray], target_vals: list[np.ndarray],
                          ylabel: str, typhoon_label: str, target_label: str) -> None:
    """Draw a deciles comparison panel using per-flow-averaged percentiles ± std across flows."""
    pcts = np.array(PERCENTILES)
    drew_any = False
    for per_flow, label, colour in (
        (target_vals,  target_label,  "#3a7bd5"),
        (typhoon_vals, typhoon_label, "#d54a3a"),
    ):
        per_flow_pcts = [np.array([np.percentile(v, p) for p in pcts]) for v in per_flow if len(v) > 0]
        if not per_flow_pcts:
            continue
        stacked = np.stack(per_flow_pcts, axis=0)
        means = stacked.mean(axis=0)
        stds  = stacked.std(axis=0)
        ax.errorbar(pcts, means, yerr=stds, marker="o", linewidth=1.5, color=colour, label=label, capsize=3)
        drew_any = True
    ax.set_xlabel("percentile (per-flow mean ± std)")
    ax.set_ylabel(ylabel)
    ax.set_xticks(pcts)
    if drew_any:
        ax.legend(loc="upper left", fontsize=8)
    ax.grid(alpha=0.25, linestyle="--")


def _draw_pair(
    profile: str,
    target: str,
    typhoon_per_flow_by_dir: dict[str, list[list[tuple[float, int]]]],
    target_per_flow_by_dir: dict[str, list[list[tuple[float, int]]]],
    typhoon_per_flow_combined: list[list[tuple[float, int, str]]],
    target_per_flow_combined: list[list[tuple[float, int, str]]],
    out_path: Path,
) -> None:
    """Produce the 10 × 3 distribution-comparison figure using per-flow macro averaging.

    Each flow contributes equal weight to every panel — matching the per-flow
    Barradas classifier's view.  Rows: size c2s/s2c/total, IAT c2s/s2c/total,
    burst_pkts c2s/s2c, burst_bytes c2s/s2c.  Columns: histogram, CDF, deciles.
    """
    sizes: dict[str, dict[str, list[np.ndarray]]] = {"typhoon": {}, "target": {}}
    iats:  dict[str, dict[str, list[np.ndarray]]] = {"typhoon": {}, "target": {}}
    for direction in DIRECTIONS:
        sizes["typhoon"][direction] = _per_flow_sizes(typhoon_per_flow_by_dir.get(direction, []))
        sizes["target"][direction]  = _per_flow_sizes(target_per_flow_by_dir.get(direction, []))
        iats["typhoon"][direction]  = _per_flow_iats(typhoon_per_flow_by_dir.get(direction, []))
        iats["target"][direction]   = _per_flow_iats(target_per_flow_by_dir.get(direction, []))

    t_total_per_flow = _total_per_flow_concat(typhoon_per_flow_combined)
    g_total_per_flow = _total_per_flow_concat(target_per_flow_combined)
    sizes["typhoon"]["total"] = _per_flow_sizes(t_total_per_flow)
    sizes["target"]["total"]  = _per_flow_sizes(g_total_per_flow)
    iats["typhoon"]["total"]  = _per_flow_iats(t_total_per_flow)
    iats["target"]["total"]   = _per_flow_iats(g_total_per_flow)

    t_bursts = _burst_per_flow(typhoon_per_flow_combined)
    g_bursts = _burst_per_flow(target_per_flow_combined)

    metric_dirs = ("c2s", "s2c", "total")
    all_size_pool = np.concatenate([v for d in metric_dirs for per_flow in (sizes["typhoon"][d], sizes["target"][d]) for v in per_flow if len(v)]) if any(len(v) for d in metric_dirs for per_flow in (sizes["typhoon"][d], sizes["target"][d]) for v in per_flow) else np.array([])
    all_iat_pool  = np.concatenate([v for d in metric_dirs for per_flow in (iats["typhoon"][d], iats["target"][d]) for v in per_flow if len(v)]) if any(len(v) for d in metric_dirs for per_flow in (iats["typhoon"][d], iats["target"][d]) for v in per_flow) else np.array([])
    size_xmax = float(np.percentile(all_size_pool, 99)) if all_size_pool.size else 0.0
    iat_xmax  = float(np.percentile(all_iat_pool, IAT_AXIS_PCTILE)) if all_iat_pool.size else 0.0
    burst_pkts_pool = np.concatenate([v for d in DIRECTIONS for per_flow in (t_bursts[d]["pkts"], g_bursts[d]["pkts"]) for v in per_flow if len(v)]) if any(len(v) for d in DIRECTIONS for per_flow in (t_bursts[d]["pkts"], g_bursts[d]["pkts"]) for v in per_flow) else np.array([])
    burst_byte_pool = np.concatenate([v for d in DIRECTIONS for per_flow in (t_bursts[d]["bytes"], g_bursts[d]["bytes"]) for v in per_flow if len(v)]) if any(len(v) for d in DIRECTIONS for per_flow in (t_bursts[d]["bytes"], g_bursts[d]["bytes"]) for v in per_flow) else np.array([])
    burst_pkts_max = float(np.percentile(burst_pkts_pool, 99)) if burst_pkts_pool.size else 0.0
    burst_byte_max = float(np.percentile(burst_byte_pool, 99)) if burst_byte_pool.size else 0.0

    # Rows: (metric label, direction, typhoon per-flow arrays, target per-flow arrays, bins, xmax, xlabel).
    row_specs: list[tuple[str, str, list[np.ndarray], list[np.ndarray], int, float, str]] = [
        ("size",        "c2s",   sizes["typhoon"]["c2s"],   sizes["target"]["c2s"],   SIZE_BINS, size_xmax,        "packet size (B)"),
        ("size",        "s2c",   sizes["typhoon"]["s2c"],   sizes["target"]["s2c"],   SIZE_BINS, size_xmax,        "packet size (B)"),
        ("size",        "total", sizes["typhoon"]["total"], sizes["target"]["total"], SIZE_BINS, size_xmax,        "packet size (B)"),
        ("IAT",         "c2s",   iats["typhoon"]["c2s"],    iats["target"]["c2s"],    IAT_BINS,  iat_xmax,         "inter-arrival time (ms)"),
        ("IAT",         "s2c",   iats["typhoon"]["s2c"],    iats["target"]["s2c"],    IAT_BINS,  iat_xmax,         "inter-arrival time (ms)"),
        ("IAT",         "total", iats["typhoon"]["total"],  iats["target"]["total"],  IAT_BINS,  iat_xmax,         "inter-arrival time (ms)"),
        ("burst_pkts",  "c2s",   t_bursts["c2s"]["pkts"],   g_bursts["c2s"]["pkts"],  SIZE_BINS, burst_pkts_max,   "packets per burst"),
        ("burst_pkts",  "s2c",   t_bursts["s2c"]["pkts"],   g_bursts["s2c"]["pkts"],  SIZE_BINS, burst_pkts_max,   "packets per burst"),
        ("burst_bytes", "c2s",   t_bursts["c2s"]["bytes"],  g_bursts["c2s"]["bytes"], SIZE_BINS, burst_byte_max,   "bytes per burst"),
        ("burst_bytes", "s2c",   t_bursts["s2c"]["bytes"],  g_bursts["s2c"]["bytes"], SIZE_BINS, burst_byte_max,   "bytes per burst"),
    ]

    fig, axes = plt.subplots(len(row_specs), 3, figsize=(18, 3.4 * len(row_specs)))
    title_lines = [f"{profile}  vs  {target}  (per-flow macro averaging)"]
    for metric, direction, t_vals, g_vals, _, _, _ in row_specs:
        title_lines.append(f"  [{direction}] TYPHOON {metric}: {_stats_line(t_vals)}")
        title_lines.append(f"  [{direction}] {target} {metric}: {_stats_line(g_vals)}")
    fig.suptitle("\n".join(title_lines), fontsize=8, family="monospace", ha="left", x=0.02)

    for row, (metric, direction, t_vals, g_vals, bins, xmax, xlabel) in enumerate(row_specs):
        _draw_overlay_hist(axes[row, 0], t_vals, g_vals, bins, xmax, xlabel, profile, target)
        axes[row, 0].set_title(f"{metric} distribution — {direction}")
        _draw_overlay_cdf(axes[row, 1], t_vals, g_vals, xmax, xlabel, profile, target)
        axes[row, 1].set_title(f"{metric} CDF — {direction}")
        _draw_deciles_overlay(axes[row, 2], t_vals, g_vals, xlabel, profile, target)
        axes[row, 2].set_title(f"{metric} deciles — {direction}")

    fig.tight_layout(rect=(0, 0, 1, 0.97))
    fig.savefig(out_path, format="pdf", bbox_inches="tight")
    plt.close(fig)


def _draw_histogram_5b(
    profile: str,
    target: str,
    typhoon_per_flow_combined: list[list[tuple[float, int, str]]],
    target_per_flow_combined: list[list[tuple[float, int, str]]],
    out_path: Path,
) -> None:
    """Plot the 300-bin 5-byte packet-length histogram side-by-side, per-flow averaged.

    Each bin corresponds to one ``hist_{i*5}_{(i+1)*5}`` Barradas-alternative
    feature.  Each flow is independently normalized (so per-flow packet count
    has no influence on the figure), and the per-flow densities are then
    averaged with equal weight — same view the per-flow classifier uses.
    """
    bin_centers = np.arange(0, BARRADAS_HIST_MAX, BARRADAS_HIST_BIN_WIDTH) + BARRADAS_HIST_BIN_WIDTH / 2
    t_density = _macro_5b_histogram(_per_flow_sizes(_total_per_flow_concat(typhoon_per_flow_combined)))
    g_density = _macro_5b_histogram(_per_flow_sizes(_total_per_flow_concat(target_per_flow_combined)))

    fig, ax = plt.subplots(1, 1, figsize=(18, 5))
    ax.fill_between(bin_centers, 0, g_density, alpha=0.55, label=target, color="#3a7bd5", step="mid")
    ax.fill_between(bin_centers, 0, t_density, alpha=0.55, label=profile, color="#d54a3a", step="mid")
    ax.set_xlim(0, BARRADAS_HIST_MAX)
    ax.set_xlabel("packet size (B), 5-byte bins → feature hist_<lo>_<hi>")
    ax.set_ylabel("per-flow density (avg across flows)")
    ax.set_title(f"{profile} vs {target} — per-flow 5-byte-bin packet-length histogram (macro avg)")
    ax.legend(loc="upper right", fontsize=9)
    ax.grid(alpha=0.25, linestyle="--")
    fig.tight_layout()
    fig.savefig(out_path, format="pdf", bbox_inches="tight")
    plt.close(fig)


def _draw_packet_index_diagnostic(
    profile_to_flows: dict[tuple[str, str], list[list[tuple[float, int]]]],
    out_path: Path,
) -> None:
    """Per-profile packet-index plots: size and IAT vs position in flow.

    Each TYPHOON flow is drawn as a thin semi-transparent line, with c2s and
    s2c flows in distinct colours so direction-specific packet-index patterns
    (e.g. handshake bursts that only appear in c2s) are visible.
    """
    profiles = sorted({prof for prof, _ in profile_to_flows})
    if not profiles:
        return
    direction_colours = {"c2s": "#d54a3a", "s2c": "#3a7bd5"}
    fig, axes = plt.subplots(len(profiles), 2, figsize=(13, 2.8 * len(profiles)), squeeze=False)
    fig.suptitle(
        f"Per-flow packet-index diagnostic — first {POSITION_PLOT_PACKETS} packets per flow "
        f"(c2s = red, s2c = blue)",
        fontsize=11, y=0.995,
    )
    for row, prof in enumerate(profiles):
        ax_size = axes[row, 0]
        ax_iat = axes[row, 1]
        counts: dict[str, int] = {"c2s": 0, "s2c": 0}
        for direction in DIRECTIONS:
            flows = profile_to_flows.get((prof, direction), [])
            counts[direction] = len(flows)
            for times, sizes in flows:
                w = min(len(times), POSITION_PLOT_PACKETS)
                if w == 0:
                    continue
                window_sizes = sizes[:w]
                window_times = times[:w]
                ax_size.plot(np.arange(w), window_sizes, alpha=0.20, linewidth=0.8,
                             color=direction_colours[direction])
                iats = _iats_ms_from_times(window_times)
                ax_iat.plot(np.arange(1, len(iats) + 1), iats, alpha=0.20, linewidth=0.8,
                            color=direction_colours[direction])
        ax_size.set_xlim(0, POSITION_PLOT_PACKETS)
        ax_size.set_xlabel("packet index in flow")
        ax_size.set_ylabel("size (B)")
        ax_size.set_title(f"{prof}: size vs packet index  (c2s={counts['c2s']}, s2c={counts['s2c']})")
        ax_size.grid(alpha=0.25, linestyle="--")
        ax_iat.set_xlim(0, POSITION_PLOT_PACKETS)
        ax_iat.set_xlabel("packet index in flow")
        ax_iat.set_ylabel("IAT (ms)")
        ax_iat.set_title(f"{prof}: IAT vs packet index  (c2s={counts['c2s']}, s2c={counts['s2c']})")
        ax_iat.grid(alpha=0.25, linestyle="--")
    fig.tight_layout(rect=(0, 0, 1, 0.99))
    fig.savefig(out_path, format="pdf", bbox_inches="tight")
    plt.close(fig)


@command(context_settings={"help_option_names": ["-h", "--help"]})
@option("--corpus-root", default=None, type=ClickPath(),
              help="Corpus root directory (default: results/background).")
@option("--out-dir", default=None, type=ClickPath(),
              help="Output directory for plots (default: <corpus-root>/plots).")
@option("--json/--no-json", "write_json", default=True, show_default=True,
              help="Write machine-readable JSON companion files alongside each PNG.")
def main(corpus_root: str | None, out_dir: str | None, write_json: bool) -> None:
    """Generate size / IAT distribution comparison plots from a finished corpus.

    Each PNG ships with a machine-readable JSON companion (Barradas moments +
    deciles per direction per metric).  ``--no-json`` disables the companion
    files if you only want the figures.
    """
    root = Path(corpus_root) if corpus_root else Path(__file__).parent.parent.parent.parent / "results" / "background"
    if not root.is_dir():
        console.print(f"[red]Corpus root not found:[/red] {root}")
        exit(1)
    out_root = Path(out_dir) if out_dir else root / "plots"
    out_root.mkdir(parents=True, exist_ok=True)

    console.print(f"[bold]Walking corpus[/bold] {root}")
    n_packets_by_pair, per_flow, per_flow_combined, payload_entropy_per_flow = _load_corpus_packets(root)
    n_packets = sum(n_packets_by_pair.values())
    n_flows   = sum(len(v) for v in per_flow.values())
    n_keys    = len({k[0] for k in n_packets_by_pair})
    console.print(f"  Loaded {n_packets} packets from {n_flows} (class, direction) flows across {n_keys} classes")

    for profile, target in PROFILE_TARGET_CLASS.items():
        typhoon_key = f"typhoon::{profile}"
        typhoon_per_flow_by_dir = {d: per_flow.get((typhoon_key, d), []) for d in DIRECTIONS}
        target_per_flow_by_dir  = {d: per_flow.get((target, d), [])      for d in DIRECTIONS}
        typhoon_per_flow_combined = per_flow_combined.get(typhoon_key, [])
        target_per_flow_combined  = per_flow_combined.get(target, [])
        typhoon_payload_entropy_by_dir = {d: payload_entropy_per_flow.get((typhoon_key, d), []) for d in DIRECTIONS}
        target_payload_entropy_by_dir  = {d: payload_entropy_per_flow.get((target, d), [])      for d in DIRECTIONS}
        if not any(typhoon_per_flow_by_dir.values()) or not any(target_per_flow_by_dir.values()):
            t_counts = ", ".join(f"{d}={len(typhoon_per_flow_by_dir[d])}" for d in DIRECTIONS)
            g_counts = ", ".join(f"{d}={len(target_per_flow_by_dir[d])}"  for d in DIRECTIONS)
            console.print(
                f"  [yellow]skip {profile} vs {target} — missing data "
                f"(typhoon flows: {t_counts}; target flows: {g_counts})[/yellow]",
            )
            continue
        out_path = out_root / f"distplot_{profile}_vs_{target}.pdf"
        _draw_pair(
            profile, target,
            typhoon_per_flow_by_dir, target_per_flow_by_dir,
            typhoon_per_flow_combined, target_per_flow_combined, out_path,
        )
        console.print(f"  [green]wrote[/green] {out_path}")
        hist_path = out_root / f"distplot_{profile}_vs_{target}_hist5b.pdf"
        _draw_histogram_5b(
            profile, target,
            typhoon_per_flow_combined, target_per_flow_combined,
            hist_path,
        )
        console.print(f"  [green]wrote[/green] {hist_path}")
        if write_json:
            json_path = out_path.with_suffix(".json")
            json_path.write_text(dumps(
                _pair_to_json(
                    profile, target,
                    typhoon_per_flow_by_dir, target_per_flow_by_dir,
                    typhoon_per_flow_combined, target_per_flow_combined,
                    typhoon_payload_entropy_by_dir, target_payload_entropy_by_dir,
                ),
                indent=2, sort_keys=True,
            ))
            console.print(f"  [green]wrote[/green] {json_path}")

    typhoon_flows_by_profile_direction: dict[tuple[str, str], list[FlowRec]] = {
        (prof.removeprefix("typhoon::"), direction): flows
        for (prof, direction), flows in per_flow.items()
        if prof.startswith("typhoon::")
    }
    if typhoon_flows_by_profile_direction:
        out_path = out_root / "distplot_typhoon_packet_index.pdf"
        _draw_packet_index_diagnostic(typhoon_flows_by_profile_direction, out_path)
        console.print(f"  [green]wrote[/green] {out_path}")
        if write_json:
            json_path = out_path.with_suffix(".json")
            json_path.write_text(dumps(
                _packet_index_to_json(typhoon_flows_by_profile_direction),
                indent=2, sort_keys=True,
            ))
            console.print(f"  [green]wrote[/green] {json_path}")


if __name__ == "__main__":
    main()
