"""
Multi-protocol comparison plots from pcap captures.

Reads pcap files from a capture run directory and produces two PNGs:

  {run}_proto_compare.png — six-panel main comparison:
    A) packet-size violin (one violin per protocol)
    B) IAT violin
    C) packet-size CDF
    D) overhead ratio bar chart
    E) byte entropy grouped bars (handshake vs data phases)
    F) protocol metric heatmap (normalized, 5 metrics × all protocols)

  {run}_handshake.png — three-panel handshake metrics:
    A) handshake duration (bar)
    B) handshake packet count (bar)
    C) handshake byte fraction of total (bar)

Per-protocol handshake boundaries come from each Protocol's handshake_sniffer
(defined in protocols.py), so each protocol is measured consistently with its
own connection-setup semantics rather than a shared global window.

Usage (via poe):
    poe proto-compare
    poe proto-compare --run 20260501_120000 --out-dir results/plots

Usage (direct):
    python -m typhoon_eval.proto_compare_plots [--run YYYYMMDD_HHMMSS]
"""

import json
import sys
from pathlib import Path

import click
import matplotlib.patches as mpatches
import matplotlib.pyplot as plt
import numpy as np
from scapy.layers.inet import IP
from scapy.utils import PcapReader

from typhoon_eval.analysis import CAPTURES_ROOT, _latest_run
from typhoon_eval.pcap_stats import CLIENT_IP, SERVER_IP, handshake_end
from typhoon_eval.protocols import BY_NAME, Protocol

_DEFAULT_OUT_DIR = Path(__file__).parent.parent.parent / "results" / "plots"

# Colour per protocol (cycles through a qualitative palette).
_PALETTE = [
    "#e41a1c", "#377eb8", "#4daf4a", "#984ea3", "#ff7f00",
    "#a65628", "#f781bf", "#999999", "#66c2a5", "#fc8d62",
    "#8da0cb", "#e78ac3", "#a6d854", "#ffd92f", "#e5c494", "#b3b3b3",
]


# ── pcap parsing ─────────────────────────────────────────────────────────────

def _parse_pcap(path: Path) -> tuple[list[tuple[float, int, bytes]], list[tuple[float, int, bytes]]]:
    """Return (c2s, s2c) lists of (timestamp_s, ip_size, app_payload)."""
    from scapy.layers.inet import UDP
    from scapy.packet import Raw
    c2s: list[tuple[float, int, bytes]] = []
    s2c: list[tuple[float, int, bytes]] = []
    with PcapReader(str(path)) as reader:
        for pkt in reader:
            if IP not in pkt:
                continue
            ip = pkt[IP]
            ts, sz = float(pkt.time), len(ip)
            payload = bytes(pkt[Raw]) if Raw in pkt else b""
            if ip.src == CLIENT_IP and ip.dst == SERVER_IP:
                c2s.append((ts, sz, payload))
            elif ip.src == SERVER_IP and ip.dst == CLIENT_IP:
                s2c.append((ts, sz, payload))
    return c2s, s2c


def _compute_metrics(
    name: str,
    c2s: list[tuple[float, int, bytes]],
    s2c: list[tuple[float, int, bytes]],
    proto: Protocol | None,
    transfer_bytes: int | None,
) -> dict:
    """Compute all per-protocol metrics from raw packet records."""
    import math
    from collections import Counter

    all_recs = sorted(c2s + s2c, key=lambda r: r[0])
    if not all_recs:
        return {}

    sniffer = proto.handshake_sniffer if proto else None
    hs_end = handshake_end(all_recs, sniffer)

    def _entropy(data: bytes) -> float:
        if not data:
            return 0.0
        counts = Counter(data)
        n = len(data)
        return max(0.0, -sum((c / n) * math.log2(c / n) for c in counts.values()))

    # Size arrays (c2s direction for violins/CDF; all for overhead).
    c2s_sizes = np.array([sz for _, sz, _ in c2s], dtype=float) if c2s else np.array([], dtype=float)
    all_sizes  = np.array([sz for _, sz, _ in all_recs], dtype=float)
    all_ts     = np.array([ts for ts, _, _ in all_recs])

    iats_ms = np.diff(np.sort(all_ts)) * 1000.0

    hs_pkts  = [r for r in all_recs if r[0] < hs_end]  if hs_end else []
    data_pkts = [r for r in all_recs if r[0] >= hs_end] if hs_end else all_recs

    hs_payload   = b"".join(r[2] for r in hs_pkts)
    data_payload = b"".join(r[2] for r in data_pkts)
    all_payload  = b"".join(r[2] for r in all_recs)

    total_bytes = int(all_sizes.sum())
    hs_bytes    = int(sum(r[1] for r in hs_pkts))

    overhead_ratio: float | None = None
    if transfer_bytes and total_bytes > transfer_bytes:
        overhead_ratio = (total_bytes - transfer_bytes) / transfer_bytes

    return {
        "label":        proto.description if proto else name,
        "c2s_sizes":    c2s_sizes,
        "all_sizes":    all_sizes,
        "iats_ms":      iats_ms,
        "entropy_all":  _entropy(all_payload),
        "entropy_hs":   _entropy(hs_payload)   if hs_payload   else None,
        "entropy_data": _entropy(data_payload) if data_payload else None,
        "overhead_ratio": overhead_ratio,
        "hs_duration_s":  (hs_end - all_ts.min()) if hs_end and len(all_ts) > 0 else None,
        "hs_pkt_count":   len(hs_pkts),
        "hs_byte_frac":   (hs_bytes / total_bytes) if total_bytes > 0 else 0.0,
        "total_bytes":    total_bytes,
        "pkt_count":      len(all_recs),
    }


# ── main comparison figure ────────────────────────────────────────────────────

def _plot_main(metrics: list[dict], run_name: str, out_dir: Path) -> None:
    labels     = [m["label"] for m in metrics]
    n          = len(metrics)
    colors     = [_PALETTE[i % len(_PALETTE)] for i in range(n)]
    label_kw   = {"rotation": 45, "ha": "right", "fontsize": 7}

    fig, axes = plt.subplots(2, 3, figsize=(20, 12))
    (ax_sv, ax_iatv, ax_cdf), (ax_oh, ax_ent, ax_heat) = axes

    # ── A: packet-size violin ────────────────────────────────────────────────
    size_data = [m["c2s_sizes"].tolist() if len(m["c2s_sizes"]) > 1 else [0.0] for m in metrics]
    parts = ax_sv.violinplot(size_data, positions=range(n), showmedians=True, showextrema=False)
    for i, body in enumerate(parts["bodies"]):
        body.set_facecolor(colors[i])
        body.set_alpha(0.7)
    parts["cmedians"].set_color("black")
    parts["cmedians"].set_linewidth(1.5)
    ax_sv.set_xticks(range(n))
    ax_sv.set_xticklabels(labels, **label_kw)
    ax_sv.set_ylabel("Packet size (bytes)")
    ax_sv.set_title("A  Packet size (c2s)", fontweight="bold")

    # ── B: IAT violin ────────────────────────────────────────────────────────
    iat_data = [m["iats_ms"].tolist() if len(m["iats_ms"]) > 1 else [0.0] for m in metrics]
    parts = ax_iatv.violinplot(iat_data, positions=range(n), showmedians=True, showextrema=False)
    for i, body in enumerate(parts["bodies"]):
        body.set_facecolor(colors[i])
        body.set_alpha(0.7)
    parts["cmedians"].set_color("black")
    parts["cmedians"].set_linewidth(1.5)
    ax_iatv.set_yscale("log")
    ax_iatv.set_xticks(range(n))
    ax_iatv.set_xticklabels(labels, **label_kw)
    ax_iatv.set_ylabel("IAT (ms, log scale)")
    ax_iatv.set_title("B  Inter-arrival time", fontweight="bold")

    # ── C: packet-size CDF ───────────────────────────────────────────────────
    for i, m in enumerate(metrics):
        sizes = np.sort(m["all_sizes"])
        if len(sizes) == 0:
            continue
        cdf = np.arange(1, len(sizes) + 1) / len(sizes)
        ax_cdf.plot(sizes, cdf, color=colors[i], linewidth=1.2, alpha=0.8, label=m["label"])
    ax_cdf.set_xlabel("Packet size (bytes)")
    ax_cdf.set_ylabel("CDF")
    ax_cdf.set_title("C  Packet size CDF", fontweight="bold")
    ax_cdf.legend(fontsize=6, ncol=2, loc="lower right")
    ax_cdf.grid(True, alpha=0.3)

    # ── D: overhead ratio bar ────────────────────────────────────────────────
    oh_labels = [m["label"] for m in metrics if m["overhead_ratio"] is not None]
    oh_vals   = [m["overhead_ratio"] for m in metrics if m["overhead_ratio"] is not None]
    oh_colors = [colors[i] for i, m in enumerate(metrics) if m["overhead_ratio"] is not None]
    if oh_vals:
        bars = ax_oh.bar(range(len(oh_labels)), oh_vals, color=oh_colors, alpha=0.8, edgecolor="white", linewidth=0.5)
        ax_oh.set_xticks(range(len(oh_labels)))
        ax_oh.set_xticklabels(oh_labels, **label_kw)
        ax_oh.axhline(0, color="black", linewidth=0.8)
        ax_oh.set_ylabel("Overhead ratio")
        ax_oh.set_title("D  Protocol overhead", fontweight="bold")
    else:
        ax_oh.text(0.5, 0.5, "No transfer_bytes data available", ha="center", va="center", transform=ax_oh.transAxes, fontsize=9, color="gray")
        ax_oh.set_title("D  Protocol overhead", fontweight="bold")
        ax_oh.set_visible(True)

    # ── E: byte entropy grouped bars (all / handshake / data) ────────────────
    x = np.arange(n)
    width = 0.26
    ent_all  = [m["entropy_all"]  or 0.0 for m in metrics]
    ent_hs   = [m["entropy_hs"]   or 0.0 for m in metrics]
    ent_data = [m["entropy_data"] or 0.0 for m in metrics]
    ax_ent.bar(x - width, ent_all,  width, color="#555555", alpha=0.8, label="all")
    ax_ent.bar(x,         ent_hs,   width, color="#f39c12", alpha=0.8, label="handshake")
    ax_ent.bar(x + width, ent_data, width, color="#2980b9", alpha=0.8, label="data")
    ax_ent.set_xticks(x)
    ax_ent.set_xticklabels(labels, **label_kw)
    ax_ent.set_ylim(0, 8.5)
    ax_ent.set_ylabel("Shannon entropy (bits)")
    ax_ent.set_title("E  Byte entropy by phase", fontweight="bold")
    ax_ent.legend(fontsize=8)

    # ── F: metric heatmap ────────────────────────────────────────────────────
    metric_names = ["Mean size", "Median IAT", "Size entropy", "Data entropy", "Overhead"]

    def _norm(vals: list[float]) -> np.ndarray:
        arr = np.array(vals, dtype=float)
        lo, hi = np.nanmin(arr), np.nanmax(arr)
        return (arr - lo) / (hi - lo) if hi > lo else np.zeros_like(arr)

    mean_sizes  = [float(m["c2s_sizes"].mean()) if len(m["c2s_sizes"]) > 0 else 0.0 for m in metrics]
    median_iats = [float(np.median(m["iats_ms"])) if len(m["iats_ms"]) > 0 else 0.0 for m in metrics]
    size_ents   = [float(_size_entropy(m["all_sizes"])) for m in metrics]
    data_ents   = [m["entropy_data"] or 0.0 for m in metrics]
    overheads   = [m["overhead_ratio"] if m["overhead_ratio"] is not None else float("nan") for m in metrics]

    heat = np.vstack([
        _norm(mean_sizes),
        _norm(median_iats),
        _norm(size_ents),
        _norm(data_ents),
        _norm(overheads),
    ])

    im = ax_heat.imshow(heat, aspect="auto", cmap="RdYlGn", vmin=0, vmax=1)
    ax_heat.set_xticks(range(n))
    ax_heat.set_xticklabels(labels, **label_kw)
    ax_heat.set_yticks(range(len(metric_names)))
    ax_heat.set_yticklabels(metric_names, fontsize=8)
    fig.colorbar(im, ax=ax_heat, fraction=0.03, pad=0.04)
    ax_heat.set_title("F  Normalized metric heatmap", fontweight="bold")

    fig.suptitle(f"Protocol comparison — {run_name}", fontsize=14, fontweight="bold")
    fig.tight_layout(rect=[0, 0, 1, 0.97])

    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / f"{run_name}_proto_compare.png"
    fig.savefig(path, format="png", bbox_inches="tight", dpi=110)
    plt.close(fig)
    click.echo(f"Saved: {path}")


def _size_entropy(sizes: np.ndarray) -> float:
    """Normalized Shannon entropy of packet-size distribution, scaled to [0, 8]."""
    import math
    from collections import Counter
    counts = Counter(int(s) for s in sizes)
    n_unique = len(counts)
    if n_unique <= 1:
        return 0.0
    n = len(sizes)
    raw = -sum((c / n) * math.log2(c / n) for c in counts.values())
    return raw / math.log2(n_unique) * 8.0


# ── handshake figure ──────────────────────────────────────────────────────────

def _plot_handshake(metrics: list[dict], run_name: str, out_dir: Path) -> None:
    labels = [m["label"] for m in metrics]
    n      = len(metrics)
    colors = [_PALETTE[i % len(_PALETTE)] for i in range(n)]
    label_kw = {"rotation": 45, "ha": "right", "fontsize": 7}

    fig, (ax_dur, ax_pkt, ax_frac) = plt.subplots(1, 3, figsize=(18, 5))

    # ── A: handshake duration ────────────────────────────────────────────────
    durations = [m["hs_duration_s"] if m["hs_duration_s"] is not None else 0.0 for m in metrics]
    ax_dur.bar(range(n), durations, color=colors, alpha=0.8, edgecolor="white", linewidth=0.5)
    ax_dur.set_xticks(range(n))
    ax_dur.set_xticklabels(labels, **label_kw)
    ax_dur.set_ylabel("Duration (s)")
    ax_dur.set_title("A  Handshake duration", fontweight="bold")

    # ── B: handshake packet count ────────────────────────────────────────────
    pkt_counts = [m["hs_pkt_count"] for m in metrics]
    ax_pkt.bar(range(n), pkt_counts, color=colors, alpha=0.8, edgecolor="white", linewidth=0.5)
    ax_pkt.set_xticks(range(n))
    ax_pkt.set_xticklabels(labels, **label_kw)
    ax_pkt.set_ylabel("Packets")
    ax_pkt.set_title("B  Handshake packet count", fontweight="bold")

    # ── C: handshake byte fraction ───────────────────────────────────────────
    hs_fracs = [m["hs_byte_frac"] for m in metrics]
    ax_frac.bar(range(n), hs_fracs, color=colors, alpha=0.8, edgecolor="white", linewidth=0.5)
    ax_frac.set_xticks(range(n))
    ax_frac.set_xticklabels(labels, **label_kw)
    ax_frac.set_ylim(0, 1.0)
    ax_frac.yaxis.set_major_formatter(plt.FuncFormatter(lambda y, _: f"{y:.0%}"))
    ax_frac.set_ylabel("Fraction of total bytes")
    ax_frac.set_title("C  Handshake byte fraction", fontweight="bold")

    fig.suptitle(f"Handshake metrics — {run_name}", fontsize=13, fontweight="bold")
    fig.tight_layout()

    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / f"{run_name}_handshake.png"
    fig.savefig(path, format="png", bbox_inches="tight", dpi=110)
    plt.close(fig)
    click.echo(f"Saved: {path}")


# ── CLI ───────────────────────────────────────────────────────────────────────

@click.command(context_settings={"help_option_names": ["-h", "--help"]})
@click.option("--run", "run_id", default=None, metavar="YYYYMMDD_HHMMSS", help="Run directory (default: most recent).")
@click.option("--out-dir", default=str(_DEFAULT_OUT_DIR), show_default=True, type=click.Path(), help="Output directory for PNGs.")
def main(run_id: str | None, out_dir: str) -> None:
    """Generate multi-protocol comparison plots from pcap captures."""
    if run_id:
        run_dir = CAPTURES_ROOT / f"run_{run_id}"
        if not run_dir.is_dir():
            click.echo(f"Run not found: {run_dir}", err=True)
            sys.exit(1)
    else:
        run_dir = _latest_run()
        if run_dir is None:
            click.echo("No capture runs found. Run 'poe capture' first.", err=True)
            sys.exit(1)

    # Load transfer_bytes metadata if available.
    meta_path = run_dir / "metadata.json"
    metadata: dict = json.loads(meta_path.read_text()) if meta_path.exists() else {}

    pcaps = sorted(run_dir.glob("*.pcap"))
    if not pcaps:
        click.echo(f"No pcap files in {run_dir}", err=True)
        sys.exit(1)

    metrics_list: list[dict] = []
    for pcap in pcaps:
        name = pcap.stem
        proto = BY_NAME.get(name)
        transfer_bytes: int | None = metadata.get(name, {}).get("transfer_bytes")

        click.echo(f"  Parsing {name}…")
        c2s, s2c = _parse_pcap(pcap)
        if not c2s and not s2c:
            continue

        m = _compute_metrics(name, c2s, s2c, proto, transfer_bytes)
        if m:
            metrics_list.append(m)

    if not metrics_list:
        click.echo("No data to plot.", err=True)
        sys.exit(1)

    run_name = run_dir.name
    _plot_main(metrics_list, run_name, Path(out_dir))
    _plot_handshake(metrics_list, run_name, Path(out_dir))


if __name__ == "__main__":
    main()
