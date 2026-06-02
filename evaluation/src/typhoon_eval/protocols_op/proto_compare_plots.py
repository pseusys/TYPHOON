"""
PART 2 — Operational comparison of UDP/TCP protocols from pcap captures.

Compares throughput, overhead, goodput efficiency, byte entropy, burstiness,
and handshake characteristics across all protocols in a capture run.  This
deliberately does **not** include detectability or fingerprint analysis — that
question belongs in PART 3 (background-blending evaluation), where TYPHOON
traffic is compared against natural UDP traffic rather than against other
tunnel/VPN protocols.  Putting tunnel-vs-tunnel ML accuracy here would frame
the wrong question.

Reads pcap files from a capture run directory and produces:

  {run}_proto_compare.png  — six-panel operational comparison
    A) packet-size CDF
    B) inter-arrival-time CDF (log x-axis)
    C) throughput vs. goodput-efficiency scatter
    D) protocol-overhead bar chart
    E) byte entropy by phase (all / handshake / data)
    F) operational metric heatmap (normalised, 6 metrics × all protocols)

  {run}_handshake.png — three-panel handshake metrics:
    A) handshake duration (bar)
    B) handshake packet count (bar)
    C) handshake byte fraction (bar)

  {run}_compare_table.md — markdown comparison table

Per-protocol handshake boundaries come from each Protocol's handshake_sniffer
(see shared/protocols.py).

Usage (via poe):
    poe proto-compare
    poe proto-compare --run 20260501_120000 --out-dir results/plots
"""

from json import loads
from math import isnan
from pathlib import Path
from sys import exit

from click import Path as ClickPath
from click import command, echo, option
from matplotlib import pyplot as plt
from numpy import arange, array, diff, nanmax, nanmin, ndarray, sort, vstack, zeros_like

from typhoon_eval.shared.analysis import CAPTURES_ROOT, _latest_run
from typhoon_eval.shared.pcap_stats import _entropy, handshake_end, parse_pcap
from typhoon_eval.shared.protocols import BY_NAME, Protocol

_DEFAULT_OUT_DIR = Path(__file__).parent.parent.parent.parent / "results" / "plots"

_PALETTE = [
    "#e41a1c", "#377eb8", "#4daf4a", "#984ea3", "#ff7f00",
    "#a65628", "#f781bf", "#999999", "#66c2a5", "#fc8d62",
    "#8da0cb", "#e78ac3", "#a6d854", "#ffd92f", "#e5c494", "#b3b3b3",
]


def _compute_metrics(
    name: str,
    c2s: list[tuple[float, int, bytes]],
    s2c: list[tuple[float, int, bytes]],
    proto: Protocol | None,
    transfer_bytes: int | None,
) -> dict:
    """Compute operational metrics for one protocol from raw packet records."""
    all_recs = sorted(c2s + s2c, key=lambda r: r[0])
    if not all_recs:
        return {}

    sniffer = proto.handshake_sniffer if proto else None
    hs_end = handshake_end(c2s, s2c, sniffer)

    all_sizes = array([sz for _, sz, _ in all_recs], dtype=float)
    all_ts    = array([ts for ts, _, _ in all_recs])
    iats_ms   = diff(sort(all_ts)) * 1000.0

    hs_pkts   = [r for r in all_recs if r[0] < hs_end]  if hs_end else []
    data_pkts = [r for r in all_recs if r[0] >= hs_end] if hs_end else all_recs

    hs_payload   = b"".join(r[2] for r in hs_pkts)
    data_payload = b"".join(r[2] for r in data_pkts)
    all_payload  = b"".join(r[2] for r in all_recs)

    total_bytes = int(all_sizes.sum())
    hs_bytes    = int(sum(r[1] for r in hs_pkts))

    overhead_ratio: float | None = None
    goodput_efficiency: float | None = None
    if transfer_bytes and total_bytes > 0:
        if total_bytes > transfer_bytes:
            overhead_ratio = (total_bytes - transfer_bytes) / transfer_bytes
        goodput_efficiency = transfer_bytes / total_bytes

    tx_time_s = float(all_ts.max() - all_ts.min()) if len(all_ts) > 1 else 0.0
    throughput_mbps = (total_bytes * 8 / tx_time_s / 1e6) if tx_time_s > 0 else 0.0

    iat_mean = float(iats_ms.mean()) if len(iats_ms) else 0.0
    iat_std  = float(iats_ms.std())  if len(iats_ms) else 0.0
    burstiness = iat_std / iat_mean if iat_mean > 0 else 0.0

    c2s_bytes = sum(r[1] for r in c2s)
    s2c_bytes = sum(r[1] for r in s2c)
    direction_asymmetry = c2s_bytes / s2c_bytes if s2c_bytes > 0 else 0.0

    return {
        "label":               proto.description if proto else name,
        "all_sizes":           all_sizes,
        "iats_ms":             iats_ms,
        "entropy_all":         _entropy(all_payload),
        "entropy_hs":          _entropy(hs_payload)   if hs_payload   else None,
        "entropy_data":        _entropy(data_payload) if data_payload else None,
        "overhead_ratio":      overhead_ratio,
        "goodput_efficiency":  goodput_efficiency,
        "throughput_mbps":     throughput_mbps,
        "burstiness":          burstiness,
        "direction_asymmetry": direction_asymmetry,
        "hs_duration_s":       (hs_end - all_ts.min()) if hs_end and len(all_ts) > 0 else None,
        "hs_pkt_count":        len(hs_pkts),
        "hs_byte_frac":        (hs_bytes / total_bytes) if total_bytes > 0 else 0.0,
        "total_bytes":         total_bytes,
        "pkt_count":           len(all_recs),
    }


def _plot_main(metrics: list[dict], run_name: str, out_dir: Path) -> None:
    labels   = [m["label"] for m in metrics]
    n        = len(metrics)
    colors   = [_PALETTE[i % len(_PALETTE)] for i in range(n)]
    label_kw = {"rotation": 45, "ha": "right", "fontsize": 7}

    fig, axes = plt.subplots(2, 3, figsize=(20, 12))
    (ax_size_cdf, ax_iat_cdf, ax_thru), (ax_oh, ax_ent, ax_heat) = axes

    # A — packet size CDF
    for i, m in enumerate(metrics):
        sizes = sort(m["all_sizes"])
        if len(sizes) == 0:
            continue
        cdf = arange(1, len(sizes) + 1) / len(sizes)
        ax_size_cdf.plot(sizes, cdf, color=colors[i], linewidth=1.2, alpha=0.8, label=m["label"])
    ax_size_cdf.set_xlabel("Transport-payload size (bytes)")
    ax_size_cdf.set_ylabel("CDF")
    ax_size_cdf.set_title("A  Packet size CDF", fontweight="bold")
    ax_size_cdf.legend(fontsize=6, ncol=2, loc="lower right")
    ax_size_cdf.grid(True, alpha=0.3)

    # B — IAT CDF (log x-axis)
    for i, m in enumerate(metrics):
        iats = sort(m["iats_ms"])
        iats = iats[iats > 0]  # log axis cannot show zero
        if len(iats) == 0:
            continue
        cdf = arange(1, len(iats) + 1) / len(iats)
        ax_iat_cdf.plot(iats, cdf, color=colors[i], linewidth=1.2, alpha=0.8, label=m["label"])
    ax_iat_cdf.set_xscale("log")
    ax_iat_cdf.set_xlabel("Inter-arrival time (ms, log scale)")
    ax_iat_cdf.set_ylabel("CDF")
    ax_iat_cdf.set_title("B  Inter-arrival-time CDF", fontweight="bold")
    ax_iat_cdf.grid(True, alpha=0.3, which="both")

    # C — throughput vs goodput efficiency scatter
    valid = [
        (m["throughput_mbps"], m["goodput_efficiency"], colors[i], m["label"])
        for i, m in enumerate(metrics)
        if m.get("goodput_efficiency") is not None and not isnan(m["goodput_efficiency"])
    ]
    if valid:
        tps, effs, clrs, lbls = zip(*valid, strict=True)
        ax_thru.scatter(tps, effs, c=clrs, s=80, zorder=3, edgecolors="white", linewidth=0.5)
        for tp, eff, lbl in zip(tps, effs, lbls, strict=True):
            ax_thru.annotate(lbl, (tp, eff), fontsize=6, textcoords="offset points", xytext=(4, 2))
        ax_thru.axhline(1.0, color="gray", linestyle="--", linewidth=0.8, label="perfect efficiency")
        ax_thru.legend(fontsize=8, loc="lower right")
    else:
        ax_thru.text(0.5, 0.5, "No transfer_bytes data available", ha="center", va="center",
                     transform=ax_thru.transAxes, fontsize=9, color="gray")
    ax_thru.set_xlabel("Throughput (Mbps)")
    ax_thru.set_ylabel("Goodput efficiency (payload / total bytes)")
    ax_thru.set_title("C  Throughput vs. efficiency", fontweight="bold")
    ax_thru.grid(True, alpha=0.3)

    # D — overhead bars
    oh_labels = [m["label"] for m in metrics if m["overhead_ratio"] is not None]
    oh_vals   = [m["overhead_ratio"] for m in metrics if m["overhead_ratio"] is not None]
    oh_colors = [colors[i] for i, m in enumerate(metrics) if m["overhead_ratio"] is not None]
    if oh_vals:
        ax_oh.bar(range(len(oh_labels)), oh_vals, color=oh_colors, alpha=0.8, edgecolor="white", linewidth=0.5)
        ax_oh.set_xticks(range(len(oh_labels)))
        ax_oh.set_xticklabels(oh_labels, **label_kw)
        ax_oh.axhline(0, color="black", linewidth=0.8)
        ax_oh.set_ylabel("Overhead ratio (extra bytes per app byte)")
        ax_oh.set_title("D  Protocol overhead", fontweight="bold")
    else:
        ax_oh.text(0.5, 0.5, "No transfer_bytes data available", ha="center", va="center",
                   transform=ax_oh.transAxes, fontsize=9, color="gray")
        ax_oh.set_title("D  Protocol overhead", fontweight="bold")

    # E — byte entropy by phase (all / handshake / data)
    x = arange(n)
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
    ax_ent.set_ylabel("Shannon entropy (bits / byte)")
    ax_ent.set_title("E  Byte entropy by phase", fontweight="bold")
    ax_ent.legend(fontsize=8)

    # F — operational metric heatmap (normalised)
    metric_names = ["Throughput", "Goodput eff.", "Data entropy", "Burstiness", "HS duration", "HS byte frac"]

    def _norm(vals: list) -> ndarray:
        arr = array(vals, dtype=float)
        lo, hi = nanmin(arr), nanmax(arr)
        return (arr - lo) / (hi - lo) if hi > lo else zeros_like(arr)

    throughputs = [m["throughput_mbps"] for m in metrics]
    effs        = [m["goodput_efficiency"] if m["goodput_efficiency"] is not None else float("nan") for m in metrics]
    data_ents   = [m["entropy_data"] or 0.0 for m in metrics]
    bursts      = [m["burstiness"] for m in metrics]
    hs_durs     = [m["hs_duration_s"] if m["hs_duration_s"] is not None else float("nan") for m in metrics]
    hs_fracs    = [m["hs_byte_frac"] for m in metrics]

    heat = vstack([
        _norm(throughputs),
        _norm(effs),
        _norm(data_ents),
        _norm(bursts),
        _norm(hs_durs),
        _norm(hs_fracs),
    ])
    im = ax_heat.imshow(heat, aspect="auto", cmap="RdYlGn", vmin=0, vmax=1)
    ax_heat.set_xticks(range(n))
    ax_heat.set_xticklabels(labels, **label_kw)
    ax_heat.set_yticks(range(len(metric_names)))
    ax_heat.set_yticklabels(metric_names, fontsize=8)
    fig.colorbar(im, ax=ax_heat, fraction=0.03, pad=0.04)
    ax_heat.set_title("F  Operational metric heatmap (normalised)", fontweight="bold")

    fig.suptitle(f"Operational comparison — {run_name}", fontsize=14, fontweight="bold")
    fig.tight_layout(rect=[0, 0, 1, 0.97])
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / f"{run_name}_proto_compare.png"
    fig.savefig(path, format="png", bbox_inches="tight", dpi=110)
    plt.close(fig)
    echo(f"Saved: {path}")


def _plot_handshake(metrics: list[dict], run_name: str, out_dir: Path) -> None:
    labels   = [m["label"] for m in metrics]
    n        = len(metrics)
    colors   = [_PALETTE[i % len(_PALETTE)] for i in range(n)]
    label_kw = {"rotation": 45, "ha": "right", "fontsize": 7}

    fig, (ax_dur, ax_pkt, ax_frac) = plt.subplots(1, 3, figsize=(18, 5))

    durations = [m["hs_duration_s"] if m["hs_duration_s"] is not None else 0.0 for m in metrics]
    ax_dur.bar(range(n), durations, color=colors, alpha=0.8, edgecolor="white", linewidth=0.5)
    ax_dur.set_xticks(range(n))
    ax_dur.set_xticklabels(labels, **label_kw)
    ax_dur.set_ylabel("Duration (s)")
    ax_dur.set_title("A  Handshake duration", fontweight="bold")

    pkt_counts = [m["hs_pkt_count"] for m in metrics]
    ax_pkt.bar(range(n), pkt_counts, color=colors, alpha=0.8, edgecolor="white", linewidth=0.5)
    ax_pkt.set_xticks(range(n))
    ax_pkt.set_xticklabels(labels, **label_kw)
    ax_pkt.set_ylabel("Packets")
    ax_pkt.set_title("B  Handshake packet count", fontweight="bold")

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
    echo(f"Saved: {path}")


def _write_table(metrics: list[dict], run_name: str, out_dir: Path) -> None:
    """Write a markdown comparison table of operational metrics."""
    lines = [
        f"# Operational comparison — `{run_name}`",
        "",
        "| Protocol | Throughput (Mbps) | Bytes (MB) | Overhead | Goodput | Data entropy (bits) | Burstiness | HS duration (s) | HS pkts | HS byte % | c2s/s2c |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for m in metrics:
        oh        = f"{m['overhead_ratio']:.1%}"      if m["overhead_ratio"]      is not None else "—"
        eff       = f"{m['goodput_efficiency']:.1%}"  if m["goodput_efficiency"]  is not None else "—"
        hs_dur    = f"{m['hs_duration_s']:.3f}"       if m["hs_duration_s"]       is not None else "—"
        ent_data  = f"{m['entropy_data']:.3f}"        if m["entropy_data"]        is not None else "—"
        lines.append(
            f"| {m['label']} | "
            f"{m['throughput_mbps']:.1f} | "
            f"{m['total_bytes'] / 1e6:.1f} | "
            f"{oh} | "
            f"{eff} | "
            f"{ent_data} | "
            f"{m['burstiness']:.2f} | "
            f"{hs_dur} | "
            f"{m['hs_pkt_count']} | "
            f"{m['hs_byte_frac']:.2%} | "
            f"{m['direction_asymmetry']:.1f} |"
        )
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / f"{run_name}_compare_table.md"
    path.write_text("\n".join(lines) + "\n")
    echo(f"Saved: {path}")


@command(context_settings={"help_option_names": ["-h", "--help"]})
@option("--run", "run_id", default=None, metavar="YYYYMMDD_HHMMSS", help="Run directory (default: most recent).")
@option("--out-dir", default=str(_DEFAULT_OUT_DIR), show_default=True, type=ClickPath(), help="Output directory for plots and table.")
def main(run_id: str | None, out_dir: str) -> None:
    """Generate operational comparison plots and table from pcap captures."""
    if run_id:
        run_dir = CAPTURES_ROOT / f"run_{run_id}"
        if not run_dir.is_dir():
            echo(f"Run not found: {run_dir}", err=True)
            exit(1)
    else:
        run_dir = _latest_run()
        if run_dir is None:
            echo("No capture runs found. Run 'poe capture' first.", err=True)
            exit(1)

    meta_path = run_dir / "metadata.json"
    metadata: dict = loads(meta_path.read_text()) if meta_path.exists() else {}

    pcaps = sorted(run_dir.glob("*.pcap"))
    if not pcaps:
        echo(f"No pcap files in {run_dir}", err=True)
        exit(1)

    metrics_list: list[dict] = []
    for pcap in pcaps:
        name      = pcap.stem
        proto_key = name.removesuffix("_chaos")
        proto     = BY_NAME.get(proto_key)
        transfer_bytes: int | None = metadata.get(proto_key, {}).get("transfer_bytes")

        echo(f"  Parsing {name}…")
        c2s, s2c = parse_pcap(pcap)
        if not c2s and not s2c:
            continue

        m = _compute_metrics(name, c2s, s2c, proto, transfer_bytes)
        if m:
            metrics_list.append(m)

    if not metrics_list:
        echo("No data to plot.", err=True)
        exit(1)

    run_name = run_dir.name
    _plot_main(metrics_list, run_name, Path(out_dir))
    _plot_handshake(metrics_list, run_name, Path(out_dir))
    _write_table(metrics_list, run_name, Path(out_dir))


if __name__ == "__main__":
    main()
