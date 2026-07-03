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

The aggregation and statistics (corpus walk, macro histograms / CDFs /
moments, JSON builders) live in ``dist_stats.py``; this module holds only the
matplotlib drawing and the CLI.
"""

from __future__ import annotations

from json import dumps
from pathlib import Path
from sys import exit

import numpy as np
from click import Path as ClickPath
from click import command, option
from matplotlib import pyplot as plt
from matplotlib.axes import Axes
from rich.console import Console

from typhoon_eval.background.dist_stats import (
    POSITION_PLOT_PACKETS,
    FlowRec,
    _burst_per_flow,
    _iats_ms_from_times,
    _load_corpus_packets,
    _macro_5b_histogram,
    _macro_cdf,
    _macro_hist_density,
    _packet_index_to_json,
    _pair_to_json,
    _per_flow_iats,
    _per_flow_sizes,
    _stats_line,
    _total_per_flow_concat,
)
from typhoon_eval.background.features import (
    BARRADAS_HIST_BIN_WIDTH,
    BARRADAS_HIST_MAX,
    DIRECTIONS,
    PERCENTILES,
)

# (TYPHOON profile, target natural class) mapping — imported rather than
# redefined so this module's plots always compare the same pair Test A
# actually trains on.  A previously-duplicated copy of this dict had drifted
# (`silent_idle` pointed at `dns` here vs. `wireguard_idle` in Test A),
# silently comparing distributions against the wrong natural class.
from typhoon_eval.background.detectability.pair_binary import PROFILE_TARGET_CLASS

console = Console()

# Histogram bins for size / IAT.
SIZE_BINS = 80
IAT_BINS = 80
# Clamp IAT axis to this percentile so a few network-stall outliers don't
# squash the bulk of the distribution into one bin.
IAT_AXIS_PCTILE = 99


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
