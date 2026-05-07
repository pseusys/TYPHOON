"""
TYPHOON traffic-pattern comparison: compare four realistic application traffic shapes.

The four modes cross two independent axes:

  payload size:   constant (PAYLOAD_FIXED bytes) vs random (PAYLOAD_MIN..PAYLOAD_MAX)
  inter-cluster:  constant (INTER_CLUSTER_MS) vs random (INTER_CLUSTER_MIN..INTER_CLUSTER_MAX ms)

Messages are sent in clusters of CLUSTER_SIZE with a short intra-cluster delay, producing
burst-and-pause traffic rather than the artificial steady-rate stream of a simple loop.

Mode 1: const payload + const wait   — uniform, predictable stream
Mode 2: const payload + random wait  — bursty timing, uniform sizes
Mode 3: random payload + const wait  — regular timing, variable sizes
Mode 4: random payload + random wait — both axes random (most realistic)

Usage (via poe):
    poe traffic-compare
    poe traffic-compare --use-case security --runs 3
    poe traffic-compare --use-case default --out-dir results/traffic

Usage (direct):
    python -m typhoon_eval.traffic_compare --use-case interactive
"""

import json
from pathlib import Path

import click
import matplotlib.patches as mpatches
import matplotlib.pyplot as plt
import numpy as np

from typhoon_eval.self.flow_plot import _DEFAULT_TYPHOON_DIR, _run_example
from typhoon_eval.shared.capture_stats import COMP_COLORS, COMPONENTS, pool_stats, stats_from_records

_DEFAULT_OUT_DIR = Path(__file__).parent.parent.parent.parent / "results" / "traffic_compare"

_MODES: list[tuple[str, str, str, bool, bool]] = [
    ("1", "Const payload\nConst wait",   "const_const",   False, False),
    ("2", "Const payload\nRandom wait",  "const_random",  False, True),
    ("3", "Random payload\nConst wait",  "random_const",  True,  False),
    ("4", "Random payload\nRandom wait", "random_random", True,  True),
]


def _mode_color(idx: int) -> str:
    palette = ["#2ecc71", "#3498db", "#e67e22", "#e74c3c"]
    return palette[idx % len(palette)]


def _plot_traffic_compare(pooled_by_mode: list[tuple[str, str, dict]], use_case: str, out_dir: Path) -> None:
    n = len(pooled_by_mode)

    fig, axes = plt.subplots(5, n, figsize=(4 * n, 22), squeeze=False)

    for col, (label, _slug, ds) in enumerate(pooled_by_mode):
        color = _mode_color(col)

        # Row 0 — packet size box plot
        ax = axes[0][col]
        sizes = np.array(ds["packet_size"]["raw"])
        if len(sizes) > 0:
            ax.boxplot(sizes, vert=True, patch_artist=True,
                       boxprops=dict(facecolor=color, alpha=0.6),
                       medianprops=dict(color="black", linewidth=2),
                       whiskerprops=dict(linestyle="--"),
                       flierprops=dict(marker=".", markersize=3, alpha=0.4))
        ax.set_xticks([])
        ax.set_title(f"Mode {col + 1}\n{label}", fontsize=9)

        # Row 1 — IAT box plot
        ax = axes[1][col]
        iats = np.array(ds["iat_ms"]["raw"])
        if len(iats) > 0:
            ax.boxplot(iats, vert=True, patch_artist=True,
                       boxprops=dict(facecolor=color, alpha=0.6),
                       medianprops=dict(color="black", linewidth=2),
                       whiskerprops=dict(linestyle="--"),
                       flierprops=dict(marker=".", markersize=3, alpha=0.4))
        ax.set_xticks([])

        # Row 2 — entropy bars (fixed 0–8 scale)
        ax = axes[2][col]
        size_ent = ds["packet_size"]["entropy"]
        iat_ent = ds["iat_ms"]["entropy"]
        ax.bar([0], [size_ent], color=COMP_COLORS["payload"], label="Size")
        ax.bar([1], [iat_ent], color=COMP_COLORS["crypto"], label="IAT")
        ax.set_xticks([0, 1])
        ax.set_xticklabels(["Size", "IAT"], fontsize=8)
        ax.set_ylim(0, 8)
        if col == 0:
            ax.legend(fontsize=7)

        # Row 3 — stacked component bars
        ax = axes[3][col]
        bottom = 0.0
        for comp in COMPONENTS:
            val = ds["components"].get(comp, 0.0)
            ax.bar([0], [val], bottom=bottom, color=COMP_COLORS[comp], label=comp)
            bottom += val
        ax.set_xticks([])

        # Row 4 — burstiness and size regularity
        ax = axes[4][col]
        burst = ds.get("burstiness", 0.0)
        sreg  = ds.get("size_regularity", 0.0)
        ax.bar([0], [burst], color="#9b59b6", alpha=0.8, label="Burstiness")
        ax.bar([1], [sreg],  color="#e67e22", alpha=0.8, label="Size reg.")
        ax.set_xticks([0, 1])
        ax.set_xticklabels(["Burst.", "Reg."], fontsize=8)
        ax.set_ylim(bottom=0)
        if col == 0:
            ax.legend(fontsize=7)

    # Shared y-axis labels
    for row_ax, label in zip(axes[:, 0], ["Packet size (bytes)", "IAT (ms)", "Shannon entropy (bits)", "Mean bytes", "Metric value"]):
        row_ax.set_ylabel(label, fontsize=9)

    comp_patches = [mpatches.Patch(color=COMP_COLORS[c], label=c) for c in COMPONENTS]
    fig.legend(handles=comp_patches, loc="lower center", ncol=len(COMPONENTS), fontsize=8, bbox_to_anchor=(0.5, 0.01))

    cfg_lines = []
    for col, (_label, _slug, ds) in enumerate(pooled_by_mode):
        cfg_list = ds.get("config", [])
        if cfg_list:
            cfg = cfg_list[0]
            body = cfg.get("body_mode", "?")
            hdr = cfg.get("header_len", "?")
            decoy = (cfg.get("decoy") or "?").replace("DecoyProvider", "")
            cfg_lines.append(f"  Mode {col + 1}: {body} hdr={hdr}B {decoy}")
    fig.text(0.01, 0.0, "\n".join(cfg_lines), fontsize=6, family="monospace", va="bottom")

    fig.suptitle(f"TYPHOON traffic-pattern comparison — use_case={use_case}", fontsize=14, fontweight="bold")
    fig.tight_layout(rect=[0, 0.03 + 0.006 * n, 1, 1])

    out_dir.mkdir(parents=True, exist_ok=True)
    png_path = out_dir / f"{use_case}_traffic_compare.png"
    fig.savefig(png_path, format="png", bbox_inches="tight", dpi=120)
    plt.close(fig)
    click.echo(f"Saved: {png_path}")


@click.command()
@click.option("--example", default="use_case", show_default=True, help="Rust example name to run")
@click.option("--use-case", "use_case", default="default", show_default=True, help="TYPHOON_USE_CASE value")
@click.option("--runs", default=3, show_default=True, help="Number of runs per mode (results are pooled)")
@click.option("--out-dir", default=str(_DEFAULT_OUT_DIR), show_default=True, type=click.Path(), help="Output directory for PNG and JSON")
@click.option("--typhoon-dir", default=str(_DEFAULT_TYPHOON_DIR), show_default=True, type=click.Path(exists=True), help="Path to the typhoon Rust crate")
@click.option("--timeout", default=90, show_default=True, help="Per-run timeout in seconds")
def main(example: str, use_case: str, runs: int, out_dir: str, typhoon_dir: str, timeout: int) -> None:
    """Run TYPHOON with each of the four payload×wait traffic modes and compare results."""
    pooled_by_mode: list[tuple[str, str, dict]] = []
    json_data: dict = {}

    for _num, label, slug, random_payload, random_wait in _MODES:
        click.echo(f"Mode {_num}: {label.replace(chr(10), ' / ')} …")
        extra_env: dict = {"TYPHOON_USE_CASE": use_case}
        if random_payload:
            extra_env["TYPHOON_RANDOM_PAYLOAD"] = "1"
        if random_wait:
            extra_env["TYPHOON_RANDOM_WAIT"] = "1"

        run_stats: list[dict] = []
        for i in range(runs):
            click.echo(f"  run {i + 1}/{runs}…")
            packets, configs = _run_example(example, Path(typhoon_dir), timeout, extra_env)
            if not packets:
                click.echo("  Warning: no capture records; skipping.", err=True)
                continue
            run_stats.append(stats_from_records(packets, configs))

        if not run_stats:
            click.echo(f"  No successful runs for mode {_num}; skipping.", err=True)
            continue

        pooled = pool_stats(run_stats, direction="all")
        pooled["config"] = run_stats[0].get("config", [])
        pooled_by_mode.append((label, slug, pooled))
        json_data[slug] = run_stats

    if not pooled_by_mode:
        click.echo("No data; nothing to plot.", err=True)
        return

    _plot_traffic_compare(pooled_by_mode, use_case, Path(out_dir))

    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    json_path = out / f"{use_case}_traffic_compare.json"
    serialisable: dict = {}
    for _label, slug, _ds in pooled_by_mode:
        runs_list = json_data.get(slug, [])
        stripped = []
        for s in runs_list:
            entry = {k: v for k, v in s.items() if k != "config"}
            for direction in ("c2s", "s2c", "all"):
                if direction in entry:
                    for metric in ("packet_size", "iat_ms"):
                        if metric in entry[direction]:
                            entry[direction][metric] = {k: v for k, v in entry[direction][metric].items() if k != "raw"}
            entry["config"] = s.get("config", [])
            stripped.append(entry)
        serialisable[slug] = stripped
    json_path.write_text(json.dumps(serialisable, indent=2))
    click.echo(f"Saved: {json_path}")


if __name__ == "__main__":
    main()
