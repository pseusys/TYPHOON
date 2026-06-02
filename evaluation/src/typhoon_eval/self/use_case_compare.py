"""
TYPHOON use-case comparison: run each PROTOCOL.md use case and compare traffic profiles.

Shows measurably different traffic characteristics for each use case:
  throughput  — minimal overhead, fastest throughput
  interactive — light padding, sparse decoy
  transparent — constant packet sizes, structured header, smooth decoy
  security    — large random padding, random header, heavy decoy
  default     — randomly chosen config (baseline for comparison)

Usage (via poe):
    poe use-case-compare
    poe use-case-compare --runs-per-case 3 --random-payload
    poe use-case-compare --cases throughput,security --runs-per-case 5

Usage (direct):
    python -m typhoon_eval.use_case_compare --runs-per-case 3
"""

from json import dumps
from pathlib import Path

from click import Path as ClickPath
from click import command, echo, option
from matplotlib import patches as mpatches
from matplotlib import pyplot as plt
from numpy import array

from typhoon_eval.self.flow_plot import _DEFAULT_TYPHOON_DIR, _run_example
from typhoon_eval.shared.capture_stats import COMP_COLORS, COMPONENTS, USE_CASE_COLORS, pool_stats, stats_from_records

_DEFAULT_CASES = ["throughput", "interactive", "transparent", "security", "default"]
_DEFAULT_OUT_DIR = Path(__file__).parent.parent.parent.parent / "results" / "use_case_compare"


def _short_title(use_case: str, pooled: dict) -> str:
    """One-line column heading: use-case name + brief body/decoy summary."""
    cfg_list = pooled.get("config", [])
    if not cfg_list:
        return use_case
    cfg = cfg_list[0]
    body = cfg.get("body_mode", "?")
    # Shorten long body mode strings: keep type and key numbers only
    if "Random" in body:
        body = "Random"
    elif "Constant" in body:
        body = "Constant"
    decoy = (cfg.get("decoy") or "?").replace("DecoyProvider", "")
    return f"{use_case}\n{body} / {decoy}"


def _config_footer(pooled_by_case: dict[str, dict]) -> str:
    """Full config summary for the figure footer, one line per use case."""
    lines = []
    for uc, ds in pooled_by_case.items():
        cfg_list = ds.get("config", [])
        if not cfg_list:
            lines.append(f"  {uc}: ?")
            continue
        parts = []
        for cfg in cfg_list:
            body = cfg.get("body_mode", "?")
            hdr = cfg.get("header_len", "?")
            decoy = (cfg.get("decoy") or "?").replace("DecoyProvider", "")
            parts.append(f"{cfg.get('dir','?')}: {body} hdr={hdr}B {decoy}")
        lines.append(f"  {uc}: {' | '.join(parts)}")
    return "\n".join(lines)


def _plot_use_case_compare(pooled_by_case: dict[str, dict], out_dir: Path) -> None:
    cases = list(pooled_by_case.keys())
    n = len(cases)

    fig, axes = plt.subplots(4, n, figsize=(4 * n, 18), squeeze=False)

    for col, use_case in enumerate(cases):
        ds = pooled_by_case[use_case]
        color = USE_CASE_COLORS.get(use_case, "#888888")

        # Row 0 — packet size box plot
        ax = axes[0][col]
        sizes = array(ds["packet_size"]["raw"])
        if len(sizes) > 0:
            ax.boxplot(sizes, vert=True, patch_artist=True,
                       boxprops=dict(facecolor=color, alpha=0.6),
                       medianprops=dict(color="black", linewidth=2),
                       whiskerprops=dict(linestyle="--"),
                       flierprops=dict(marker=".", markersize=3, alpha=0.4))
        ax.set_xticks([])
        ax.set_title(_short_title(use_case, ds), fontsize=9)

        # Row 1 — IAT box plot
        ax = axes[1][col]
        iats = array(ds["iat_ms"]["raw"])
        if len(iats) > 0:
            ax.boxplot(iats, vert=True, patch_artist=True,
                       boxprops=dict(facecolor=color, alpha=0.6),
                       medianprops=dict(color="black", linewidth=2),
                       whiskerprops=dict(linestyle="--"),
                       flierprops=dict(marker=".", markersize=3, alpha=0.4))
        ax.set_xticks([])

        # Row 2 — entropy bars (fixed 0–8 scale for all use cases)
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

    # Shared y-axis labels (left column only)
    for row_ax, label in zip(axes[:, 0], ["Packet size (bytes)", "IAT (ms)", "Shannon entropy (bits)", "Mean bytes"], strict=True):
        row_ax.set_ylabel(label, fontsize=9)

    comp_patches = [mpatches.Patch(color=COMP_COLORS[c], label=c) for c in COMPONENTS]
    fig.legend(handles=comp_patches, loc="lower center", ncol=len(COMPONENTS), fontsize=8, bbox_to_anchor=(0.5, 0.01))

    footer = _config_footer(pooled_by_case)
    fig.text(0.01, 0.0, footer, fontsize=6, family="monospace", va="bottom")

    fig.suptitle("TYPHOON use-case comparison", fontsize=14, fontweight="bold")
    fig.tight_layout(rect=[0, 0.04 + 0.008 * len(cases), 1, 1])

    out_dir.mkdir(parents=True, exist_ok=True)
    png_path = out_dir / "use_case_compare.png"
    fig.savefig(png_path, format="png", bbox_inches="tight", dpi=120)
    plt.close(fig)
    echo(f"Saved: {png_path}")


@command()
@option("--example", default="use_case", show_default=True, help="Rust example name to run")
@option("--cases", default=",".join(_DEFAULT_CASES), show_default=True, help="Comma-separated list of use cases")
@option("--runs-per-case", default=3, show_default=True, help="Number of runs averaged per use case")
@option("--random-payload", is_flag=True, default=False, help="Set TYPHOON_RANDOM_PAYLOAD to randomise message sizes")
@option("--random-wait", is_flag=True, default=False, help="Set TYPHOON_RANDOM_WAIT to randomise inter-cluster pauses")
@option("--out-dir", default=str(_DEFAULT_OUT_DIR), show_default=True, type=ClickPath(), help="Output directory for PNG and JSON")
@option("--typhoon-dir", default=str(_DEFAULT_TYPHOON_DIR), show_default=True, type=ClickPath(exists=True), help="Path to the typhoon Rust crate")
@option("--timeout", default=60, show_default=True, help="Per-run timeout in seconds")
def main(example: str, cases: str, runs_per_case: int, random_payload: bool, random_wait: bool, out_dir: str, typhoon_dir: str, timeout: int) -> None:
    """Run TYPHOON for each use case and compare traffic profiles side by side."""
    case_list = [c.strip() for c in cases.split(",") if c.strip()]

    pooled_by_case: dict[str, dict] = {}
    json_data: dict[str, list] = {}

    for use_case in case_list:
        extra_env: dict = {"TYPHOON_USE_CASE": use_case}
        if random_payload:
            extra_env["TYPHOON_RANDOM_PAYLOAD"] = "1"
        if random_wait:
            extra_env["TYPHOON_RANDOM_WAIT"] = "1"

        run_stats: list[dict] = []
        for i in range(runs_per_case):
            echo(f"  {use_case}  run {i + 1}/{runs_per_case}…")
            packets, configs = _run_example(example, Path(typhoon_dir), timeout, extra_env)
            if not packets:
                echo("  Warning: no capture records; skipping.", err=True)
                continue
            run_stats.append(stats_from_records(packets, configs))

        if not run_stats:
            echo(f"No successful runs for {use_case}; skipping.", err=True)
            continue

        pooled = pool_stats(run_stats, direction="all")
        pooled["config"] = run_stats[0].get("config", [])
        pooled_by_case[use_case] = pooled
        json_data[use_case] = run_stats

    if not pooled_by_case:
        echo("No data; nothing to plot.", err=True)
        return

    _plot_use_case_compare(pooled_by_case, Path(out_dir))

    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    json_path = out / "use_case_compare.json"
    serialisable: dict = {}
    for uc, runs in json_data.items():
        stripped = []
        for s in runs:
            entry = {k: v for k, v in s.items() if k != "config"}
            for direction in ("c2s", "s2c", "all"):
                if direction in entry:
                    for metric in ("packet_size", "iat_ms"):
                        if metric in entry[direction]:
                            entry[direction][metric] = {k: v for k, v in entry[direction][metric].items() if k != "raw"}
            entry["config"] = s.get("config", [])
            stripped.append(entry)
        serialisable[uc] = stripped
    json_path.write_text(dumps(serialisable, indent=2))
    echo(f"Saved: {json_path}")


if __name__ == "__main__":
    main()
