"""
TYPHOON self-comparison: run one configuration N times and compare the runs.

Shows how much TYPHOON varies across independent executions: which parameters were
selected (body mode, header length, decoy) and how they impact packet size distribution,
inter-arrival time, entropy, and per-component byte breakdown.

Usage (via poe):
    poe self-compare
    poe self-compare --use-case security --runs 8 --random-payload
    poe self-compare --example use_case --use-case default --runs 6 --out-dir results/cmp

Usage (direct):
    python -m typhoon_eval.self_compare --use-case default --runs 6
"""

from json import dumps
from pathlib import Path

from click import Path as ClickPath
from click import command, echo, option
from matplotlib import patches as mpatches
from matplotlib import pyplot as plt
from numpy import arange, array, zeros

from typhoon_eval.self.flow_plot import _DEFAULT_TYPHOON_DIR, _run_example
from typhoon_eval.shared.capture_stats import COMP_COLORS, COMPONENTS, USE_CASE_COLORS, stats_from_records

_DEFAULT_OUT_DIR = Path(__file__).parent.parent.parent.parent / "results" / "self_compare"


def _config_label(config_list: list[dict]) -> str:
    """Summarise a run's config into a short human-readable string."""
    if not config_list:
        return "?"
    parts = []
    for cfg in config_list:
        body = cfg.get("body_mode", "?")
        hdr = cfg.get("header_len", "?")
        decoy = (cfg.get("decoy") or "?").split("DecoyProvider")[0]
        parts.append(f"{cfg.get('dir','?')}: {body} hdr={hdr}B {decoy}")
    return " | ".join(parts)


def _plot_self_compare(run_stats: list[dict], use_case: str, out_dir: Path) -> None:
    n = len(run_stats)
    run_labels = [f"Run {i + 1}" for i in range(n)]
    color = USE_CASE_COLORS.get(use_case, "#888888")

    fig, axes = plt.subplots(3, 2, figsize=(14, 15))
    (ax_size, ax_iat), (ax_ent, ax_comp), (ax_burst, ax_reg) = axes

    # Panel A — packet size violin plots
    size_data = [array(s["all"]["packet_size"]["raw"]) for s in run_stats]
    size_data_nz = [d[d > 0] if len(d) > 0 else d for d in size_data]
    if any(len(d) > 0 for d in size_data_nz):
        parts = ax_size.violinplot(
            [d.tolist() if len(d) > 0 else [0.0] for d in size_data_nz],
            positions=list(range(1, n + 1)),
            showmedians=True,
        )
        for pc in parts["bodies"]:
            pc.set_facecolor(color)
            pc.set_alpha(0.6)
    ax_size.set_xticks(range(1, n + 1))
    ax_size.set_xticklabels(run_labels, rotation=20, ha="right")
    ax_size.set_ylabel("Packet size (bytes)")
    ax_size.set_title("Packet size distribution per run")

    # Panel B — IAT violin plots
    iat_data = [array(s["all"]["iat_ms"]["raw"]) for s in run_stats]
    iat_data_nz = [d[d > 0] if len(d) > 0 else d for d in iat_data]
    if any(len(d) > 0 for d in iat_data_nz):
        parts = ax_iat.violinplot(
            [d.tolist() if len(d) > 0 else [0.0] for d in iat_data_nz],
            positions=list(range(1, n + 1)),
            showmedians=True,
        )
        for pc in parts["bodies"]:
            pc.set_facecolor(color)
            pc.set_alpha(0.6)
    ax_iat.set_xticks(range(1, n + 1))
    ax_iat.set_xticklabels(run_labels, rotation=20, ha="right")
    ax_iat.set_ylabel("IAT (ms)")
    ax_iat.set_title("Inter-arrival time distribution per run")

    # Panel C — entropy bar chart (size entropy + IAT entropy)
    x = arange(n)
    bar_w = 0.35
    size_entropies = [s["all"]["packet_size"]["entropy"] for s in run_stats]
    iat_entropies = [s["all"]["iat_ms"]["entropy"] for s in run_stats]
    ax_ent.bar(x - bar_w / 2, size_entropies, bar_w, label="Size entropy", color=COMP_COLORS["payload"])
    ax_ent.bar(x + bar_w / 2, iat_entropies, bar_w, label="IAT entropy", color=COMP_COLORS["crypto"])
    ax_ent.set_xticks(x)
    ax_ent.set_xticklabels(run_labels, rotation=20, ha="right")
    ax_ent.set_ylabel("Shannon entropy (bits)")
    ax_ent.set_ylim(0, 8)
    ax_ent.set_title("Entropy per run")
    ax_ent.legend(fontsize=8)

    # Panel D — stacked component bars (mean bytes per component)
    bottoms = zeros(n)
    for comp in COMPONENTS:
        heights = array([s["all"]["components"].get(comp, 0.0) for s in run_stats])
        ax_comp.bar(x, heights, bottom=bottoms, color=COMP_COLORS[comp], label=comp)
        bottoms += heights
    ax_comp.set_xticks(x)
    ax_comp.set_xticklabels(run_labels, rotation=20, ha="right")
    ax_comp.set_ylabel("Mean bytes")
    ax_comp.set_title("Mean packet composition per run")
    comp_patches = [mpatches.Patch(color=COMP_COLORS[c], label=c) for c in COMPONENTS]
    ax_comp.legend(handles=comp_patches, fontsize=8)

    # Panel E — burstiness bar chart per run
    burstinesses   = [s["all"].get("burstiness", 0.0) for s in run_stats]
    size_regs      = [s["all"].get("size_regularity", 0.0) for s in run_stats]
    x = arange(n)
    ax_burst.bar(x, burstinesses, color=color, alpha=0.75)
    ax_burst.set_xticks(x)
    ax_burst.set_xticklabels(run_labels, rotation=20, ha="right")
    ax_burst.set_ylabel("Burstiness (std/mean IAT)")
    ax_burst.set_title("IAT burstiness per run")
    ax_burst.grid(True, axis="y", alpha=0.3)

    # Panel F — size regularity per run
    ax_reg.bar(x, size_regs, color="#e67e22", alpha=0.75)
    ax_reg.set_xticks(x)
    ax_reg.set_xticklabels(run_labels, rotation=20, ha="right")
    ax_reg.set_ylim(0, 1.05)
    ax_reg.set_ylabel("Size regularity (unique/total)")
    ax_reg.set_title("Packet size regularity per run")
    ax_reg.grid(True, axis="y", alpha=0.3)

    # Footer: config labels
    config_lines = [f"  Run {i + 1}: {_config_label(s['config'])}" for i, s in enumerate(run_stats)]
    fig.text(0.01, 0.01, "\n".join(config_lines), fontsize=6, family="monospace", va="bottom")

    fig.suptitle(f"TYPHOON self-comparison — use_case={use_case} ({n} runs)", fontsize=13, fontweight="bold")
    fig.tight_layout(rect=[0, 0.06 + 0.012 * n, 1, 1])

    out_dir.mkdir(parents=True, exist_ok=True)
    stem = f"{use_case}_self_compare"
    pdf_path = out_dir / f"{stem}.pdf"
    fig.savefig(pdf_path, format="pdf", bbox_inches="tight")
    plt.close(fig)
    echo(f"Saved: {pdf_path}")


@command()
@option("--example", default="use_case", show_default=True, help="Rust example name to run")
@option("--use-case", "use_case", default="default", show_default=True, help="TYPHOON_USE_CASE value")
@option("--runs", default=6, show_default=True, help="Number of repeated runs")
@option("--random-payload", is_flag=True, default=False, help="Set TYPHOON_RANDOM_PAYLOAD to randomise message sizes")
@option("--random-wait", is_flag=True, default=False, help="Set TYPHOON_RANDOM_WAIT to randomise inter-cluster pauses")
@option("--out-dir", default=str(_DEFAULT_OUT_DIR), show_default=True, type=ClickPath(), help="Output directory for PNG and JSON")
@option("--typhoon-dir", default=str(_DEFAULT_TYPHOON_DIR), show_default=True, type=ClickPath(exists=True), help="Path to the typhoon Rust crate")
@option("--timeout", default=60, show_default=True, help="Per-run timeout in seconds")
def main(example: str, use_case: str, runs: int, random_payload: bool, random_wait: bool, out_dir: str, typhoon_dir: str, timeout: int) -> None:
    """Run a TYPHOON example N times with the same use case and compare the runs."""
    extra_env: dict = {"TYPHOON_USE_CASE": use_case}
    if random_payload:
        extra_env["TYPHOON_RANDOM_PAYLOAD"] = "1"
    if random_wait:
        extra_env["TYPHOON_RANDOM_WAIT"] = "1"

    run_stats: list[dict] = []
    for i in range(runs):
        echo(f"Run {i + 1}/{runs} (use_case={use_case})…")
        packets, configs = _run_example(example, Path(typhoon_dir), timeout, extra_env)
        if not packets:
            echo(f"  Warning: no capture records in run {i + 1}; skipping.", err=True)
            continue
        run_stats.append(stats_from_records(packets, configs))

    if not run_stats:
        echo("No successful runs; nothing to plot.", err=True)
        return

    _plot_self_compare(run_stats, use_case, Path(out_dir))

    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    json_path = out / f"{use_case}_self_compare.json"
    serialisable = []
    for s in run_stats:
        entry = {k: v for k, v in s.items() if k != "config"}
        for direction in ("c2s", "s2c", "all"):
            if direction in entry:
                for metric in ("packet_size", "iat_ms"):
                    if metric in entry[direction]:
                        entry[direction][metric] = {k: v for k, v in entry[direction][metric].items() if k != "raw"}
        entry["config"] = s.get("config", [])
        serialisable.append(entry)
    json_path.write_text(dumps(serialisable, indent=2))
    echo(f"Saved: {json_path}")


if __name__ == "__main__":
    main()
