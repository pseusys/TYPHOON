"""
TYPHOON evaluation — pcap analysis.

Reads all .pcap files from a capture run directory, computes per-protocol
statistics in three directions (c2s, s2c, all), and writes stats.json into
the same run directory.

Usage (via poe):
    poe analyze                        # analyse most recent run
    poe analyze --run 20260423_130000  # analyse a specific run

Usage (direct):
    python -m typhoon_eval.analysis [--run YYYYMMDD_HHMMSS]
"""

import json
import sys
from pathlib import Path

import click
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.table import Table

from .pcap_stats import analyze_pcap

console = Console()

RESULTS_DIR = Path(__file__).parent.parent.parent / "results"
CAPTURES_ROOT = RESULTS_DIR / "captures"


def _latest_run() -> Path | None:
    runs = sorted(p for p in CAPTURES_ROOT.glob("run_*") if p.is_dir()) if CAPTURES_ROOT.exists() else []
    return runs[-1] if runs else None


@click.command(context_settings={"help_option_names": ["-h", "--help"]})
@click.option(
    "--run",
    "run_id",
    default=None,
    metavar="YYYYMMDD_HHMMSS",
    help="Run directory to analyse (default: most recent).",
)
def main(run_id: str | None) -> None:
    """TYPHOON evaluation — analyse pcap captures from a capture run."""

    if run_id:
        run_dir = CAPTURES_ROOT / run_id
        if not run_dir.is_dir():
            console.print(f"[red]Run not found:[/red] {run_dir}")
            sys.exit(1)
    else:
        run_dir = _latest_run()
        if run_dir is None:
            console.print("[red]No capture runs found.[/red] Run [bold]poe capture[/bold] first.")
            sys.exit(1)

    pcaps = sorted(run_dir.glob("*.pcap"))
    if not pcaps:
        console.print(f"[red]No pcap files in[/red] {run_dir}")
        sys.exit(1)

    meta_path = run_dir / "metadata.json"
    metadata: dict = json.loads(meta_path.read_text()) if meta_path.exists() else {}

    cfg: dict = {}
    cfg_path = run_dir / "config.json"
    if cfg_path.exists():
        cfg = json.loads(cfg_path.read_text())

    console.print("\n[bold]TYPHOON pcap analysis[/bold]")
    console.print(f"  Run       : [dim]{run_dir.name}[/dim]")
    if cfg:
        chaos_note = " [yellow](chaos)[/yellow]" if cfg.get("chaos") else ""
        tb = cfg.get("transfer_bytes", 0)
        console.print(f"  Captured  : {', '.join(cfg.get('protocols', []))}{chaos_note}")
        console.print(f"  Transfer  : {tb / 1_048_576:.0f} MB per client")
    console.print(f"  Files     : {len(pcaps)} pcap(s)\n")

    all_stats: dict[str, dict] = {}

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        TimeElapsedColumn(),
        console=console,
        transient=False,
    ) as progress:
        for pcap in pcaps:
            name = pcap.stem  # e.g. "wireguard" or "wireguard_chaos"
            task = progress.add_task(f"  [cyan]{name:<22}[/cyan]", total=None)

            # transfer_bytes stored per protocol name in metadata (strip _chaos suffix)
            proto_key = name.removesuffix("_chaos")
            transfer_bytes: int | None = metadata.get(proto_key, {}).get("transfer_bytes")

            stats = analyze_pcap(pcap, transfer_bytes=transfer_bytes)
            all_stats[name] = stats

            progress.update(task, total=1, completed=1,
                            description=f"  [green]✓[/green] [cyan]{name:<22}[/cyan]")

    out_path = run_dir / "stats.json"
    out_path.write_text(json.dumps(all_stats, indent=2))
    console.print(f"\nStats → [dim]{out_path}[/dim]")

    _print_summary(all_stats)


def _fmt_entropy(e: float | None) -> str:
    if e is None:
        return "[dim]—[/dim]"
    color = "green" if e >= 7.5 else ("yellow" if e >= 6.0 else "red")
    return f"[{color}]{e:.2f}[/{color}]"


def _fmt_pct(v: float | None) -> str:
    if v is None:
        return "[dim]—[/dim]"
    color = "red" if v > 0.5 else ("yellow" if v > 0.1 else "green")
    return f"[{color}]{v:+.1%}[/{color}]"


def _print_summary(all_stats: dict[str, dict]) -> None:
    table = Table(title="Analysis summary", show_lines=True)
    table.add_column("Capture", style="cyan", no_wrap=True)
    table.add_column("Dir", style="dim")
    table.add_column("Pkts", justify="right", style="dim")
    table.add_column("Time (s)", justify="right", style="dim")
    table.add_column("Size p50/p99 (B)", justify="right")
    table.add_column("IAT p50/p95 (ms)", justify="right", style="dim")
    table.add_column("Entropy\nall / hs / data", justify="right")
    table.add_column("Overhead", justify="right")

    for name, dirs in sorted(all_stats.items()):
        first = True
        for direction in ("c2s", "s2c", "all"):
            s = dirs.get(direction, {})
            if not s:
                continue
            ps = s.get("packet_size", {})
            iat = s.get("iat_ms", {})
            ent = s.get("entropy", {})

            p50 = f"{ps.get('p50', 0):.0f}" if ps else "—"
            p99 = f"{ps.get('p99', 0):.0f}" if ps else "—"
            ip50 = f"{iat.get('p50', 0):.2f}" if iat else "—"
            ip95 = f"{iat.get('p95', 0):.2f}" if iat else "—"

            ent_str = (
                f"{_fmt_entropy(ent.get('all'))} / "
                f"{_fmt_entropy(ent.get('handshake'))} / "
                f"{_fmt_entropy(ent.get('data'))}"
            )

            overhead = _fmt_pct(s.get("overhead_ratio"))

            table.add_row(
                name if first else "",
                direction,
                str(s.get("packet_count", 0)),
                f"{s.get('transmission_time_s', 0):.1f}",
                f"{p50} / {p99}",
                f"{ip50} / {ip95}",
                ent_str,
                overhead,
            )
            first = False

    console.print(table)
    console.print()


if __name__ == "__main__":
    main()
