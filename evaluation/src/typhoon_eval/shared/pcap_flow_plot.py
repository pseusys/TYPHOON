"""
Per-packet pcap timeline grid for all captured protocols.

Reads pcap files from a capture run directory and produces a single PNG with
one subplot per protocol.  Each packet is one point: client→server packets
are plotted above the zero line, server→client packets below it.  The
handshake boundary (per protocol's sniffer) is shown as a dashed vertical
line.  All subplots share the same y-axis range for direct size comparison.

Usage (via poe):
    poe proto-flow-plot
    poe proto-flow-plot --run 20260501_120000 --out-dir results/plots

Usage (direct):
    python -m typhoon_eval.pcap_flow_plot [--run YYYYMMDD_HHMMSS] [--out-dir DIR]
"""

import sys
from math import ceil
from pathlib import Path

import click
import matplotlib.patches as mpatches
import matplotlib.pyplot as plt
import numpy as np
from scapy.layers.inet import IP
from scapy.utils import PcapReader

from typhoon_eval.shared.analysis import CAPTURES_ROOT, _latest_run
from typhoon_eval.shared.pcap_stats import CLIENT_IP, SERVER_IP, handshake_end
from typhoon_eval.shared.protocols import BY_NAME

_DEFAULT_OUT_DIR = Path(__file__).parent.parent.parent.parent / "results" / "plots"

_C2S_COLOR = "#2980b9"
_S2C_COLOR = "#e74c3c"
_HS_COLOR  = "#f39c12"
_GRID_COLS = 4


def _parse_timeline(path: Path) -> tuple[list[tuple[float, int]], list[tuple[float, int]]]:
    """Return (c2s, s2c) lists of (timestamp_s, ip_size_bytes)."""
    c2s: list[tuple[float, int]] = []
    s2c: list[tuple[float, int]] = []
    with PcapReader(str(path)) as reader:
        for pkt in reader:
            if IP not in pkt:
                continue
            ip = pkt[IP]
            ts = float(pkt.time)
            sz = len(ip)
            if ip.src == CLIENT_IP and ip.dst == SERVER_IP:
                c2s.append((ts, sz))
            elif ip.src == SERVER_IP and ip.dst == CLIENT_IP:
                s2c.append((ts, sz))
    return c2s, s2c


def _plot_timeline(run_dir: Path, out_dir: Path) -> None:
    pcaps = sorted(run_dir.glob("*.pcap"))
    if not pcaps:
        click.echo(f"No pcap files in {run_dir}", err=True)
        sys.exit(1)

    # Collect per-protocol data.
    proto_data: list[tuple[str, list, list]] = []
    for pcap in pcaps:
        name = pcap.stem
        c2s, s2c = _parse_timeline(pcap)
        if c2s or s2c:
            proto_data.append((name, c2s, s2c))

    if not proto_data:
        click.echo("No packets found in any pcap.", err=True)
        sys.exit(1)

    # Global y-range: shared across all subplots for comparability.
    all_sizes = [sz for _, c2s, s2c in proto_data for _, sz in c2s + s2c]
    y_max = float(max(all_sizes)) if all_sizes else 1500.0

    n = len(proto_data)
    cols = min(_GRID_COLS, n)
    rows = ceil(n / cols)

    fig, axes = plt.subplots(rows, cols, figsize=(6 * cols, 3.5 * rows), squeeze=False)

    for idx, (name, c2s, s2c) in enumerate(proto_data):
        row, col = divmod(idx, cols)
        ax = axes[row][col]

        proto = BY_NAME.get(name)
        title = proto.description if proto else name

        # Normalise to this pcap's first packet.
        all_ts = [ts for ts, _ in c2s + s2c]
        t0 = min(all_ts) if all_ts else 0.0

        # Handshake boundary.
        hs_end_ts: float | None = None
        if proto and proto.handshake_sniffer:
            c2s_recs = [(ts, sz, b"") for ts, sz in c2s]
            s2c_recs = [(ts, sz, b"") for ts, sz in s2c]
            hs_end_ts = handshake_end(c2s_recs, s2c_recs, proto.handshake_sniffer)

        if c2s:
            ts_arr = np.array([ts - t0 for ts, _ in c2s])
            sz_arr = np.array([sz for _, sz in c2s], dtype=float)
            ax.scatter(ts_arr, sz_arr, color=_C2S_COLOR, s=3, alpha=0.5, linewidths=0, rasterized=True)

        if s2c:
            ts_arr = np.array([ts - t0 for ts, _ in s2c])
            sz_arr = np.array([-sz for _, sz in s2c], dtype=float)
            ax.scatter(ts_arr, sz_arr, color=_S2C_COLOR, s=3, alpha=0.5, linewidths=0, rasterized=True)

        if hs_end_ts is not None:
            ax.axvline(hs_end_ts - t0, color=_HS_COLOR, linewidth=1.0, linestyle="--", alpha=0.85, label="hs end")

        ax.axhline(0, color="black", linewidth=0.5)
        ax.set_ylim(-y_max * 1.08, y_max * 1.08)
        ax.set_title(title, fontsize=9, fontweight="bold")
        ax.set_xlabel("Time (s)", fontsize=7)
        ax.set_ylabel("Bytes", fontsize=7)
        ax.tick_params(labelsize=6)

    # Hide unused axes.
    for idx in range(n, rows * cols):
        row, col = divmod(idx, cols)
        axes[row][col].set_visible(False)

    handles = [
        mpatches.Patch(color=_C2S_COLOR, label="client → server"),
        mpatches.Patch(color=_S2C_COLOR, label="server → client"),
        mpatches.Patch(color=_HS_COLOR,  label="handshake end"),
    ]
    fig.legend(handles=handles, loc="lower center", ncol=3, fontsize=9, bbox_to_anchor=(0.5, 0.0))
    fig.suptitle(f"Per-packet timeline — {run_dir.name}", fontsize=13, fontweight="bold")
    fig.tight_layout(rect=[0, 0.03, 1, 1])

    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / f"{run_dir.name}_pcap_flow.png"
    fig.savefig(path, format="png", bbox_inches="tight", dpi=100)
    plt.close(fig)
    click.echo(f"Saved: {path}")


@click.command(context_settings={"help_option_names": ["-h", "--help"]})
@click.option("--run", "run_id", default=None, metavar="YYYYMMDD_HHMMSS", help="Run directory to plot (default: most recent).")
@click.option("--out-dir", default=str(_DEFAULT_OUT_DIR), show_default=True, type=click.Path(), help="Output directory for the PNG.")
def main(run_id: str | None, out_dir: str) -> None:
    """Generate per-packet timeline grid from pcap files of a capture run."""
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

    _plot_timeline(run_dir, Path(out_dir))


if __name__ == "__main__":
    main()
