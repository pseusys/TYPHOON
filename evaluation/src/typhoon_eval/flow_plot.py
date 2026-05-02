"""
TYPHOON flow packet structure visualiser.

Runs a TYPHOON example with capture logging (primary mode) or reads an existing
log file (fallback), then generates a single PNG with one stacked-bar subplot
per paired flow showing per-packet wire composition over time.

c2s and s2c flows that share the same logical connection are detected by
maximising Jaccard overlap of their active time buckets and merged into one
subplot (c2s bars positive, s2c bars negative with hatching).

Two display modes:
  - Bucketed (default): packets are summed into fixed-width time buckets.
  - Per-packet (--per-packet): one bar per packet; x spacing is proportional
    to the inter-packet delay so gaps between bars visually encode time.

Usage (via poe):
    poe plot --example heavy_traffic --out-dir out/
    poe plot --log trace.log --out-dir out/
    poe plot --example hello_world --per-packet --out-dir out/

Usage (direct):
    python -m typhoon_eval.flow_plot --example hello_world --out-dir out/
    python -m typhoon_eval.flow_plot --log trace.log --out-dir out/
    python -m typhoon_eval.flow_plot --example hello_world --per-packet --out-dir out/
"""

import json
import os
import subprocess
import sys
from collections import defaultdict
from pathlib import Path

import click
import matplotlib.patches as mpatches
import matplotlib.pyplot as plt
import numpy as np

# Default path to the typhoon Rust crate, relative to this file.
_DEFAULT_TYPHOON_DIR = Path(__file__).parent.parent.parent.parent / "typhoon"

# Wire-packet component order (bottom → top in each bar).
_COMPONENTS = ["tailor", "crypto", "header", "payload", "body"]

_COLORS = {
    "tailor":  "#555555",
    "crypto":  "#9b59b6",
    "header":  "#e67e22",
    "payload": "#2980b9",
    "body":    "#95a5a6",
}


def _parse_lines(lines: list[str]) -> tuple[list[dict], list[dict]]:
    """
    Extract capture JSONL records from env_logger output lines.

    Returns (packet_records, config_records) separated by ``kind``.
    Config records (kind="Config") carry flow configuration metadata;
    all other records are per-packet measurements.
    """
    packets: list[dict] = []
    configs: list[dict] = []
    for line in lines:
        if "typhoon::capture" not in line:
            continue
        brace = line.find("{")
        if brace == -1:
            continue
        try:
            rec = json.loads(line[brace:])
        except json.JSONDecodeError:
            continue
        if rec.get("kind") == "Config":
            configs.append(rec)
        else:
            packets.append(rec)
    return packets, configs


def _run_example(example: str, typhoon_dir: Path, timeout: int) -> tuple[list[dict], list[dict]]:
    """Build and run a TYPHOON example with capture logging; return (packets, configs)."""
    env = {**os.environ, "RUST_LOG": "typhoon::capture=trace"}
    try:
        result = subprocess.run(
            ["cargo", "run", "--features", "capture", "--example", example],
            cwd=typhoon_dir,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=env,
        )
    except subprocess.TimeoutExpired as exc:
        stderr = exc.stderr or ""
        return _parse_lines((stderr if isinstance(stderr, str) else stderr.decode()).splitlines())
    return _parse_lines(result.stderr.splitlines())


def _auto_bucket_ms(records: list[dict], target_bars: int = 200) -> int:
    """Choose a bucket width (ms) that produces roughly target_bars bars."""
    if len(records) < 2:
        return 10
    duration = max(r["t"] for r in records) - min(r["t"] for r in records)
    return max(1, duration // target_bars)


def _bucket(records: list[dict], bucket_ms: int) -> dict[str, dict[int, dict]]:
    """Group records into time buckets per flow address."""
    t_min = min(r["t"] for r in records)

    def _empty():
        return {"c2s": {c: 0 for c in _COMPONENTS}, "s2c": {c: 0 for c in _COMPONENTS}}

    flows: dict[str, dict[int, dict]] = defaultdict(lambda: defaultdict(_empty))
    for r in records:
        flow = r.get("flow", "unknown")
        bucket = (r["t"] - t_min) // bucket_ms
        direction = r.get("dir", "c2s")
        for comp in _COMPONENTS:
            flows[flow][bucket][direction][comp] += r.get(comp, 0)
    return flows


def _port(addr: str) -> int:
    return int(addr.rsplit(":", 1)[-1])


def _pair_flows(flows: dict[str, dict]) -> list[tuple[str | None, str | None, dict]]:
    """
    Pair c2s-only and s2c-only flows by temporal overlap (Jaccard similarity).

    c2s packets are logged with flow=server_addr; s2c packets with flow=client_addr.
    Matching them reconstructs the full bidirectional picture per connection.
    Returns list of (c2s_addr, s2c_addr, merged_buckets).
    """
    c2s_only: dict[str, dict] = {}
    s2c_only: dict[str, dict] = {}
    mixed: dict[str, dict] = {}

    for addr, buckets in flows.items():
        has_c2s = any(sum(b["c2s"].values()) > 0 for b in buckets.values())
        has_s2c = any(sum(b["s2c"].values()) > 0 for b in buckets.values())
        if has_c2s and has_s2c:
            mixed[addr] = buckets
        elif has_c2s:
            c2s_only[addr] = buckets
        else:
            s2c_only[addr] = buckets

    # Sort by port for deterministic pairing when Jaccard scores are equal
    # (all flows concurrent → same overlap → need a tiebreaker).
    c2s_sorted = sorted(c2s_only, key=_port)
    s2c_sorted = sorted(s2c_only, key=_port)

    used_s2c: set[str] = set()
    paired: list[tuple[str | None, str | None, dict]] = []

    for c2s_addr in c2s_sorted:
        c2s_times = {t for t, b in c2s_only[c2s_addr].items() if sum(b["c2s"].values()) > 0}
        best_match: str | None = None
        best_score = -1.0
        for s2c_addr in s2c_sorted:
            if s2c_addr in used_s2c:
                continue
            s2c_times = {t for t, b in s2c_only[s2c_addr].items() if sum(b["s2c"].values()) > 0}
            union = len(c2s_times | s2c_times)
            score = len(c2s_times & s2c_times) / union if union > 0 else 0.0
            if score > best_score:
                best_score = score
                best_match = s2c_addr

        merged: dict[int, dict] = {
            t: {"c2s": dict(b["c2s"]), "s2c": dict(b["s2c"])}
            for t, b in c2s_only[c2s_addr].items()
        }
        if best_match is not None:
            used_s2c.add(best_match)
            for t, dirs in s2c_only[best_match].items():
                if t in merged:
                    for comp in _COMPONENTS:
                        merged[t]["s2c"][comp] += dirs["s2c"][comp]
                else:
                    merged[t] = {"c2s": {c: 0 for c in _COMPONENTS}, "s2c": dict(dirs["s2c"])}
        paired.append((c2s_addr, best_match, merged))

    for s2c_addr in s2c_sorted:
        if s2c_addr not in used_s2c:
            paired.append((None, s2c_addr, s2c_only[s2c_addr]))

    for addr, buckets in mixed.items():
        paired.append((addr, addr, buckets))

    return paired


def _pair_records(records: list[dict]) -> list[tuple[str | None, str | None, list[dict]]]:
    """
    Pair c2s-only and s2c-only flow record streams using the same Jaccard heuristic
    as _pair_flows, but return per-pair raw record lists for per-packet plotting.
    """
    flow_records: dict[str, list[dict]] = defaultdict(list)
    for r in records:
        flow_records[r.get("flow", "unknown")].append(r)

    bms = _auto_bucket_ms(records)
    flows_bucketed = _bucket(records, bms)
    pairs_info = _pair_flows(flows_bucketed)

    result = []
    for c2s_addr, s2c_addr, _ in pairs_info:
        pair_recs: list[dict] = []
        if c2s_addr:
            pair_recs.extend(flow_records.get(c2s_addr, []))
        if s2c_addr and s2c_addr != c2s_addr:
            pair_recs.extend(flow_records.get(s2c_addr, []))
        pair_recs.sort(key=lambda r: r["t"])
        result.append((c2s_addr, s2c_addr, pair_recs))
    return result


def _compute_xpos(timestamps: list[int]) -> np.ndarray:
    """
    Map packet timestamps to x positions with proportional inter-packet spacing.

    Each packet occupies exactly 1 unit on the x axis; the gap between consecutive
    packets grows with their time difference, normalised by the median inter-packet
    gap so typical neighbours are ~2 units apart and outliers are proportionally wider.
    """
    n = len(timestamps)
    if n <= 1:
        return np.arange(n, dtype=float)
    diffs = np.diff(timestamps).astype(float)
    positive = diffs[diffs > 0]
    median_gap = float(np.median(positive)) if len(positive) > 0 else 1.0
    gap_weight = 1.0 / median_gap
    xpos = np.zeros(n)
    for i, d in enumerate(diffs, start=1):
        xpos[i] = xpos[i - 1] + 1.0 + gap_weight * d
    return xpos


def _config_annotation(
    c2s_addr: str | None,
    s2c_addr: str | None,
    configs: list[dict],
) -> str:
    """
    Build a compact config annotation string for a subplot.

    Looks up Config records matching each flow address and direction,
    then formats: ``body=… header=…B decoy=…`` per direction.
    Returns an empty string if no config records are found.
    """
    by_key: dict[tuple[str, str], dict] = {
        (r.get("flow", ""), r.get("dir", "")): r for r in configs
    }

    def _fmt(addr: str | None, direction: str) -> str:
        if addr is None:
            return ""
        rec = by_key.get((addr, direction))
        if rec is None:
            return ""
        body = rec.get("body_mode", "?")
        hdr = rec.get("header_len", "?")
        decoy = rec.get("decoy", "?")
        return f"{direction}: body={body}  header={hdr}B  decoy={decoy}"

    parts = [p for p in (_fmt(c2s_addr, "c2s"), _fmt(s2c_addr, "s2c")) if p]
    return "\n".join(parts)


def _subplot_title(
    c2s_addr: str | None,
    s2c_addr: str | None,
    configs: list[dict] | None = None,
) -> str:
    if c2s_addr == s2c_addr:
        base = c2s_addr or "unknown"
    else:
        parts = []
        if c2s_addr:
            parts.append(f"→ {c2s_addr} (c2s)")
        if s2c_addr:
            parts.append(f"← {s2c_addr} (s2c)")
        base = "   ".join(parts)

    if configs:
        annotation = _config_annotation(c2s_addr, s2c_addr, configs)
        if annotation:
            return f"{base}\n{annotation}"
    return base


def _draw_bars(ax, times_or_xpos, values_by_direction: dict[str, dict[int | float, dict]]) -> None:
    """Draw stacked bars for both directions onto ax."""
    def _empty_dirs() -> dict:
        return {"c2s": {c: 0 for c in _COMPONENTS}, "s2c": {c: 0 for c in _COMPONENTS}}

    for direction, sign in (("c2s", 1), ("s2c", -1)):
        bottoms: dict = {}
        for comp in _COMPONENTS:
            xs = list(values_by_direction[direction].keys())
            heights = [values_by_direction[direction][x][comp] for x in xs]
            bots = [bottoms.get(x, 0.0) * sign for x in xs]
            ax.bar(
                xs,
                [h * sign for h in heights],
                bottom=bots,
                color=_COLORS[comp],
                hatch="/" if direction == "s2c" else None,
                edgecolor="white",
                linewidth=0.3,
                width=0.8,
            )
            for x, h in zip(xs, heights):
                bottoms[x] = bottoms.get(x, 0.0) + h


def _make_legend() -> tuple[list, list]:
    component_patches = [mpatches.Patch(color=_COLORS[c], label=c) for c in _COMPONENTS]
    direction_patches = [
        mpatches.Patch(facecolor="white", edgecolor="gray", label="c2s (positive)"),
        mpatches.Patch(facecolor="white", edgecolor="gray", hatch="///", label="s2c (negative)"),
    ]
    return component_patches, direction_patches


def _plot_all(
    pairs: list[tuple[str | None, str | None, dict]],
    out_dir: Path,
    bucket_ms: int,
    name: str,
    configs: list[dict] | None = None,
) -> None:
    """Render all paired flows as bucketed stacked-bar subplots in a single PNG."""
    pairs = [(c, s, b) for c, s, b in pairs if b]
    if not pairs:
        return

    all_max_t = max(max(buckets) for _, _, buckets in pairs)
    times = list(range(all_max_t + 1))

    n = len(pairs)
    fig_width = max(14, len(times) * 0.08)
    fig, axes = plt.subplots(n, 1, figsize=(fig_width, 4.5 * n), squeeze=False)
    axes_flat = axes[:, 0]

    component_patches, direction_patches = _make_legend()

    def _empty_dirs() -> dict:
        return {"c2s": {c: 0 for c in _COMPONENTS}, "s2c": {c: 0 for c in _COMPONENTS}}

    for ax, (c2s_addr, s2c_addr, buckets) in zip(axes_flat, pairs):
        values_by_dir: dict[str, dict] = {"c2s": {}, "s2c": {}}
        for t in times:
            dirs = buckets.get(t, _empty_dirs())
            for direction in ("c2s", "s2c"):
                values_by_dir[direction][t] = dirs[direction]
        _draw_bars(ax, times, values_by_dir)

        ax.axhline(0, color="black", linewidth=0.8)
        ax.set_xlabel(f"Time ({bucket_ms} ms buckets)")
        ax.set_ylabel("Bytes")
        ax.set_title(_subplot_title(c2s_addr, s2c_addr, configs), fontsize=8)
        ax.legend(handles=component_patches + direction_patches, loc="upper right", fontsize=8)

    fig.suptitle(name, fontsize=13, fontweight="bold")
    fig.tight_layout()

    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / f"{name}.png"
    fig.savefig(path, format="png", bbox_inches="tight", dpi=100)
    plt.close(fig)
    click.echo(f"Saved: {path}")


def _plot_all_per_packet(
    pairs_with_records: list[tuple[str | None, str | None, list[dict]]],
    out_dir: Path,
    name: str,
    configs: list[dict] | None = None,
) -> None:
    """
    Render all paired flows as per-packet stacked-bar subplots in a single PNG.

    Each bar is exactly one packet. X positions are scaled so the gap between
    consecutive bars is proportional to their inter-packet delay, giving a
    visual time reference while guaranteeing every bar has a visible width.
    """
    pairs_with_records = [(c, s, r) for c, s, r in pairs_with_records if r]
    if not pairs_with_records:
        return

    max_packets = max(len(r) for _, _, r in pairs_with_records)
    fig_width = min(60, max(18, max_packets * 0.08))
    n = len(pairs_with_records)
    fig, axes = plt.subplots(n, 1, figsize=(fig_width, 4.5 * n), squeeze=False)
    axes_flat = axes[:, 0]

    component_patches, direction_patches = _make_legend()

    for ax, (c2s_addr, s2c_addr, pair_records) in zip(axes_flat, pairs_with_records):
        timestamps = [r["t"] for r in pair_records]
        xpos = _compute_xpos(timestamps)

        values_by_dir: dict[str, dict] = {"c2s": {}, "s2c": {}}
        for xi, r in zip(xpos, pair_records):
            direction = r.get("dir", "c2s")
            values_by_dir[direction][xi] = {comp: r.get(comp, 0) for comp in _COMPONENTS}
        # Ensure both directions have entries (empty dicts are fine for _draw_bars)
        _draw_bars(ax, xpos, values_by_dir)

        ax.axhline(0, color="black", linewidth=0.8)
        ax.set_ylabel("Bytes")
        ax.set_title(_subplot_title(c2s_addr, s2c_addr, configs), fontsize=8)
        ax.legend(handles=component_patches + direction_patches, loc="upper right", fontsize=8)

        # Place ~10 time-reference ticks labelled with ms-since-start.
        n_ticks = min(10, len(timestamps))
        tick_indices = np.linspace(0, len(timestamps) - 1, n_ticks, dtype=int)
        t0 = timestamps[0]
        ax.set_xticks([xpos[i] for i in tick_indices])
        ax.set_xticklabels(
            [f"{timestamps[i] - t0} ms" for i in tick_indices],
            rotation=30, ha="right", fontsize=7,
        )
        ax.set_xlabel("Packets (x spacing ∝ inter-packet delay)")

    fig.suptitle(name, fontsize=13, fontweight="bold")
    fig.tight_layout()

    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / f"{name}_packets.png"
    fig.savefig(path, format="png", bbox_inches="tight", dpi=100)
    plt.close(fig)
    click.echo(f"Saved: {path}")


@click.command()
@click.option("--example", default=None, help="Rust example name to compile and run")
@click.option("--log", "log_file", default=None, type=click.Path(), help="Existing log file (use '-' for stdin)")
@click.option("--out-dir", required=True, type=click.Path(), help="Directory for output PNG(s)")
@click.option("--typhoon-dir", default=str(_DEFAULT_TYPHOON_DIR), show_default=True, type=click.Path(exists=True), help="Path to the typhoon Rust crate")
@click.option("--timeout", default=30, show_default=True, help="Timeout in seconds when running an example")
@click.option("--bucket-ms", default=0, show_default=True, help="Time bucket width in ms (0 = auto); ignored with --per-packet")
@click.option("--per-packet", is_flag=True, default=False, help="One bar per packet; x spacing proportional to inter-packet delay")
def main(example: str, log_file: str, out_dir: str, typhoon_dir: str, timeout: int, bucket_ms: int, per_packet: bool) -> None:
    """Generate paired-flow packet structure diagrams from TYPHOON capture logs."""
    if not example and not log_file:
        raise click.UsageError("Provide either --example or --log.")
    if example and log_file:
        raise click.UsageError("--example and --log are mutually exclusive.")

    if example:
        records, configs = _run_example(example, Path(typhoon_dir), timeout)
        name = example
    elif log_file == "-":
        records, configs = _parse_lines(sys.stdin.readlines())
        name = "capture"
    else:
        records, configs = _parse_lines(Path(log_file).read_text().splitlines())
        name = Path(log_file).stem

    if not records:
        click.echo(
            "No capture records found.\n"
            "Ensure the typhoon crate is built with --features capture and "
            "RUST_LOG=typhoon::capture=trace is set.",
            err=True,
        )
        sys.exit(1)

    out = Path(out_dir)
    if per_packet:
        pairs = _pair_records(records)
        _plot_all_per_packet(pairs, out, name, configs)
    else:
        bms = bucket_ms if bucket_ms > 0 else _auto_bucket_ms(records)
        flows = _bucket(records, bms)
        pairs = _pair_flows(flows)
        _plot_all(pairs, out, bms, name, configs)


if __name__ == "__main__":
    main()
