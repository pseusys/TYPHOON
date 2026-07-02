"""TYPHOON flow packet-structure visualiser.

Runs a TYPHOON example with capture logging (or reads an existing log file)
and produces a stacked-bar PNG with one subplot per paired flow. c2s and s2c
flows of the same connection are merged via max-Jaccard overlap of active
time buckets (c2s positive, s2c negative; outlines encode packet kind).

Display modes: bucketed (sum into fixed-width buckets, default) or
per-packet (one bar per packet; x spacing proportional to inter-packet
delay so gaps visually encode time).
"""

from collections import defaultdict
from json import JSONDecodeError, loads
from os import environ
from pathlib import Path
from subprocess import TimeoutExpired, run
from sys import exit, stdin

import numpy as np
from click import Path as ClickPath
from click import UsageError, command, echo, option
from matplotlib import patches as mpatches
from matplotlib import pyplot as plt
from matplotlib.axes import Axes

# Default path to the typhoon Rust crate, relative to this file.
_DEFAULT_TYPHOON_DIR = Path(__file__).parent.parent.parent.parent.parent / "typhoon"

# Wire-packet component order (bottom → top in each bar).
_COMPONENTS = ["trailer", "crypto", "header", "payload", "body"]
# Minimum records to autoscale a histogram bucket — below this we fall back to 10 ms.
MIN_RECORDS_FOR_AUTO_BUCKET = 2

_COLORS = {
    "trailer":  "#555555",
    "crypto":  "#9b59b6",
    "header":  "#e67e22",
    "payload": "#2980b9",
    "body":    "#95a5a6",
}

_KIND_EDGE_COLORS = {
    "Data":    "#2c3e50",
    "Service": "#f39c12",
    "Decoy":   "#e74c3c",
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
            rec = loads(line[brace:])
        except JSONDecodeError:
            continue
        if rec.get("kind") == "Config":
            configs.append(rec)
        else:
            packets.append(rec)
    return packets, configs


def _run_example(example: str, typhoon_dir: Path, timeout: int, extra_env: dict | None = None) -> tuple[list[dict], list[dict]]:
    """Build and run a TYPHOON example with capture logging; return (packets, configs)."""
    env = {**environ, "RUST_LOG": "typhoon::capture=trace", **(extra_env or {})}
    try:
        result = run(
            ["cargo", "run", "--features", "capture", "--example", example],
            cwd=typhoon_dir,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=env,
        )
    except TimeoutExpired as exc:
        stderr = exc.stderr or ""
        return _parse_lines((stderr if isinstance(stderr, str) else stderr.decode()).splitlines())
    return _parse_lines(result.stderr.splitlines())


def _auto_bucket_ms(records: list[dict], target_bars: int = 200) -> int:
    """Choose a bucket width (ms) that produces roughly target_bars bars."""
    if len(records) < MIN_RECORDS_FOR_AUTO_BUCKET:
        return 10
    duration = max(r["t"] for r in records) - min(r["t"] for r in records)
    return max(1, duration // target_bars)


def _bucket(records: list[dict], bucket_ms: int) -> dict[str, dict[int, dict]]:
    """Group records into time buckets per flow address."""
    t_min = min(r["t"] for r in records)

    def _empty() -> dict[str, dict[str, int]]:
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

    paired.extend((None, s2c_addr, s2c_only[s2c_addr]) for s2c_addr in s2c_sorted if s2c_addr not in used_s2c)
    paired.extend((addr, addr, buckets) for addr, buckets in mixed.items())

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
        pair_recs.sort(key=lambda r: r["t"])
        result.append((c2s_addr, s2c_addr, pair_recs))
    return result


def _compute_xpos(timestamps: list[int]) -> np.ndarray:
    """
    Map packet timestamps to x positions with proportional inter-packet spacing.

    Each packet occupies exactly 1 unit on the x axis; the gap between consecutive
    packets grows with their time difference, normalised by the median inter-packet
    gap so typical neighbours are ~2 units apart. Gaps larger than 10× the median
    are capped to prevent rare large delays (e.g. infrequent decoy packets) from
    compressing all other bars to sub-pixel width.
    """
    n = len(timestamps)
    if n <= 1:
        return np.arange(n, dtype=float)
    diffs = np.diff(timestamps).astype(float)
    positive = diffs[diffs > 0]
    median_gap = float(np.median(positive)) if len(positive) > 0 else 1.0
    gap_weight = 1.0 / median_gap
    gap_cap = median_gap * 10.0
    xpos = np.zeros(n)
    for i, d in enumerate(diffs, start=1):
        xpos[i] = xpos[i - 1] + 1.0 + gap_weight * min(float(d), gap_cap)
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


def _draw_bars(ax: Axes, times_or_xpos: list[float] | list[int], values_by_direction: dict[str, dict[int | float, dict]], kind_by_xpos: dict | None = None) -> None:
    """Draw stacked bars for both directions onto ax."""
    for direction, sign in (("c2s", 1), ("s2c", -1)):
        bottoms: dict = {}
        for comp in _COMPONENTS:
            xs = list(values_by_direction[direction].keys())
            heights = [values_by_direction[direction][x][comp] for x in xs]
            bots = [bottoms.get(x, 0.0) * sign for x in xs]
            if kind_by_xpos is not None:
                edge_colors = [_KIND_EDGE_COLORS.get(kind_by_xpos.get(x, "Data"), "#2c3e50") for x in xs]
                lw = 0.4
            else:
                edge_colors = "white"
                lw = 0.3
            ax.bar(
                xs,
                [h * sign for h in heights],
                bottom=bots,
                color=_COLORS[comp],
                edgecolor=edge_colors,
                linewidth=lw,
                width=0.8,
            )
            for x, h in zip(xs, heights, strict=True):
                bottoms[x] = bottoms.get(x, 0.0) + h


def _make_legend(with_kinds: bool = False) -> tuple[list, list]:
    component_patches = [mpatches.Patch(color=_COLORS[c], label=c) for c in _COMPONENTS]
    direction_patches = [
        mpatches.Patch(facecolor="white", edgecolor="gray", label="c2s (positive)"),
        mpatches.Patch(facecolor="white", edgecolor="gray", label="s2c (negative)"),
    ]
    if with_kinds:
        kind_patches = [mpatches.Patch(facecolor="gray", edgecolor=ec, linewidth=1.5, label=k) for k, ec in _KIND_EDGE_COLORS.items()]
        return component_patches, direction_patches, kind_patches
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

    for ax, (c2s_addr, s2c_addr, buckets) in zip(axes_flat, pairs, strict=True):
        values_by_dir: dict[str, dict] = {"c2s": {}, "s2c": {}}
        for t in times:
            dirs = buckets.get(t, _empty_dirs())
            for direction in ("c2s", "s2c"):
                values_by_dir[direction][t] = dirs[direction]
        _draw_bars(ax, times, values_by_dir, kind_by_xpos=None)

        ax.axhline(0, color="black", linewidth=0.8)
        ax.set_xlabel(f"Time ({bucket_ms} ms buckets)")
        ax.set_ylabel("Bytes")
        ax.set_title(_subplot_title(c2s_addr, s2c_addr, configs), fontsize=8)
        ax.legend(handles=component_patches + direction_patches, loc="upper right", fontsize=8)

    fig.suptitle(name, fontsize=13, fontweight="bold")
    fig.tight_layout()

    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / f"{name}.pdf"
    fig.savefig(path, format="pdf", bbox_inches="tight")
    plt.close(fig)
    echo(f"Saved: {path}")


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

    # Pre-compute xpos for all pairs to size the figure so bars are always ≥ 2 px.
    all_xpos = [_compute_xpos([r["t"] for r in recs]) for _, _, recs in pairs_with_records]
    max_xpos_range = max((xp[-1] - xp[0]) for xp in all_xpos if len(xp) > 1) if all_xpos else 1.0
    fig_width = max(18.0, max_xpos_range * 5.0 / (0.8 * 100))  # ensure ≥ 5 px/bar at 100 dpi
    fig_width = min(120.0, fig_width)

    n = len(pairs_with_records)
    fig, axes = plt.subplots(n, 1, figsize=(fig_width, 4.5 * n), squeeze=False)
    axes_flat = axes[:, 0]

    component_patches, direction_patches, kind_patches = _make_legend(with_kinds=True)

    for ax, (c2s_addr, s2c_addr, pair_records), xpos in zip(axes_flat, pairs_with_records, all_xpos, strict=True):
        timestamps = [r["t"] for r in pair_records]

        values_by_dir: dict[str, dict] = {"c2s": {}, "s2c": {}}
        kind_by_xpos: dict[float, str] = {}
        for xi, r in zip(xpos, pair_records, strict=True):
            direction = r.get("dir", "c2s")
            values_by_dir[direction][xi] = {comp: r.get(comp, 0) for comp in _COMPONENTS}
            kind_by_xpos[xi] = r.get("kind", "Data")
        _draw_bars(ax, xpos, values_by_dir, kind_by_xpos=kind_by_xpos)

        ax.axhline(0, color="black", linewidth=0.8)
        ax.set_ylabel("Bytes")
        ax.set_title(_subplot_title(c2s_addr, s2c_addr, configs), fontsize=8)
        ax.legend(handles=component_patches + direction_patches + kind_patches, loc="upper right", fontsize=8)

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
    path = out_dir / f"{name}_packets.pdf"
    fig.savefig(path, format="pdf", bbox_inches="tight")
    plt.close(fig)
    echo(f"Saved: {path}")


@command()
@option("--example", default=None, help="Rust example name to compile and run")
@option("--log", "log_file", default=None, type=ClickPath(), help="Existing log file (use '-' for stdin)")
@option("--out-dir", required=True, type=ClickPath(), help="Directory for output PNG(s)")
@option("--typhoon-dir", default=str(_DEFAULT_TYPHOON_DIR), show_default=True, type=ClickPath(exists=True), help="Path to the typhoon Rust crate")
@option("--timeout", default=30, show_default=True, help="Timeout in seconds when running an example")
@option("--bucket-ms", default=0, show_default=True, help="Time bucket width in ms (0 = auto); ignored with --per-packet")
@option("--per-packet/--bucketed", default=True, help="One bar per packet (default) or bucket-aggregated bars")
def main(example: str, log_file: str, out_dir: str, typhoon_dir: str, timeout: int, bucket_ms: int, per_packet: bool) -> None:
    """Generate paired-flow packet structure diagrams from TYPHOON capture logs."""
    if not example and not log_file:
        raise UsageError("Provide either --example or --log.")
    if example and log_file:
        raise UsageError("--example and --log are mutually exclusive.")

    if example:
        records, configs = _run_example(example, Path(typhoon_dir), timeout)
        name = example
    elif log_file == "-":
        records, configs = _parse_lines(stdin.readlines())
        name = "capture"
    else:
        records, configs = _parse_lines(Path(log_file).read_text().splitlines())
        name = Path(log_file).stem

    if not records:
        echo(
            "No capture records found.\n"
            "Ensure the typhoon crate is built with --features capture and "
            "RUST_LOG=typhoon::capture=trace is set.",
            err=True,
        )
        exit(1)

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
