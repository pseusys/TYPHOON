"""TYPHOON load / stress test: sweep flood duration × flows × server reader sockets.

The **dockerized flood** is the core; the host criterion bench and the flamegraph are optional and
share one Rust impl (`benches/load.rs`):

  * **dockerized flood** (always) — the eval TYPHOON client/server containers (`EVAL_MODE=load`) run
    the realistic obfuscated profile over a real veth network via `compose/docker-compose.load.yml`.
    Per cell we sample **both** containers' memory + CPU with `docker stats` (peak + growth slope, to
    test server queue-memory growth) and read throughput + loss (application sequence gaps plus the
    core `drain_drops` / `recv_errors` counters from `typhoon::record_loss`) from the logs.
  * **host criterion `load` bench** (`--criterion`) — in-process one-way send throughput per flow
    count; isolates the raw send pipeline (the throughput ceiling).
  * **flamegraph** (`--flamegraph`) — a `perf` flamegraph of that same `load` bench (in-process
    client+server send/recv hot path). Auto-skips without perf + cargo-flamegraph.

Linux + a running Docker daemon required. Mirrors `.github/workflows/evaluation.yaml`. Outputs into
`--out-dir`: `load_test.json` (raw grid), `load_test.pdf` (summary), `load_test_table.md` (per-cell
table + auto-derived findings), and `flamegraphs/load.{svg,pdf}` when the flamegraph runs.
"""

from __future__ import annotations

from contextlib import suppress
from itertools import product
from json import dumps, loads
from os import environ
from pathlib import Path
from platform import system
from random import Random
from re import compile as re_compile
from shutil import which
from subprocess import DEVNULL, PIPE, STDOUT, TimeoutExpired, run
from threading import Event, Thread
from time import monotonic

import numpy as np
from click import ClickException, command, option
from click import Path as ClickPath
from matplotlib import pyplot as plt
from python_on_whales import DockerClient, DockerException

from typhoon_eval.shared.console import console
from typhoon_eval.shared.docker_utils import COMPOSE_DIR, _overlay_env
from typhoon_eval.shared.profiles import PROFILES, profile_to_env

TYPHOON_ROOT = Path(__file__).parent.parent.parent.parent.parent / "typhoon"
BENCH_KEY    = TYPHOON_ROOT / ".bench_keys" / "server_fast.key"
DEFAULT_OUT  = Path(__file__).parent.parent.parent.parent.parent / "artifacts" / "loadtest"

# fast_software build key env var (the default feature set used by the host criterion bench).
KEY_ENV_VAR = "TYPHOON_TEST_SERVER_KEY_FAST"
MEGABYTE    = 1024 * 1024

# Dockerized load sweep (minimal compose: server + client, no observer).
LOAD_COMPOSE  = COMPOSE_DIR / "docker-compose.load.yml"
SERVER_IMAGE  = "typhoon-eval-typhoon-server"
CLIENT_IMAGE  = "typhoon-eval-typhoon-client"
LOAD_PROJECT  = "typhoon-eval-load"
# Server ends a run this long after the last packet; also the client-flood grace.
LOAD_IDLE_S       = 8
SERVER_WAIT_TIMEOUT_S = 300.0
DOCKER_SAMPLE_INTERVAL_S = 0.3
# A per-run memory-growth slope above this (MB/s) is flagged as queue/leak growth rather than noise.
MEM_GROWTH_THRESHOLD_MB_S = 0.5
BUILD_COMPOSE   = COMPOSE_DIR / "docker-compose.build.yml"

_BENCHER_RE   = re_compile(r"test load/f(\d+)/(\d+)\s+\.\.\.\s+bench:\s+(\d+)\s+ns/iter")
_CAPTURE_RE   = re_compile(r"typhoon::capture")
_THROUGHPUT_RE = re_compile(r"throughput_mbps=([\d.]+)")


# ── shared cargo helpers (mirrors the retired benchmark.py) ───────────────────

def _run(label: str, cmd: list[str], env: dict[str, str] | None = None, capture: Path | None = None) -> bool:
    console.print(f"  [dim]$ {' '.join(cmd)}[/dim]")
    run_env = {**environ, **env} if env else None
    if capture:
        with capture.open("w") as fh:
            result = run(cmd, cwd=TYPHOON_ROOT, env=run_env, stdin=DEVNULL, stdout=fh, stderr=STDOUT)
    else:
        result = run(cmd, cwd=TYPHOON_ROOT, env=run_env, stdin=DEVNULL)
    if result.returncode != 0:
        console.print(f"  [red]✗ {label} failed (exit {result.returncode})[/red]")
    return result.returncode == 0


def _svg_to_pdf(svg_path: Path) -> bool:
    """Render a same-named .pdf from *svg_path* via rsvg-convert, keeping the .svg too."""
    pdf_path = svg_path.with_suffix(".pdf")
    return _run(f"svg2pdf-{svg_path.stem}", ["rsvg-convert", "-f", "pdf", "-o", str(pdf_path), str(svg_path)])


# ── per-container docker-stats sampling ───────────────────────────────────────

def _sample_containers(dc: DockerClient, stop: Event, out: dict) -> None:
    """Poll `docker stats` until *stop*, recording (t, mem_bytes, cpu_pct) per container role."""
    while not stop.is_set():
        try:
            snapshots = dc.stats()
        except Exception:  # noqa: BLE001 — transient (container gone) is fine
            snapshots = []
        now = monotonic()
        for snap in snapshots:
            name = snap.container_name
            role = "server" if name.endswith("-server-1") else "client" if name.endswith("-client-1") else None
            if role is not None:
                out[role].append((now, int(snap.memory_used), float(snap.cpu_percentage)))
        stop.wait(DOCKER_SAMPLE_INTERVAL_S)


def _mem_summary(series: list[tuple[float, int, float]]) -> dict:
    """Peak RSS (MB), linear growth slope (MB/s over the run), and mean CPU % from a sample series."""
    if not series:
        return {"peak_mb": 0.0, "growth_mb_s": 0.0, "cpu_pct": 0.0}
    ts = np.array([t for t, _, _ in series])
    mem_mb = np.array([m for _, m, _ in series]) / MEGABYTE
    cpu = np.array([c for _, _, c in series])
    slope = float(np.polyfit(ts - ts[0], mem_mb, 1)[0]) if len(series) > 1 and ts[-1] > ts[0] else 0.0
    return {"peak_mb": float(mem_mb.max()), "growth_mb_s": slope, "cpu_pct": float(cpu.mean())}


# ── capture-log parsing ───────────────────────────────────────────────────────

def _capture_records(text: str) -> list[dict]:
    """Extract JSONL records emitted on the `typhoon::capture` log target from stderr text."""
    records: list[dict] = []
    for line in text.splitlines():
        if not _CAPTURE_RE.search(line):
            continue
        brace = line.find("{")
        if brace == -1:
            continue
        try:
            records.append(loads(line[brace:]))
        except ValueError:
            continue
    return records


CELL_KEYS = (
    "packets", "bytes", "seq_gaps", "drain_drops", "recv_errors", "loss_pct", "client_throughput_mbps",
    "server_peak_mb", "server_growth_mb_s", "server_cpu_pct",
    "client_peak_mb", "client_growth_mb_s", "client_cpu_pct",
)


# ── dockerized load cell (throughput / loss / per-container memory) ────────────

def _run_docker_cell(flows: int, readers: int, duration_s: float, payload: int, profile: str, profile_env: dict) -> dict | None:
    """Run one server+client container pair over the minimal load compose.

    The client floods for `duration_s` seconds (duration-driven, so the run lasts long enough to
    sample regardless of host speed). Samples both containers' memory + CPU via `docker stats` during
    the flood, waits for the server to exit, then parses throughput + LoadStats/Loss from the logs.
    *profile_env* carries the sampled realistic-profile PROFILE_* vars the eval binaries consume.
    """
    env = {
        **profile_env,
        "SERVER_IMAGE": SERVER_IMAGE,
        "CLIENT_IMAGE": CLIENT_IMAGE,
        "LOAD_DURATION_S": f"{duration_s:g}",
        "LOAD_PAYLOAD": str(payload),
        "LOAD_FLOWS": str(flows),
        "LOAD_READERS": str(readers),
        "TRAFFIC_PROFILE": profile,
        "IDLE_TIMEOUT_S": str(LOAD_IDLE_S),
        "SERVER_RUST_LOG": "typhoon::capture=trace",
    }
    with _overlay_env(env):
        dc = DockerClient(compose_files=[LOAD_COMPOSE], compose_project_name=LOAD_PROJECT)
        with suppress(Exception):
            dc.compose.down(volumes=True, remove_orphans=True, quiet=True)

        try:
            dc.compose.up(detach=True, quiet=True)
        except DockerException:
            console.print(f"  [yellow]⚠ compose up failed (f{flows} r{readers} {duration_s:g}s) — skipping[/yellow]")
            with suppress(Exception):
                dc.compose.down(volumes=True, remove_orphans=True, quiet=True)
            return None

        samples: dict = {"server": [], "client": []}
        stop = Event()
        sampler = Thread(target=_sample_containers, args=(dc, stop, samples), daemon=True)
        sampler.start()

        server_name = f"{LOAD_PROJECT}-server-1"

        def _wait_server() -> None:
            with suppress(Exception):
                dc.container.wait(server_name)

        waiter = Thread(target=_wait_server, daemon=True)
        waiter.start()
        waiter.join(timeout=SERVER_WAIT_TIMEOUT_S)
        if waiter.is_alive():
            console.print(f"  [yellow]⚠ server did not finish in {SERVER_WAIT_TIMEOUT_S:.0f}s (f{flows} r{readers} {duration_s:g}s)[/yellow]")

        stop.set()
        sampler.join()

        server_log = client_log = ""
        with suppress(Exception):
            server_log = dc.container.logs(server_name)
        with suppress(Exception):
            client_log = dc.container.logs(f"{LOAD_PROJECT}-client-1")
        with suppress(Exception):
            dc.compose.down(volumes=True, remove_orphans=True, quiet=True)

    records = _capture_records(server_log)
    stats = next((r for r in records if r.get("kind") == "LoadStats"), {})
    loss = next((r for r in records if r.get("kind") == "Loss"), {})
    tput = _THROUGHPUT_RE.search(client_log)

    packets = int(stats.get("packets", 0))
    seq_gaps = int(stats.get("seq_gaps", 0))
    sent_estimate = packets + seq_gaps
    srv = _mem_summary(samples["server"])
    cli = _mem_summary(samples["client"])

    return {
        "packets": packets,
        "bytes": int(stats.get("bytes", 0)),
        "seq_gaps": seq_gaps,
        "drain_drops": int(loss.get("drain_drops", 0)),
        "recv_errors": int(loss.get("recv_errors", 0)),
        "loss_pct": (100.0 * seq_gaps / sent_estimate) if sent_estimate else 0.0,
        "client_throughput_mbps": float(tput.group(1)) if tput else 0.0,
        "server_peak_mb": srv["peak_mb"],
        "server_growth_mb_s": srv["growth_mb_s"],
        "server_cpu_pct": srv["cpu_pct"],
        "client_peak_mb": cli["peak_mb"],
        "client_growth_mb_s": cli["growth_mb_s"],
        "client_cpu_pct": cli["cpu_pct"],
    }


# ── criterion throughput ──────────────────────────────────────────────────────

def _run_throughput(flows: list[int], readers: list[int], bench_seconds: float) -> dict[int, float]:
    """Run `cargo bench --bench load` over the flow grid; return flow-count → one-way MB/s (max size).

    The bench is one-way (client send only), so it is client-bound and independent of readers — hence
    keyed by flow count alone. Bounded by a wall-clock timeout so a pathological setup can never wedge
    the sweep; on timeout, whatever cells were parsed before the kill are still returned.
    """
    env = {
        **environ,
        KEY_ENV_VAR: str(BENCH_KEY),
        "TYPHOON_LOAD_BENCH_FLOWS": ",".join(map(str, flows)),
        "TYPHOON_LOAD_BENCH_READERS": ",".join(map(str, readers)),
    }
    # Generous per-grid budget: one setup per flow count × 2 sizes, each a warm-up + measurement
    # window, plus the McEliece handshake setup cost; timeout only trips on a genuine wedge.
    budget = 90.0 + max(1, len(flows)) * (bench_seconds + 1.0) * 6
    try:
        proc = run(
            ["cargo", "bench", "--bench", "load", "--", "--output-format", "bencher",
             "--warm-up-time", "0.5", "--measurement-time", str(bench_seconds), "--sample-size", "20"],
            cwd=TYPHOON_ROOT, env=env, stdin=DEVNULL, stdout=PIPE, stderr=STDOUT, text=True, timeout=budget,
        )
        stdout = proc.stdout
    except TimeoutExpired as exc:
        console.print(f"  [yellow]⚠ throughput bench exceeded {budget:.0f}s — using partial results[/yellow]")
        stdout = exc.stdout.decode() if isinstance(exc.stdout, bytes) else (exc.stdout or "")
    best: dict[int, float] = {}
    best_size: dict[int, int] = {}
    for match in _BENCHER_RE.finditer(stdout):
        f, size, ns = int(match[1]), int(match[2]), int(match[3])
        mbps = (size / MEGABYTE) / (ns / 1e9)
        if size >= best_size.get(f, 0):  # report throughput at the largest transfer size
            best_size[f] = size
            best[f] = mbps
    return best


# ── plotting ──────────────────────────────────────────────────────────────────

def _config_labels(flows: list[int], readers: list[int]) -> list[tuple[int, int]]:
    return [(f, r) for f in flows for r in readers]


def _plot(results: dict, flows: list[int], readers: list[int], durations: list[float], throughput: dict, out_dir: Path) -> Path:
    configs = _config_labels(flows, readers)
    labels = [f"f{f}·r{r}" for f, r in configs]
    x = np.arange(len(configs))
    dur_colors = plt.cm.viridis(np.linspace(0.15, 0.85, len(durations)))

    def cfg_max(key: str) -> list[float]:
        return [max(results[(f, r, d)][key] for d in durations) for f, r in configs]

    fig, axes = plt.subplots(3, 2, figsize=(15, 15))
    (ax_thr, ax_tput), (ax_rss, ax_growth), (ax_loss, ax_text) = axes

    # Panel A — host criterion one-way send throughput per flow (client-bound; raw send path).
    fx = np.arange(len(flows))
    ax_thr.bar(fx, [throughput.get(f, 0.0) for f in flows], color="#2980b9", alpha=0.85)
    ax_thr.set_xticks(fx)
    ax_thr.set_xticklabels([f"{f} flow(s)" for f in flows])
    ax_thr.set_ylabel("MB/s")
    ax_thr.set_title("Host criterion raw send throughput (per flow)")
    ax_thr.grid(True, axis="y", alpha=0.3)

    bar_w = 0.8 / max(1, len(durations))
    # Panel B — dockerized end-to-end flood throughput, grouped by flood duration.
    # Panel D (ax_loss) — application packet loss %, grouped by flood duration.
    for di, dur in enumerate(durations):
        offset = (di - (len(durations) - 1) / 2) * bar_w
        tput = [results[(f, r, dur)]["client_throughput_mbps"] for f, r in configs]
        loss = [results[(f, r, dur)]["loss_pct"] for f, r in configs]
        ax_tput.bar(x + offset, tput, bar_w, color=dur_colors[di], label=f"{dur:g} s")
        ax_loss.bar(x + offset, loss, bar_w, color=dur_colors[di], label=f"{dur:g} s")
    for ax, title, ylabel in ((ax_tput, "Docker end-to-end flood throughput", "MB/s"), (ax_loss, "Application packet loss", "Loss (%)")):
        ax.set_xticks(x)
        ax.set_xticklabels(labels, rotation=20, ha="right")
        ax.set_ylabel(ylabel)
        ax.set_title(title)
        ax.grid(True, axis="y", alpha=0.3)
        ax.legend(fontsize=8)

    # Panel C — peak container memory (server vs client), max across durations per config.
    # Panel E — memory growth slope (server vs client) — tests the queue-growth hypothesis.
    half = bar_w if len(durations) == 1 else 0.2
    for ax, skey, ckey, title, ylabel in (
        (ax_rss, "server_peak_mb", "client_peak_mb", "Peak container memory", "Peak RSS (MB)"),
        (ax_growth, "server_growth_mb_s", "client_growth_mb_s", "Memory growth under load", "Growth (MB/s)"),
    ):
        ax.bar(x - half / 2, cfg_max(skey), half, color="#c0392b", label="server")
        ax.bar(x + half / 2, cfg_max(ckey), half, color="#16a085", label="client")
        ax.set_xticks(x)
        ax.set_xticklabels(labels, rotation=20, ha="right")
        ax.set_ylabel(ylabel)
        ax.set_title(title)
        ax.grid(True, axis="y", alpha=0.3)
        ax.legend(fontsize=8)
    ax_growth.axhline(0, color="black", linewidth=0.6)

    # Panel F — findings.
    ax_text.axis("off")
    ax_text.text(0.0, 1.0, _findings_text(results, flows, readers, durations, throughput), va="top", ha="left", fontsize=9, family="monospace", transform=ax_text.transAxes)

    fig.suptitle("TYPHOON load test — dockerized flood (realistic profile) + per-container memory", fontsize=14, fontweight="bold")
    fig.tight_layout(rect=[0, 0, 1, 0.98])
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / "load_test.pdf"
    fig.savefig(path, format="pdf", bbox_inches="tight")
    plt.close(fig)
    return path


# ── findings / table ──────────────────────────────────────────────────────────

def _findings(results: dict, flows: list[int], readers: list[int], durations: list[float], throughput: dict) -> list[str]:
    lines: list[str] = []
    if throughput:
        best_f = max(throughput, key=throughput.get)
        lines.append(f"Best one-way send throughput: {throughput[best_f]:.2f} MB/s at {best_f} flow(s).")
        if len(flows) > 1:
            base = throughput.get(flows[0], 0.0)
            top = throughput.get(flows[-1], 0.0)
            if base and top <= base * 1.15:
                trend = "flat" if top >= base * 0.85 else "drops"
                lines.append(f"Send throughput {trend} across flows ({base:.2f}→{top:.2f} MB/s, {flows[0]}→{flows[-1]}) — adding flows does not help; the per-packet send path is the bottleneck.")
    cells = [results[(f, r, d)] for f in flows for r in readers for d in durations]
    max_client = max((c["client_throughput_mbps"] for c in cells), default=0.0)
    lines.append(f"Docker end-to-end flood peaks at {max_client:.2f} MB/s (realistic profile, server-inclusive).")

    max_srv_peak = max((c["server_peak_mb"] for c in cells), default=0.0)
    max_srv_growth = max((c["server_growth_mb_s"] for c in cells), default=0.0)
    max_cli_peak = max((c["client_peak_mb"] for c in cells), default=0.0)
    lines.append(f"Peak memory: server {max_srv_peak:.1f} MB, client {max_cli_peak:.1f} MB.")
    if max_srv_growth > MEM_GROWTH_THRESHOLD_MB_S:
        lines.append(f"Server memory GROWS at up to {max_srv_growth:.2f} MB/s under load — queue growth confirmed.")
    else:
        lines.append(f"Server memory stable (max slope {max_srv_growth:.2f} MB/s) — bounded queues hold; no runaway growth.")

    lossy = [(d, f, r) for d in durations for f in flows for r in readers if results[(f, r, d)]["loss_pct"] > 0]
    if lossy:
        d, f, r = min(lossy, key=lambda c: (c[0], -c[1], -c[2]))
        cell = results[(f, r, d)]
        if cell["drain_drops"] == 0 and cell["recv_errors"] == 0:
            where = "kernel socket buffer"  # seq gaps with no core-counter hits = dropped before the drain channel
        elif cell["drain_drops"] >= cell["recv_errors"]:
            where = "drain channel"
        else:
            where = "socket recv"
        lines.append(f"Loss onset: {cell['loss_pct']:.2f}% at f{f}·r{r} {d:g}s (mostly {where}).")
    else:
        lines.append("No packet loss across the grid — the client can't saturate the server at these rates.")
    return lines


def _findings_text(results: dict, flows: list[int], readers: list[int], durations: list[float], throughput: dict) -> str:
    body = "\n".join(f"• {line}" for line in _findings(results, flows, readers, durations, throughput))
    return "Findings & critical path\n" + "-" * 28 + "\n" + body + "\n\nSee flamegraphs/load.svg (if present)\nfor the send/recv hot path."


def _write_table(results: dict, flows: list[int], readers: list[int], durations: list[float], throughput: dict, out_dir: Path) -> Path:
    lines = ["# TYPHOON Load / Scaling Test", "",
             "`Send MB/s` is the host criterion **one-way send** micro-benchmark (client-bound, per flow "
             "count). `Flood MB/s`, memory, and loss are from the **dockerized** flood with the realistic "
             "eval profile; each cell floods for the given duration and memory is per-container peak + "
             "linear growth slope over the run.", "",
             "| Flows | Readers | Dur (s) | Send MB/s | Flood MB/s | Srv peak MB | Srv grow MB/s | Cli peak MB | Loss % | drops | rx_err |",
             "|------:|--------:|--------:|----------:|-----------:|------------:|--------------:|------------:|-------:|------:|-------:|"]
    for f, r in _config_labels(flows, readers):
        for d in durations:
            c = results[(f, r, d)]
            thr = throughput.get(f, 0.0)
            lines.append(f"| {f} | {r} | {d:g} | {thr:.2f} | {c['client_throughput_mbps']:.2f} | {c['server_peak_mb']:.1f} | {c['server_growth_mb_s']:.2f} | {c['client_peak_mb']:.1f} | {c['loss_pct']:.2f} | {c['drain_drops']} | {c['recv_errors']} |")
    lines += ["", "## Findings", ""] + [f"- {line}" for line in _findings(results, flows, readers, durations, throughput)]
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / "load_test_table.md"
    path.write_text("\n".join(lines) + "\n")
    return path


# ── flamegraph (load bench: in-process client+server send/recv hot path) ───────

def _perf_paranoid() -> int | None:
    """Current kernel.perf_event_paranoid, or None if unreadable."""
    try:
        return int(Path("/proc/sys/kernel/perf_event_paranoid").read_text().strip())
    except (OSError, ValueError):
        return None


def _flamegraph(out_dir: Path) -> bool:
    """Flamegraph the `load` bench — the in-process client+server send/recv hot path.

    Auto-skips (returns False) when cargo-flamegraph is absent or perf sampling is disallowed.
    """
    if which("cargo-flamegraph") is None:
        console.print("  [yellow]⚠ cargo-flamegraph not installed — skipping flamegraph[/yellow]")
        return False
    paranoid = _perf_paranoid()
    if paranoid is not None and paranoid > 1:
        console.print(f"  [yellow]⚠ perf sampling disallowed (perf_event_paranoid={paranoid}, need ≤1) — skipping flamegraph[/yellow]")
        return False

    flame_dir = out_dir / "flamegraphs"
    flame_dir.mkdir(parents=True, exist_ok=True)
    svg = flame_dir / "load.svg"
    env = {
        **environ, KEY_ENV_VAR: str(BENCH_KEY),
        "TYPHOON_LOAD_BENCH_FLOWS": "2", "TYPHOON_LOAD_BENCH_READERS": "1", "TYPHOON_LOAD_BENCH_SIZES": "32768",
        "RUSTFLAGS": "-D warnings",
    }
    ok = _run(
        "flamegraph",
        ["cargo", "flamegraph", "--bench", "load", "-o", str(svg), "--",
         "--bench", "--warm-up-time", "0.5", "--measurement-time", "3", "load/f2"],
        env=env,
    )
    if not (ok and svg.exists()):
        console.print("  [yellow]⚠ flamegraph did not produce output (perf denied?) — skipping[/yellow]")
        return False
    if which("rsvg-convert") is not None:
        _svg_to_pdf(svg)
    return True


# ── CLI ───────────────────────────────────────────────────────────────────────

def _int_list(raw: str) -> list[int]:
    return [int(v) for v in raw.split(",") if v.strip()]


def _float_list(raw: str) -> list[float]:
    return [float(v) for v in raw.split(",") if v.strip()]


def _docker_available() -> bool:
    try:
        DockerClient().info()
        return True
    except Exception:  # noqa: BLE001
        return False


def _build_images() -> bool:
    """Build the typhoon server + client images the load compose uses."""
    return _shell_build(["docker", "compose", "-f", str(BUILD_COMPOSE), "build", "typhoon-server", "typhoon-client"])


def _shell_build(cmd: list[str]) -> bool:
    console.print(f"  [dim]$ {' '.join(cmd)}[/dim]")
    result = run(cmd, env={**environ, "DOCKER_BUILDKIT": "1", "COMPOSE_DOCKER_CLI_BUILD": "1"}, stdin=DEVNULL)
    return result.returncode == 0


@command(context_settings={"help_option_names": ["-h", "--help"]})
@option("--durations", default="5,15", show_default=True, help="Comma-separated flood durations in seconds (docker flood; two values also probe memory growth over time).")
@option("--flows", default="1,2,4", show_default=True, help="Comma-separated flow (UDP port) counts.")
@option("--readers", default="1,2", show_default=True, help="Comma-separated SO_REUSEPORT reader counts per flow.")
@option("--payload", default=1024, show_default=True, type=int, help="Per-packet user payload in bytes.")
@option("--profile", default="bulk_upload", show_default=True, help="TYPHOON traffic profile for the docker flood (realistic obfuscation).")
@option("--criterion/--no-criterion", default=True, show_default=True, help="Also run the host criterion raw-send micro-benchmark.")
@option("--flamegraph/--no-flamegraph", default=True, show_default=True, help="Also record a perf flamegraph of the load bench (needs perf + cargo-flamegraph).")
@option("--bench-seconds", default=2.0, show_default=True, type=float, help="Criterion measurement time per throughput cell.")
@option("--build/--no-build", default=True, show_default=True, help="Build the load docker images before the sweep.")
@option("--out-dir", default=str(DEFAULT_OUT), show_default=True, type=ClickPath(), help="Output directory.")
def main(durations: str, flows: str, readers: str, payload: int, profile: str, criterion: bool, flamegraph: bool, bench_seconds: float, build: bool, out_dir: str) -> None:
    """TYPHOON load test. The dockerized realistic-profile flood (throughput, packet loss, per-container
    memory) is the core; each cell floods for the given duration(s). The host criterion raw-send bench
    and the load-bench flamegraph are optional (`--no-criterion` / `--no-flamegraph`, and auto-skip
    when their host deps are missing)."""
    if system() != "Linux":
        raise ClickException("load-test requires Linux (docker; perf/cargo-flamegraph for the flamegraph) — skipping.")
    if not _docker_available():
        raise ClickException("load-test requires a running Docker daemon for the flood sweep — skipping.")
    if profile not in PROFILES:
        raise ClickException(f"unknown profile '{profile}'; valid: {', '.join(PROFILES)}")
    profile_env = profile_to_env(PROFILES[profile], Random(0))

    duration_list = _float_list(durations)
    flow_list = _int_list(flows)
    reader_list = _int_list(readers)
    out_root = Path(out_dir)
    out_root.mkdir(parents=True, exist_ok=True)
    BENCH_KEY.parent.mkdir(parents=True, exist_ok=True)

    # ── host vehicles (optional): both driven by benches/load.rs ──
    if (criterion or flamegraph) and which("cargo") is None:
        console.print("  [yellow]⚠ cargo not found — skipping host criterion + flamegraph[/yellow]")
        criterion = flamegraph = False
    if criterion or flamegraph:
        console.print("[cyan]Generating benchmark server key[/cyan]")
        if not _run("gen-key", ["cargo", "run", "--quiet", "--bin", "typhoon-gen-key", "--no-default-features", "--features", "fast_software,server,tokio,clap", "--", str(BENCH_KEY)], env={"RUSTFLAGS": "-D warnings"}):
            raise ClickException("Key generation failed.")

    throughput: dict[int, float] = {}
    if criterion:
        console.print("[cyan]Measuring raw send throughput (host criterion)[/cyan]")
        throughput = _run_throughput(flow_list, reader_list, bench_seconds)

    # ── docker flood sweep (the core) ──
    if build:
        console.print("[cyan]Building load docker images[/cyan]")
        if not _build_images():
            raise ClickException("Docker image build failed.")

    console.print(f"[cyan]Dockerized flood sweep (profile={profile})[/cyan]")
    results: dict = {}
    for (f, r, d) in product(flow_list, reader_list, duration_list):
        console.print(f"  f{f}·r{r} {d:g}s")
        cell = _run_docker_cell(f, r, d, payload, profile, profile_env)
        results[(f, r, d)] = cell if cell is not None else dict.fromkeys(CELL_KEYS, 0.0)

    if flamegraph:
        console.print("[cyan]Recording flamegraph (load bench hot path)[/cyan]")
        _flamegraph(out_root)

    plot_path = _plot(results, flow_list, reader_list, duration_list, throughput, out_root)
    table_path = _write_table(results, flow_list, reader_list, duration_list, throughput, out_root)
    json_path = out_root / "load_test.json"
    json_path.write_text(dumps({
        "durations_s": duration_list, "flows": flow_list, "readers": reader_list, "payload": payload, "profile": profile,
        "send_throughput_mbps": {f"f{f}": v for f, v in throughput.items()},
        "cells": {f"f{f}_r{r}_{d:g}s": v for (f, r, d), v in results.items()},
    }, indent=2))

    console.print(f"\n[green]Load-test artifacts →[/green] {out_root}")
    for p in (plot_path, table_path, json_path):
        console.print(f"  [dim]{p}[/dim]")


if __name__ == "__main__":
    main()
