"""TYPHOON total evaluation pipeline (eight phases).

  1. build       — protocol + background-generator Docker images
  2. capture     — bulk runs + scenario variants + optional chaos run
  3. analyze     — pcap statistics per capture run
  4. visualize   — protocol comparison and flow plots
  5. typhoon     — TYPHOON intrinsic comparisons (self, use-case, traffic)
  6. background  — Part 3 corpus + blending + detectability + dist plots
  7. benchmark   — cargo bench + example flamegraphs (Linux only, auto-skipped elsewhere)
  8. report      — aggregate everything into artifacts/<pipeline_id>/report.md

All derived artifacts go under ARTIFACTS_ROOT/<pipeline_id>/ (default
../../artifacts/). PCAPs stay in results/captures/ and results/background/
because they are too large to ship as artifacts.

To re-analyze already-stored PCAPs (e.g. after changing feature sets or
classifier options) without regenerating the corpus, skip generation and
point the background phase at an existing corpus:

    poe evaluate --skip build,capture \\
        --corpus-root results/background/pipeline_<id>
"""

from datetime import UTC, datetime
from json import dumps, loads
from pathlib import Path
from platform import system
from shutil import copy2
from subprocess import DEVNULL, STDOUT, run
from sys import exit

from click import ClickException, Command, command, option
from click import Path as ClickPath
from rich.rule import Rule

from typhoon_eval.background.corpus import main as _bg_corpus_main
from typhoon_eval.background.detectability.cli import main as _bg_detectability_main
from typhoon_eval.background.dist_plot import main as _bg_distplot_main
from typhoon_eval.background.ml_blending import main as _bg_blending_main
from typhoon_eval.benchmark import main as _benchmark_main
from typhoon_eval.protocols_op.proto_compare_plots import main as _proto_compare_main
from typhoon_eval.self.self_compare import main as _self_compare_main
from typhoon_eval.self.traffic_compare import main as _traffic_compare_main
from typhoon_eval.self.use_case_compare import main as _use_case_compare_main
from typhoon_eval.shared.analysis import CAPTURES_ROOT, _latest_run
from typhoon_eval.shared.analysis import main as _analysis_main
from typhoon_eval.shared.console import console
from typhoon_eval.shared.orchestrator import main as _orchestrator_main
from typhoon_eval.shared.pcap_flow_plot import main as _pcap_flow_plot_main

PROJECT_ROOT   = Path(__file__).parent.parent.parent.parent
RESULTS_DIR    = PROJECT_ROOT / "evaluation" / "results"
ARTIFACTS_ROOT = PROJECT_ROOT / "artifacts"
BACKGROUND_ROOT = RESULTS_DIR / "background"

_ALL_PHASES = ("build", "capture", "analyze", "visualize", "typhoon", "background", "benchmark", "report")

# Lines of captured output to show on a --quiet-build failure — enough to see
# the actual Docker error without dumping the full (often 1000s-of-lines) log.
_QUIET_FAILURE_TAIL_LINES = 200

EVAL_ROOT = Path(__file__).parent.parent.parent
PROTOCOL_COMPOSE   = EVAL_ROOT / "compose" / "docker-compose.build.yml"
BACKGROUND_COMPOSE = EVAL_ROOT / "background" / "compose" / "docker-compose.build.yml"


# ── direct-import + subprocess helpers ────────────────────────────────────────

def _invoke(label: str, command: Command, args: list[str], log_path: Path | None = None) -> bool:
    """Invoke a click *command* in-process; record cmd + exit_code to *log_path*."""
    console.print(f"\n  [dim]$ python -m {command.name} {' '.join(args)}[/dim]")
    if log_path:
        with log_path.open("a") as lf:
            lf.write(f"\n$ python -m {command.name} {' '.join(args)}\n")
    try:
        command.main(args=args, standalone_mode=False)
        exit_code = 0
    except SystemExit as exc:
        exit_code = int(exc.code) if isinstance(exc.code, int) else 1
    except ClickException as exc:
        exc.show()
        exit_code = exc.exit_code
    except Exception as exc:  # noqa: BLE001 — pipeline must isolate phase failures
        console.print(f"  [red]✗ {label} raised {type(exc).__name__}: {exc}[/red]")
        exit_code = 1
    if log_path:
        with log_path.open("a") as lf:
            lf.write(f"exit_code={exit_code}\n")
    return exit_code == 0


def _shell(label: str, cmd: list[str], log_path: Path | None = None, quiet: bool = False) -> bool:
    """Run *cmd* as a subprocess; for modules without a direct import target.

    *quiet* redirects stdout/stderr into *log_path* instead of streaming them
    to the console — ``docker compose build`` alone can emit thousands of
    lines of layer output, which drowns everything else in CI logs. The
    command is still fully captured in the log file, and on failure the last
    ``_QUIET_FAILURE_TAIL_LINES`` lines are printed so the actual error stays
    visible. Silently does nothing (falls back to streaming) when *quiet* is
    requested without a *log_path* to capture into.
    """
    console.print(f"\n  [dim]$ {' '.join(cmd)}[/dim]")
    if log_path:
        with log_path.open("a") as lf:
            lf.write(f"\n$ {' '.join(cmd)}\n")
    if quiet and log_path:
        with log_path.open("a") as lf:
            result = run(cmd, stdin=DEVNULL, stdout=lf, stderr=STDOUT)
    else:
        result = run(cmd, stdin=DEVNULL)
    if log_path:
        with log_path.open("a") as lf:
            lf.write(f"exit_code={result.returncode}\n")
    if quiet and log_path:
        if result.returncode == 0:
            console.print(f"  [green]✓[/green] {label} (output suppressed — see {log_path})")
        else:
            console.print(f"  [red]✗ {label} failed (exit {result.returncode}) — last {_QUIET_FAILURE_TAIL_LINES} lines:[/red]")
            tail = log_path.read_text().splitlines()[-_QUIET_FAILURE_TAIL_LINES:]
            console.print("[dim]" + "\n".join(tail) + "[/dim]")
    return result.returncode == 0


# ── Phase 1: build ────────────────────────────────────────────────────────────

def _phase_build(log_dir: Path, quiet: bool = False) -> None:
    """Build protocol + background-generator Docker images via docker compose.

    *quiet* suppresses the (often 1000s-of-lines) build output from the
    console — still fully captured in ``build.log`` — printing only a
    per-target pass/fail line. See ``_shell``.
    """
    console.print(Rule("[bold]Phase 1 — Build[/bold]"))
    log_path = log_dir / "build.log"

    for label, compose_file in (("protocol-images", PROTOCOL_COMPOSE), ("background-images", BACKGROUND_COMPOSE)):
        if not compose_file.exists():
            console.print(f"  [yellow]Skipping {label}: compose file not found at {compose_file}[/yellow]")
            continue
        console.print(f"\n  [cyan]{label}[/cyan] ← {compose_file.relative_to(EVAL_ROOT)}")
        _shell(label, ["docker", "compose", "-f", str(compose_file), "build"], log_path, quiet=quiet)


# ── Phase 2: captures ─────────────────────────────────────────────────────────

def _phase_capture(
    classification_runs: int,
    profiles: list[str],
    chaos: bool,
    log_dir: Path,
) -> list[str]:
    """Return list of run IDs created (bulk classification runs only).

    Transfer size is not a parameter here: the orchestrator derives it from the
    selected profile's ``PROFILE_BYTES_C2S`` env, so there is nothing to pass.
    """
    console.print(Rule("[bold]Phase 2 — Captures[/bold]"))
    log_path = log_dir / "capture.log"

    bulk_run_ids: list[str] = []

    for i in range(classification_runs):
        console.print(f"\n  [cyan]Bulk classification run {i + 1}/{classification_runs}[/cyan]")
        ok = _invoke("capture-bulk", _orchestrator_main, ["--all", "--profile", "bulk_upload"], log_path)
        if ok:
            rd = _latest_run()
            if rd:
                bulk_run_ids.append(rd.name.removeprefix("run_"))
                console.print(f"  [green]✓[/green] Created {rd.name}")
        else:
            console.print("  [yellow]⚠ Bulk capture failed — continuing[/yellow]")

    for profile in profiles:
        if profile == "bulk_upload":
            continue
        console.print(f"\n  [cyan]Profile run: {profile}[/cyan]")
        _invoke(f"capture-{profile}", _orchestrator_main, ["--all", "--profile", profile], log_path)

    if chaos:
        console.print("\n  [cyan]Chaos run (bulk + pumba)[/cyan]")
        _invoke("capture-chaos", _orchestrator_main, ["--all", "--chaos", "--profile", "bulk_upload"], log_path)

    console.print(f"\n  Created {len(bulk_run_ids)} bulk classification run(s).")
    return bulk_run_ids


# ── Phase 3: analysis ─────────────────────────────────────────────────────────

def _phase_analyze(artifacts_dir: Path, log_dir: Path) -> None:
    console.print(Rule("[bold]Phase 3 — Analysis[/bold]"))
    log_path = log_dir / "analyze.log"

    all_runs = sorted(p for p in CAPTURES_ROOT.glob("run_*") if p.is_dir()) if CAPTURES_ROOT.exists() else []
    if not all_runs:
        console.print("  [yellow]No capture runs found — skipping analysis.[/yellow]")
        return

    analyze_dir = artifacts_dir / "analyze"
    for rd in all_runs:
        run_id = rd.name.removeprefix("run_")
        # Skip aborted captures (config.json but no pcaps) — analysis has
        # nothing to parse and would only emit an empty run.
        if not any(rd.glob("*.pcap")):
            console.print(f"\n  [yellow]Skipping [dim]{rd.name}[/dim] — no pcaps (aborted capture).[/yellow]")
            continue
        console.print(f"\n  Analyzing [dim]{rd.name}[/dim]…")
        if _invoke("analyze", _analysis_main, ["--run", run_id], log_path):
            sp = rd / "stats.json"
            if sp.exists():
                dst = analyze_dir / rd.name / "stats.json"
                dst.parent.mkdir(parents=True, exist_ok=True)
                copy2(sp, dst)


# ── Phase 4: protocol visualization ──────────────────────────────────────────

def _phase_visualize(bulk_run_ids: list[str], artifacts_dir: Path, log_dir: Path) -> list[Path]:
    console.print(Rule("[bold]Phase 4 — Protocol visualization[/bold]"))
    log_path = log_dir / "visualize.log"
    generated: list[Path] = []

    proto_cmp_dir  = artifacts_dir / "proto_compare"
    flow_plot_dir  = artifacts_dir / "flow_plots"

    for run_id in bulk_run_ids:
        console.print(f"\n  [cyan]proto-compare[/cyan] {run_id}")
        _invoke("proto-compare", _proto_compare_main, ["--run", run_id, "--out-dir", str(proto_cmp_dir)], log_path)
        for suffix in ("_proto_compare.pdf", "_handshake.pdf", "_fingerprint.pdf", "_compare_table.md"):
            p = proto_cmp_dir / f"run_{run_id}{suffix}"
            if p.exists():
                generated.append(p)

        console.print(f"  [cyan]flow-plot[/cyan] {run_id}")
        _invoke("flow-plot", _pcap_flow_plot_main, ["--run", run_id, "--out-dir", str(flow_plot_dir)], log_path)
        generated.extend(flow_plot_dir.glob(f"run_{run_id}*.pdf"))

    return generated


# ── Phase 5: TYPHOON intrinsic comparisons ────────────────────────────────────

def _phase_typhoon(
    typhoon_runs: int,
    typhoon_uc_runs: int,
    typhoon_traffic_runs: int,
    artifacts_dir: Path,
    log_dir: Path,
) -> list[Path]:
    console.print(Rule("[bold]Phase 5 — TYPHOON intrinsic comparisons[/bold]"))
    log_path = log_dir / "typhoon.log"
    generated: list[Path] = []

    self_cmp_dir    = artifacts_dir / "self_compare"
    uc_cmp_dir      = artifacts_dir / "use_case_compare"
    traffic_cmp_dir = artifacts_dir / "traffic_compare"

    console.print(f"\n  [cyan]self-compare[/cyan] ({typhoon_runs} runs)")
    if _invoke("self-compare", _self_compare_main, ["--runs", str(typhoon_runs), "--out-dir", str(self_cmp_dir)], log_path):
        generated.extend(self_cmp_dir.glob("*.pdf"))

    console.print(f"\n  [cyan]use-case-compare[/cyan] ({typhoon_uc_runs} runs/case)")
    if _invoke("uc-compare", _use_case_compare_main, ["--runs-per-case", str(typhoon_uc_runs), "--out-dir", str(uc_cmp_dir)], log_path):
        generated.extend(uc_cmp_dir.glob("*.pdf"))

    console.print(f"\n  [cyan]traffic-compare[/cyan] ({typhoon_traffic_runs} runs/mode)")
    if _invoke("traffic-compare", _traffic_compare_main, ["--runs", str(typhoon_traffic_runs), "--out-dir", str(traffic_cmp_dir)], log_path):
        generated.extend(traffic_cmp_dir.glob("*.pdf"))

    return generated


# ── Phase 6: background blending (Part 3) ─────────────────────────────────────

def _phase_background(
    background_runs: int,
    pipeline_id: str,
    artifacts_dir: Path,
    log_dir: Path,
    corpus_root_override: Path | None = None,
) -> list[Path]:
    """Run the randomised background corpus + the three analyses on it.

    Corpus PCAPs land in ``results/background/pipeline_<id>/`` (kept out of
    artifacts — too large). Derived plots / JSON / per-run metadata.json
    summaries are copied / written under ``artifacts/<id>/background/``.

    When *corpus_root_override* is given, corpus generation is skipped and the
    blending / open-world / distribution analyses run against those already-
    stored PCAPs instead — useful for re-running the analyses (e.g. after
    changing feature sets or classifier options) without regenerating the
    (large) corpus.
    """
    console.print(Rule("[bold]Phase 6 — Background blending[/bold]"))
    log_path = log_dir / "background.log"
    generated: list[Path] = []

    bg_dir = artifacts_dir / "background"
    bg_dir.mkdir(parents=True, exist_ok=True)

    if corpus_root_override is not None:
        corpus_pcap_root = corpus_root_override
        if not corpus_pcap_root.is_dir():
            console.print(f"  [red]--corpus-root not found:[/red] {corpus_pcap_root} — skipping background analyses.")
            return generated
        n_runs = sum(1 for _ in corpus_pcap_root.glob("run_*"))
        console.print(f"\n  [cyan]reusing stored corpus[/cyan] ({n_runs} runs ← {corpus_pcap_root})")
    else:
        corpus_pcap_root = BACKGROUND_ROOT / f"pipeline_{pipeline_id}"
        console.print(f"\n  [cyan]background-corpus[/cyan] ({background_runs} runs → {corpus_pcap_root})")
        ok = _invoke(
            "bg-corpus",
            _bg_corpus_main,
            ["--runs", str(background_runs), "--out-dir", str(corpus_pcap_root), "--no-build"],
            log_path,
        )
        if not ok or not corpus_pcap_root.is_dir():
            console.print("  [yellow]Corpus failed — skipping downstream blending analyses.[/yellow]")
            return generated

    # Aggregate per-run metadata.json into artifacts (no PCAPs).
    meta_dir = bg_dir / "corpus_metadata"
    meta_dir.mkdir(parents=True, exist_ok=True)
    for run_dir in sorted(corpus_pcap_root.glob("run_*")):
        for f in ("metadata.json", "config.json"):
            src = run_dir / f
            if src.exists():
                dst = meta_dir / run_dir.name / f
                dst.parent.mkdir(parents=True, exist_ok=True)
                copy2(src, dst)

    blending_dir = bg_dir / "blending"
    detectability_dir = bg_dir / "detectability"
    distplot_dir = bg_dir / "distplot"

    console.print(f"\n  [cyan]background-blending[/cyan] → {blending_dir}")
    if _invoke(
        "bg-blending",
        _bg_blending_main,
        ["--corpus-root", str(corpus_pcap_root), "--out-dir", str(blending_dir)],
        log_path,
    ):
        generated.extend(blending_dir.glob("*.json"))

    console.print(f"\n  [cyan]background-detectability[/cyan] → {detectability_dir}")
    if _invoke(
        "bg-detectability",
        _bg_detectability_main,
        ["--corpus-root", str(corpus_pcap_root), "--out-dir", str(detectability_dir)],
        log_path,
    ):
        generated.extend(detectability_dir.glob("*.pdf"))
        generated.extend(detectability_dir.glob("*.json"))

    console.print(f"\n  [cyan]background-distplot[/cyan] → {distplot_dir}")
    if _invoke(
        "bg-distplot",
        _bg_distplot_main,
        ["--corpus-root", str(corpus_pcap_root), "--out-dir", str(distplot_dir)],
        log_path,
    ):
        generated.extend(distplot_dir.glob("*.pdf"))
        generated.extend(distplot_dir.glob("*.json"))

    # Stash a pointer to the corpus PCAP root so the report can cite it.
    (bg_dir / "corpus_pcap_root.txt").write_text(str(corpus_pcap_root) + "\n")
    return generated


# ── Phase 7: benchmark ────────────────────────────────────────────────────────

def _phase_benchmark(artifacts_dir: Path, log_dir: Path) -> list[Path]:
    """Run cargo bench + example flamegraphs. Linux only — auto-skipped elsewhere."""
    console.print(Rule("[bold]Phase 7 — Benchmark[/bold]"))
    generated: list[Path] = []

    if system() != "Linux":
        console.print("  [yellow]Skipping benchmark phase — requires Linux (perf + cargo-flamegraph).[/yellow]")
        return generated

    log_path = log_dir / "benchmark.log"
    bench_dir = artifacts_dir / "benchmark"

    if _invoke("benchmark", _benchmark_main, ["--out-dir", str(bench_dir)], log_path):
        generated.extend(bench_dir.glob("*.txt"))
        generated.extend((bench_dir / "flamegraphs").glob("*.pdf"))
        generated.extend((bench_dir / "flamegraphs").glob("*.svg"))
    return generated


# ── Phase 8: report ───────────────────────────────────────────────────────────

def _generate_report(
    pipeline_id: str,
    bulk_run_ids: list[str],
    artifacts_dir: Path,
) -> Path:
    console.print(Rule("[bold]Phase 7 — Report[/bold]"))

    lines: list[str] = [
        "# TYPHOON Evaluation Report",
        "",
        f"Generated: {datetime.now(UTC).isoformat()}",
        f"Pipeline:  `{pipeline_id}`",
        "",
        f"All artifacts in this directory (`{artifacts_dir.relative_to(PROJECT_ROOT)}/`).",
        "PCAPs are kept in `evaluation/results/captures/` and ",
        "`evaluation/results/background/` (too large to ship as artifacts).",
        "",
    ]

    all_runs = sorted(CAPTURES_ROOT.glob("run_*")) if CAPTURES_ROOT.exists() else []

    # ── Capture runs ──────────────────────────────────────────────────────────
    lines += ["## Capture Runs", ""]
    if all_runs:
        lines.append("| Run | Scenario | Chaos | Protocols | Transfer |")
        lines.append("|-----|----------|-------|-----------|----------|")
        for rd in all_runs:
            cfg_path = rd / "config.json"
            if cfg_path.exists():
                cfg: dict = loads(cfg_path.read_text())
                chaos_flag = "yes" if cfg.get("chaos") else "no"
                scenario   = cfg.get("profile", cfg.get("scenario", "?"))
                protos     = ", ".join(cfg.get("protocols", []))
                tb_mb      = cfg.get("transfer_bytes", 0) / 1_048_576
                lines.append(f"| `{rd.name}` | {scenario} | {chaos_flag} | {protos} | {tb_mb:.0f} MB |")
            else:
                lines.append(f"| `{rd.name}` | ? | ? | ? | ? |")
        lines.append("")
    else:
        lines += ["*(no capture runs found)*", ""]

    # ── Analysis artifacts ────────────────────────────────────────────────────
    lines += ["## Analysis Artifacts", ""]
    analyze_dir = artifacts_dir / "analyze"
    stats_files = sorted(analyze_dir.rglob("stats.json")) if analyze_dir.exists() else []
    for sp in stats_files:
        lines.append(f"- `{sp.relative_to(artifacts_dir)}` — per-direction pcap statistics (JSON)")
    if stats_files:
        lines += ["", "Each `stats.json` contains `c2s`, `s2c`, and `all` metrics:",
                  "packet/byte counts, size/IAT percentiles + entropy, handshake metrics,",
                  "burst statistics, direction asymmetry, first-N-packet fingerprints.", ""]
    else:
        lines += ["*(no stats.json files copied)*", ""]

    # ── Plots and tables ──────────────────────────────────────────────────────
    lines += ["## Plots and Tables", ""]
    _descriptions = {
        "proto_compare":     "6-panel protocol comparison (CDFs, overhead, entropy, heatmap) + markdown table",
        "flow_plots":        "Per-packet timeline grid (packet size + direction over time)",
        "self_compare":      "TYPHOON variability across repeated runs (same config, N executions)",
        "use_case_compare":  "TYPHOON per-use-case profiles (throughput / interactive / transparent / security)",
        "traffic_compare":   "TYPHOON traffic modes (constant/random payload × constant/random wait)",
        "background":        "Part 3 background-blending corpus: blending fraction, open-world detectability, distribution overlays",
        "benchmark":         "Rust-level cargo bench results + example flamegraphs (Linux only)",
    }
    for section in ("proto_compare", "flow_plots", "self_compare", "use_case_compare",
                    "traffic_compare", "background", "benchmark"):
        sd = artifacts_dir / section
        if not sd.exists():
            continue
        files = sorted({*sd.rglob("*.pdf"), *sd.rglob("*.md"), *sd.rglob("*.json"),
                         *sd.rglob("*.txt"), *sd.rglob("*.svg")})
        if not files:
            continue
        lines += [f"### {section.replace('_', ' ').title()}", _descriptions.get(section, ""), ""]
        for f in files:
            lines.append(f"- `{f.relative_to(artifacts_dir)}`")
        lines.append("")

    # ── Phase logs ────────────────────────────────────────────────────────────
    lines += ["## Phase Logs", ""]
    logs_dir = artifacts_dir / "logs"
    log_files = sorted(logs_dir.glob("*.log")) if logs_dir.exists() else []
    for lf in log_files:
        lines.append(f"- `{lf.relative_to(artifacts_dir)}`")
    if not log_files:
        lines.append("*(no phase logs found)*")
    lines.append("")

    # ── How to reproduce ──────────────────────────────────────────────────────
    lines += [
        "## Reproducing Results",
        "",
        "```bash",
        "cd evaluation",
        "# Full pipeline (long — background corpus dominates):",
        "poe evaluate",
        "",
        "# Reuse existing Docker images + capture runs, skip the 7500-run corpus:",
        "poe evaluate --skip build,capture,background",
        "",
        "# Skip Rust-level benchmarking (cargo bench + flamegraphs) — it auto-skips",
        "# on non-Linux hosts anyway:",
        "poe evaluate --skip benchmark",
        "",
        "# Re-analyze already-stored PCAPs (e.g. after changing feature sets or",
        "# classifier options) without regenerating the corpus:",
        "poe evaluate --skip build,capture \\",
        "    --corpus-root results/background/pipeline_<id>",
        "",
        "# Individual steps:",
        "poe build",
        "poe capture --all --profile bulk_upload",
        "poe analyze",
        "poe proto-compare",
        "poe background-build",
        "poe background-corpus",
        "poe background-blending",
        "poe background-detectability",
        "poe background-distplot",
        "poe benchmark",
        "```",
        "",
    ]

    report_path = artifacts_dir / "report.md"
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text("\n".join(lines))
    console.print(f"\n  Report → [dim]{report_path}[/dim]")
    return report_path


# ── CLI ───────────────────────────────────────────────────────────────────────

@command(context_settings={"help_option_names": ["-h", "--help"]})
@option("--classification-runs", default=3, show_default=True, type=int,
              help="Number of bulk all-protocol capture runs used by the visualize phase (proto-compare + flow plots).")
@option("--profiles", default="bulk_upload", show_default=True,
              help="Comma-separated profiles to capture (one run each beyond the bulk classification runs).")
@option("--chaos/--no-chaos", default=True, show_default=True,
              help="Run one chaos (pumba) capture.")
@option("--typhoon-runs", default=6, show_default=True, type=int,
              help="Repeated runs for self-compare.")
@option("--typhoon-uc-runs", default=3, show_default=True, type=int,
              help="Runs per use case for use-case-compare.")
@option("--typhoon-traffic-runs", default=3, show_default=True, type=int,
              help="Runs per payload×wait mode for traffic-compare (4 modes × this many runs).")
@option("--background-runs", default=7500, show_default=True, type=int,
              help="Number of randomised background-blending corpus runs (long). Ignored when --corpus-root is given.")
@option("--corpus-root", "corpus_root", default=None, type=ClickPath(),
              help="Re-analyze an already-stored background corpus at this path instead of "
                   "generating a new one. Skips corpus generation; blending/open-world/distplot "
                   "run on the stored PCAPs. Pair with '--skip build,capture' to reuse everything.")
@option("--artifacts-dir", default=str(ARTIFACTS_ROOT), show_default=True, type=ClickPath(),
              help="Root directory for per-pipeline-run artifact subdirectories.")
@option("--quiet-build/--no-quiet-build", default=False, show_default=True,
              help="Suppress the build phase's docker compose output (1000s of lines) from the "
                   "console — still fully captured in logs/build.log, with the last "
                   f"{_QUIET_FAILURE_TAIL_LINES} lines printed on failure.")
@option("--skip", default="", show_default=True,
              help=f"Comma-separated phases to skip: {', '.join(_ALL_PHASES)}.")
def main(
    classification_runs: int,
    profiles: str,
    chaos: bool,
    typhoon_runs: int,
    typhoon_uc_runs: int,
    typhoon_traffic_runs: int,
    background_runs: int,
    corpus_root: str | None,
    artifacts_dir: str,
    quiet_build: bool,
    skip: str,
) -> None:
    """TYPHOON total evaluation pipeline: build → capture → analyze → visualize → typhoon → background → report."""

    skipped = {s.strip() for s in skip.split(",") if s.strip()}
    invalid = skipped - set(_ALL_PHASES)
    if invalid:
        console.print(f"[red]Unknown phases to skip:[/red] {', '.join(sorted(invalid))}")
        console.print(f"Valid phases: {', '.join(_ALL_PHASES)}")
        exit(1)

    profile_list = [s.strip() for s in profiles.split(",") if s.strip()]
    corpus_root_path = Path(corpus_root) if corpus_root else None

    pipeline_id = "pipeline_" + datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
    artifacts_root = Path(artifacts_dir)
    artifacts_dir_run = artifacts_root / pipeline_id
    artifacts_dir_run.mkdir(parents=True, exist_ok=True)
    log_dir = artifacts_dir_run / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)

    console.print(f"\n[bold]TYPHOON evaluation pipeline[/bold]  id=[dim]{pipeline_id}[/dim]")
    console.print(f"  Phases    : {', '.join(p for p in _ALL_PHASES if p not in skipped)}")
    if skipped:
        console.print(f"  Skipped   : {', '.join(sorted(skipped))}")
    if corpus_root_path:
        console.print(f"  Corpus    : [dim]{corpus_root_path}[/dim] (reusing stored PCAPs — no corpus generation)")
    console.print(f"  Artifacts : [dim]{artifacts_dir_run}[/dim]")
    console.print(f"  PCAP root : [dim]{CAPTURES_ROOT}[/dim] (kept outside artifacts)\n")

    # Snapshot the resolved pipeline parameters for reproducibility.
    (artifacts_dir_run / "pipeline_config.json").write_text(dumps({
        "pipeline_id":          pipeline_id,
        "classification_runs":  classification_runs,
        "profiles":             profile_list,
        "chaos":                chaos,
        "typhoon_runs":         typhoon_runs,
        "typhoon_uc_runs":      typhoon_uc_runs,
        "typhoon_traffic_runs": typhoon_traffic_runs,
        "background_runs":      background_runs,
        "corpus_root":          str(corpus_root_path) if corpus_root_path else None,
        "quiet_build":          quiet_build,
        "skipped_phases":       sorted(skipped),
    }, indent=2))

    if "build" not in skipped:
        _phase_build(log_dir, quiet=quiet_build)

    bulk_run_ids: list[str] = []

    if "capture" not in skipped:
        bulk_run_ids = _phase_capture(classification_runs, profile_list, chaos, log_dir)
    else:
        all_runs = sorted(CAPTURES_ROOT.glob("run_*")) if CAPTURES_ROOT.exists() else []
        for rd in reversed(all_runs):
            cfg_path = rd / "config.json"
            if not cfg_path.exists():
                continue
            # Skip aborted captures (config.json but no pcaps) — otherwise they
            # get fed to proto-compare / flow-plot, which fail on empty runs.
            if not any(rd.glob("*.pcap")):
                continue
            cfg: dict = loads(cfg_path.read_text())
            if not cfg.get("chaos") and cfg.get("profile", cfg.get("scenario")) == "bulk_upload":
                bulk_run_ids.append(rd.name.removeprefix("run_"))
            if len(bulk_run_ids) >= classification_runs:
                break
        bulk_run_ids.reverse()
        console.print(f"  [dim](capture skipped — using {len(bulk_run_ids)} existing bulk run(s))[/dim]")

    if "analyze" not in skipped:
        _phase_analyze(artifacts_dir_run, log_dir)

    if "visualize" not in skipped:
        _phase_visualize(bulk_run_ids, artifacts_dir_run, log_dir)

    if "typhoon" not in skipped:
        _phase_typhoon(typhoon_runs, typhoon_uc_runs, typhoon_traffic_runs, artifacts_dir_run, log_dir)

    if "background" not in skipped:
        _phase_background(background_runs, pipeline_id, artifacts_dir_run, log_dir, corpus_root_path)

    if "benchmark" not in skipped:
        _phase_benchmark(artifacts_dir_run, log_dir)

    if "report" not in skipped:
        _generate_report(pipeline_id, bulk_run_ids, artifacts_dir_run)

    console.print(f"\n[bold green]Pipeline complete.[/bold green]  Artifacts → [dim]{artifacts_dir_run}[/dim]\n")


if __name__ == "__main__":
    main()
