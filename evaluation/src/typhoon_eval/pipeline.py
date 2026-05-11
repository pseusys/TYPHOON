"""
TYPHOON total evaluation pipeline.

Orchestrates the full evaluation in six phases:
  1. capture   — bulk runs (N times) + scenario variants + optional chaos run
  2. analyze   — pcap statistics for every capture run
  3. visualize — protocol comparison and flow plots per capture run
  4. typhoon   — TYPHOON intrinsic comparisons (self, use-case, traffic)
  5. ml        — feature extraction, supervised + sequence + byte classifiers
  6. report    — generate evaluation/results/report.md

All diagrams go to DIAGRAMS_DIR (default: ../../diagrams/).
All analysis artefacts and model weights stay in RESULTS_DIR (default: results/).

Usage:
    poe evaluate
    poe evaluate --classification-runs 5 --no-chaos
    poe evaluate --skip capture,typhoon
    poe evaluate --diagrams-dir /tmp/diagrams
"""

import datetime
import json
import subprocess
import sys
from pathlib import Path

import click
from rich.console import Console
from rich.rule import Rule

from typhoon_eval.shared.analysis import CAPTURES_ROOT, _latest_run

console = Console()

RESULTS_DIR    = Path(__file__).parent.parent.parent / "results"
PROJECT_ROOT   = RESULTS_DIR.parent.parent
DIAGRAMS_DIR   = PROJECT_ROOT / "diagrams"
_PYTHON        = sys.executable

_ALL_PHASES = ("capture", "analyze", "visualize", "typhoon", "ml", "report")


# ── subprocess helper ─────────────────────────────────────────────────────────

def _run(label: str, cmd: list[str], log_path: Path | None = None) -> bool:
    """Run *cmd* inheriting the terminal's stdout/stderr so Rich output renders live.

    Capturing stdout via PIPE causes Rich in the subprocess to detect non-TTY
    and suppress its Progress spinner — making the pipeline appear frozen.
    Instead we let output flow directly to the terminal and only record the
    command invocation and exit code in the log file.
    """
    console.print(f"\n  [dim]$ {' '.join(cmd)}[/dim]")
    if log_path:
        with log_path.open("a") as lf:
            lf.write(f"\n$ {' '.join(cmd)}\n")
    result = subprocess.run(cmd, stdin=subprocess.DEVNULL)
    if log_path:
        with log_path.open("a") as lf:
            lf.write(f"exit_code={result.returncode}\n")
    return result.returncode == 0


def _mod(module: str, *args: str) -> list[str]:
    return [_PYTHON, "-m", module, *args]


# ── Phase 1: captures ─────────────────────────────────────────────────────────

def _phase_capture(
    classification_runs: int,
    profiles: list[str],
    chaos: bool,
    transfer_bytes: int,
    log_dir: Path,
) -> list[str]:
    """Return list of run IDs created (bulk classification runs only)."""
    console.print(Rule("[bold]Phase 1 — Captures[/bold]"))
    log_dir.mkdir(parents=True, exist_ok=True)
    log_path = log_dir / "capture.log"

    bulk_run_ids: list[str] = []

    # N bulk runs for ML training data.
    for i in range(classification_runs):
        console.print(f"\n  [cyan]Bulk classification run {i + 1}/{classification_runs}[/cyan]")
        ok = _run(
            "capture-bulk",
            _mod("typhoon_eval.shared.orchestrator", "--all", "--profile", "bulk_upload"),
            log_path,
        )
        if ok:
            rd = _latest_run()
            if rd:
                bulk_run_ids.append(rd.name.removeprefix("run_"))
                console.print(f"  [green]✓[/green] Created {rd.name}")
        else:
            console.print("  [yellow]⚠ Bulk capture failed — continuing[/yellow]")

    # One run per non-bulk scenario.
    for profile in profiles:
        if profile == "bulk_upload":
            continue
        console.print(f"\n  [cyan]Profile run: {profile}[/cyan]")
        _run(
            f"capture-{profile}",
            _mod("typhoon_eval.shared.orchestrator", "--all", "--profile", profile),
            log_path,
        )

    # Optional chaos run.
    if chaos:
        console.print("\n  [cyan]Chaos run (bulk + pumba)[/cyan]")
        _run(
            "capture-chaos",
            _mod("typhoon_eval.shared.orchestrator", "--all", "--chaos", "--profile", "bulk_upload"),
            log_path,
        )

    console.print(f"\n  Created {len(bulk_run_ids)} bulk classification run(s).")
    return bulk_run_ids


# ── Phase 2: analysis ─────────────────────────────────────────────────────────

def _phase_analyze(run_ids: list[str], log_dir: Path) -> None:
    console.print(Rule("[bold]Phase 2 — Analysis[/bold]"))
    log_path = log_dir / "analyze.log"

    # Analyze every available capture run (not just bulk classification ones).
    all_runs = sorted(p for p in CAPTURES_ROOT.glob("run_*") if p.is_dir()) if CAPTURES_ROOT.exists() else []
    if not all_runs:
        console.print("  [yellow]No capture runs found — skipping analysis.[/yellow]")
        return

    for rd in all_runs:
        run_id = rd.name.removeprefix("run_")
        console.print(f"\n  Analyzing [dim]{rd.name}[/dim]…")
        _run("analyze", _mod("typhoon_eval.shared.analysis", "--run", run_id), log_path)


# ── Phase 3: protocol visualization ──────────────────────────────────────────

def _phase_visualize(bulk_run_ids: list[str], diagrams_dir: Path, log_dir: Path) -> list[Path]:
    console.print(Rule("[bold]Phase 3 — Protocol visualization[/bold]"))
    log_path = log_dir / "visualize.log"
    generated: list[Path] = []

    proto_cmp_dir  = diagrams_dir / "proto_compare"
    flow_plot_dir  = diagrams_dir / "flow_plots"

    for run_id in bulk_run_ids:
        console.print(f"\n  [cyan]proto-compare[/cyan] {run_id}")
        _run("proto-compare", _mod("typhoon_eval.protocols_op.proto_compare_plots", "--run", run_id, "--out-dir", str(proto_cmp_dir)), log_path)
        for suffix in ("_proto_compare.png", "_handshake.png", "_fingerprint.png"):
            p = proto_cmp_dir / f"run_{run_id}{suffix}"
            if p.exists():
                generated.append(p)

        console.print(f"  [cyan]flow-plot[/cyan] {run_id}")
        _run("flow-plot", _mod("typhoon_eval.shared.pcap_flow_plot", "--run", run_id, "--out-dir", str(flow_plot_dir)), log_path)
        for p in flow_plot_dir.glob(f"run_{run_id}*.png"):
            generated.append(p)

    return generated


# ── Phase 4: TYPHOON intrinsic comparisons ────────────────────────────────────

def _phase_typhoon(
    typhoon_runs: int,
    typhoon_uc_runs: int,
    diagrams_dir: Path,
    log_dir: Path,
) -> list[Path]:
    console.print(Rule("[bold]Phase 4 — TYPHOON intrinsic comparisons[/bold]"))
    log_path = log_dir / "typhoon.log"
    generated: list[Path] = []

    self_cmp_dir   = diagrams_dir / "self_compare"
    uc_cmp_dir     = diagrams_dir / "use_case_compare"
    traffic_cmp_dir = diagrams_dir / "traffic_compare"

    console.print(f"\n  [cyan]self-compare[/cyan] ({typhoon_runs} runs)")
    ok = _run("self-compare", _mod("typhoon_eval.self.self_compare", "--runs", str(typhoon_runs), "--out-dir", str(self_cmp_dir)), log_path)
    if ok:
        generated.extend(self_cmp_dir.glob("*.png"))

    console.print(f"\n  [cyan]use-case-compare[/cyan] ({typhoon_uc_runs} runs/case)")
    ok = _run("uc-compare", _mod("typhoon_eval.self.use_case_compare", "--runs-per-case", str(typhoon_uc_runs), "--out-dir", str(uc_cmp_dir)), log_path)
    if ok:
        generated.extend(uc_cmp_dir.glob("*.png"))

    console.print("\n  [cyan]traffic-compare[/cyan]")
    ok = _run("traffic-compare", _mod("typhoon_eval.self.traffic_compare", "--out-dir", str(traffic_cmp_dir)), log_path)
    if ok:
        generated.extend(traffic_cmp_dir.glob("*.png"))

    return generated


# ── Phase 5: ML ───────────────────────────────────────────────────────────────

def _phase_ml(
    bulk_run_ids: list[str],
    diagrams_dir: Path,
    results_dir: Path,
    log_dir: Path,
) -> tuple[Path | None, list[Path]]:
    """Returns (features_npz_path, list_of_plot_paths)."""
    console.print(Rule("[bold]Phase 5 — ML[/bold]"))
    log_path  = log_dir / "ml.log"
    ml_plots  = diagrams_dir / "ml"
    ml_models = results_dir / "ml" / "models"

    if not bulk_run_ids:
        console.print("  [yellow]No bulk classification runs available — skipping ML.[/yellow]")
        return None, []

    # Feature extraction: aggregate all available runs.
    features_path = results_dir / "ml" / "features.npz"
    features_path.parent.mkdir(parents=True, exist_ok=True)
    console.print("\n  [cyan]ml-features[/cyan] (all runs → aggregated feature matrix)")
    _run("ml-features", _mod("typhoon_eval.ml.ml_features", "--all-runs", "--out", str(features_path)), log_path)

    if not features_path.exists():
        console.print("  [yellow]features.npz not found — skipping ML training.[/yellow]")
        return None, []

    # For ml-classify / ml-cluster / ml-sequence / ml-bytes, they need --run to find
    # the features.npz.  We saved it to results/ml/features.npz, but those modules
    # look for {run_dir}/features.npz.  Copy it into the latest bulk run so the --run
    # flag resolves correctly.
    latest_bulk_run_dir = CAPTURES_ROOT / f"run_{bulk_run_ids[-1]}"
    dest = latest_bulk_run_dir / "features.npz"
    if not dest.exists() or dest.stat().st_mtime < features_path.stat().st_mtime:
        import shutil
        shutil.copy2(features_path, dest)

    run_id = bulk_run_ids[-1]
    generated: list[Path] = []

    for label, module, extra_args in [
        ("ml-classify",  "typhoon_eval.ml.ml_classify", []),
        ("ml-cluster",   "typhoon_eval.ml.ml_cluster",  []),
        ("ml-sequence",  "typhoon_eval.ml.ml_sequence", []),
        ("ml-bytes",     "typhoon_eval.ml.ml_bytes",    []),
    ]:
        console.print(f"\n  [cyan]{label}[/cyan]")
        _run(
            label,
            _mod(module, "--run", run_id, "--out-dir", str(ml_plots), "--model-dir", str(ml_models), *extra_args),
            log_path,
        )

    generated.extend(ml_plots.glob("*.png"))
    return features_path, generated


# ── Phase 6: report ───────────────────────────────────────────────────────────

def _generate_report(
    pipeline_id: str,
    bulk_run_ids: list[str],
    diagrams_dir: Path,
    results_dir: Path,
) -> Path:
    console.print(Rule("[bold]Phase 6 — Report[/bold]"))

    lines: list[str] = [
        "# TYPHOON Evaluation Report",
        "",
        f"Generated: {datetime.datetime.now(datetime.UTC).isoformat()}",
        f"Pipeline:  `{pipeline_id}`",
        "",
    ]

    # ── Capture runs ──────────────────────────────────────────────────────────
    lines += ["## Capture Runs", ""]
    all_runs = sorted(CAPTURES_ROOT.glob("run_*")) if CAPTURES_ROOT.exists() else []
    if all_runs:
        lines.append("| Run | Scenario | Chaos | Protocols | Transfer |")
        lines.append("|-----|----------|-------|-----------|----------|")
        for rd in all_runs:
            cfg_path = rd / "config.json"
            if cfg_path.exists():
                cfg: dict = json.loads(cfg_path.read_text())
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

    # ── Analysis artefacts ────────────────────────────────────────────────────
    lines += ["## Analysis Artefacts", ""]
    for rd in all_runs:
        sp = rd / "stats.json"
        if sp.exists():
            lines.append(f"- `{sp.relative_to(PROJECT_ROOT)}` — per-direction pcap statistics (JSON)")
    lines += ["", "Each `stats.json` contains `c2s`, `s2c`, and `all` direction metrics:",
              "packet counts, byte counts, size/IAT percentiles and entropy, handshake",
              "metrics, burst statistics, direction asymmetry, and first-N-packet fingerprints.", ""]

    # ── Diagrams ──────────────────────────────────────────────────────────────
    lines += ["## Diagrams", ""]
    diagram_sections: dict[str, list[str]] = {}
    for png in sorted(diagrams_dir.rglob("*.png")):
        section = png.parent.name
        diagram_sections.setdefault(section, []).append(f"- `{png.relative_to(PROJECT_ROOT)}`")

    _descriptions = {
        "proto_compare":      "6-panel protocol comparison (violin, CDF, overhead, entropy, heatmap)",
        "handshake":          "3-panel handshake duration / packet count / byte fraction",
        "fingerprint":        "8-panel fingerprint analysis (burstiness, JS-divergence, IAT fingerprint, asymmetry…)",
        "flow_plots":         "Per-packet timeline grid showing packet sizes and directions over time",
        "self_compare":       "TYPHOON variability across repeated runs (same config, N executions)",
        "use_case_compare":   "TYPHOON per-use-case traffic profiles (throughput / interactive / transparent / security)",
        "traffic_compare":    "TYPHOON traffic modes (constant/random payload × constant/random wait)",
        "ml":                 "ML classification and clustering outputs (confusion matrices, accuracy, importances, PCA/UMAP)",
    }

    for section, file_lines in sorted(diagram_sections.items()):
        desc = _descriptions.get(section, "")
        lines.append(f"### {section.replace('_', ' ').title()}")
        if desc:
            lines.append(f"{desc}")
        lines.append("")
        lines.extend(file_lines)
        lines.append("")

    # ── ML model weights ──────────────────────────────────────────────────────
    ml_model_dir = results_dir / "ml" / "models"
    lines += ["## ML Model Weights", ""]
    model_files = sorted(ml_model_dir.glob("*")) if ml_model_dir.exists() else []
    if model_files:
        lines.append("| File | Format | Description |")
        lines.append("|------|--------|-------------|")
        _model_desc = {
            "_rf.joblib":       ("joblib", "Random Forest classifier (sklearn)"),
            "_gb.joblib":       ("joblib", "Gradient Boosting classifier (sklearn)"),
            "_svm.joblib":      ("joblib", "SVM (RBF) + StandardScaler tuple (sklearn)"),
            "_xgb.joblib":      ("joblib", "XGBoost classifier"),
            "_cluster.joblib":  ("joblib", "StandardScaler + PCA(2) fitted transformers"),
            "_mlp.joblib":      ("joblib", "MLP + StandardScaler for sequence classification"),
            "_deepfp.pt":       ("torch",  "1D-CNN (Deep Fingerprinting) state dict — sequence"),
            "_bytes_rf.joblib": ("joblib", "Random Forest on IP+UDP header bytes"),
            "_bytes_cnn.pt":    ("torch",  "1D-CNN (ByteCNN) state dict — header bytes"),
        }
        for f in model_files:
            for suffix, (fmt, desc) in _model_desc.items():
                if f.name.endswith(suffix):
                    lines.append(f"| `{f.relative_to(PROJECT_ROOT)}` | {fmt} | {desc} |")
                    break
            else:
                lines.append(f"| `{f.relative_to(PROJECT_ROOT)}` | — | — |")
        lines.append("")
    else:
        lines += ["*(no model weights found — ML phase may have been skipped)*", ""]

    # ── Feature matrix ────────────────────────────────────────────────────────
    features_path = results_dir / "ml" / "features.npz"
    if features_path.exists():
        lines += [
            "## Feature Matrix",
            "",
            f"`{features_path.relative_to(PROJECT_ROOT)}` — NumPy archive (npz) containing:",
            "",
            "| Array | Shape | Description |",
            "|-------|-------|-------------|",
            "| `X_stat` | (N, 35) | Scalar statistical features per capture |",
            "| `X_seq`  | (N, 100) | Direction-signed first-100-packet sizes |",
            "| `X_iat`  | (N, 100) | Direction-signed first-100-packet IATs (ms) |",
            "| `y`      | (N,) | Integer class labels |",
            "| `labels` | (P,) | Protocol names ordered by class index |",
            "",
        ]

    # ── How to reproduce ──────────────────────────────────────────────────────
    lines += [
        "## Reproducing Results",
        "",
        "```bash",
        "cd evaluation",
        "# Full pipeline (takes 30–60 min depending on Docker speed and ML hardware)",
        "poe evaluate",
        "",
        "# Skip capture (reuse existing runs) and TYPHOON intrinsics",
        "poe evaluate --skip capture,typhoon",
        "",
        "# Individual steps",
        "poe capture --all --profile bulk_upload",
        "poe analyze",
        "poe proto-compare",
        "poe ml-features --all-runs",
        "poe ml-classify --model-dir results/ml/models",
        "poe ml-cluster  --model-dir results/ml/models",
        "poe ml-sequence --model-dir results/ml/models",
        "poe ml-bytes    --model-dir results/ml/models",
        "```",
        "",
    ]

    report_path = results_dir / "report.md"
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text("\n".join(lines))
    console.print(f"\n  Report → [dim]{report_path}[/dim]")
    return report_path


# ── CLI ───────────────────────────────────────────────────────────────────────

@click.command(context_settings={"help_option_names": ["-h", "--help"]})
@click.option("--classification-runs", default=3, show_default=True, type=int,
              help="Number of bulk all-protocol capture runs for ML training data.")
@click.option("--profiles", default="bulk_upload,tiny_session,medium_cbr,bulk_bursty", show_default=True,
              help="Comma-separated profiles to capture (one run each, beyond the bulk classification runs).")
@click.option("--chaos/--no-chaos", default=True, show_default=True,
              help="Run one chaos (pumba) capture.")
@click.option("--bytes", "transfer_bytes", default=10_485_760, show_default=True, type=int,
              help="Payload bytes per client for capture runs.")
@click.option("--typhoon-runs", default=6, show_default=True, type=int,
              help="Repeated runs for self-compare.")
@click.option("--typhoon-uc-runs", default=3, show_default=True, type=int,
              help="Runs per use case for use-case-compare.")
@click.option("--diagrams-dir", default=str(DIAGRAMS_DIR), show_default=True, type=click.Path(),
              help="Root directory for all generated diagram PNGs.")
@click.option("--skip", default="", show_default=True,
              help=f"Comma-separated phases to skip: {', '.join(_ALL_PHASES)}.")
def main(
    classification_runs: int,
    profiles: str,
    chaos: bool,
    transfer_bytes: int,
    typhoon_runs: int,
    typhoon_uc_runs: int,
    diagrams_dir: str,
    skip: str,
) -> None:
    """TYPHOON total evaluation pipeline: capture → analyze → visualize → ML → report."""

    skipped = {s.strip() for s in skip.split(",") if s.strip()}
    invalid = skipped - set(_ALL_PHASES)
    if invalid:
        console.print(f"[red]Unknown phases to skip:[/red] {', '.join(sorted(invalid))}")
        console.print(f"Valid phases: {', '.join(_ALL_PHASES)}")
        sys.exit(1)

    profile_list = [s.strip() for s in profiles.split(",") if s.strip()]
    d_dir = Path(diagrams_dir)
    d_dir.mkdir(parents=True, exist_ok=True)

    pipeline_id = "pipeline_" + datetime.datetime.now(datetime.UTC).strftime("%Y%m%d_%H%M%S")
    log_dir = RESULTS_DIR / "pipeline" / pipeline_id
    log_dir.mkdir(parents=True, exist_ok=True)

    console.print(f"\n[bold]TYPHOON evaluation pipeline[/bold]  id=[dim]{pipeline_id}[/dim]")
    console.print(f"  Phases   : {', '.join(p for p in _ALL_PHASES if p not in skipped)}")
    if skipped:
        console.print(f"  Skipped  : {', '.join(sorted(skipped))}")
    console.print(f"  Diagrams : [dim]{d_dir}[/dim]")
    console.print(f"  Results  : [dim]{RESULTS_DIR}[/dim]\n")

    bulk_run_ids: list[str] = []

    if "capture" not in skipped:
        bulk_run_ids = _phase_capture(classification_runs, profile_list, chaos, transfer_bytes, log_dir)
    else:
        # Use the N most-recent bulk (non-chaos) runs.
        all_runs = sorted(CAPTURES_ROOT.glob("run_*")) if CAPTURES_ROOT.exists() else []
        for rd in reversed(all_runs):
            cfg_path = rd / "config.json"
            if not cfg_path.exists():
                continue
            cfg: dict = json.loads(cfg_path.read_text())
            if not cfg.get("chaos") and cfg.get("profile", cfg.get("scenario")) == "bulk_upload":
                bulk_run_ids.append(rd.name.removeprefix("run_"))
            if len(bulk_run_ids) >= classification_runs:
                break
        bulk_run_ids.reverse()
        console.print(f"  [dim](capture skipped — using {len(bulk_run_ids)} existing bulk run(s))[/dim]")

    if "analyze" not in skipped:
        _phase_analyze(bulk_run_ids, log_dir)

    if "visualize" not in skipped:
        _phase_visualize(bulk_run_ids, d_dir, log_dir)

    if "typhoon" not in skipped:
        _phase_typhoon(typhoon_runs, typhoon_uc_runs, d_dir, log_dir)

    if "ml" not in skipped:
        _phase_ml(bulk_run_ids, d_dir, RESULTS_DIR, log_dir)

    if "report" not in skipped:
        _generate_report(pipeline_id, bulk_run_ids, d_dir, RESULTS_DIR)

    console.print(f"\n[bold green]Pipeline complete.[/bold green]  Logs → [dim]{log_dir}[/dim]\n")


if __name__ == "__main__":
    main()
