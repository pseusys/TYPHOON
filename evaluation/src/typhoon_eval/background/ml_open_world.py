"""Methodologically-grounded detectability metrics for Part 3.

Two tests, both with stratified k-fold cross-validation so reported numbers
reflect held-out performance, never training-set memorisation:

  * Test A — Pair-binary detection.  For each TYPHOON profile that targets a
    natural class (e.g. ``as_quic_d`` mimics ``quic_download``), train a
    binary classifier on (TYPHOON-as-X) vs (real-X) flows only, with
    ``StratifiedKFold(5)``.  Report AUC-ROC and TPR @ 1% FPR aggregated from
    out-of-fold predictions.  AUC ≈ 0.5 means perfectly indistinguishable;
    AUC = 1.0 means trivially detected.  This is the threat model from
    Tschantz et al. S&P 2016: a censor who *suspects* the protocol and
    trains a pair-specific classifier.

  * Test B — Closed-world (n+1)-class.  Train a multi-class classifier on
    all natural classes plus TYPHOON, with ``StratifiedKFold(5)`` and
    ``cross_val_predict`` for clean out-of-fold predictions.  Report
    accuracy, macro-F1, per-class precision/recall/F1, and a confusion
    matrix.  TYPHOON's recall is the headline: lower means the censor more
    often mistakes TYPHOON for a natural class.

The Test C (open-world unknown-class detection) lives in ``ml_blending.py``
and remains the realistic-censor metric — a censor without TYPHOON labels
runs a multi-class classifier and thresholds confidence.
"""

from __future__ import annotations

import sys
from pathlib import Path

import click
import numpy as np
from rich.console import Console
from rich.table import Table

from typhoon_eval.background.ml_blending import FEATURE_NAMES, TYPHOON_CLASS, _load_corpus

console = Console()

PAIR_TOP_FEATURES = 5
LARGE_DELTA = 1.0
MEDIUM_DELTA = 0.5

# Each profile's intended natural-class target — the class the profile is
# designed to mimic.  Pairs not listed here are skipped in Test A.
PROFILE_TARGET_CLASS: dict[str, str] = {
    "as_quic_d":       "quic_download",
    "as_quic_u":       "quic_upload",
    "as_video":        "rtp_video",
    "as_video_bursty": "rtp_video",
    "as_voice":        "rtp_voice",
    "silent_idle":     "wireguard_idle",
}

KFOLD_SPLITS = 5
RF_N_ESTIMATORS = 200
RF_RANDOM_STATE = 42
PAIR_FPR_TARGET = 0.01            # 1% — small samples (~30-40) make 0.1% unreliable
MIN_SAMPLES_PER_CLASS = KFOLD_SPLITS  # need ≥ k flows per class to run StratifiedKFold(k)


def _tpr_at_fpr(scores_pos: np.ndarray, scores_neg: np.ndarray, target_fpr: float) -> tuple[float, float]:
    """TPR at FPR ≤ *target_fpr* given out-of-fold positive (TYPHOON) and negative (natural) scores."""
    if len(scores_neg) == 0 or len(scores_pos) == 0:
        return float("nan"), float("nan")
    sorted_neg = np.sort(scores_neg)[::-1]
    cutoff_idx = max(0, int(np.floor(target_fpr * len(sorted_neg))) - 1)
    threshold = float(sorted_neg[cutoff_idx])
    tpr = float((scores_pos > threshold).sum()) / len(scores_pos)
    return threshold, tpr


def _run_pair_binary(
    profile: str,
    target_class: str,
    X: np.ndarray,
    y: list[str],
    profiles: list[str],
) -> dict[str, object] | None:
    """Stratified-5-fold pair-binary AUC + TPR @ 1% FPR + feature importance for one pair.

    AUC and TPR come from out-of-fold predictions (no leakage).  Feature
    importance is averaged across the per-fold models — the same models that
    produced the AUC, so the importances correspond to *generalising* signal,
    not training-set memorisation.  Δ values are computed in z-space against a
    scaler fit on the bg-class half of the pair (so Δ = 0 on the negative side
    by construction; positive Δ means TYPHOON sits above the natural class).
    """
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.metrics import roc_auc_score
    from sklearn.model_selection import StratifiedKFold, cross_val_predict
    from sklearn.pipeline import Pipeline
    from sklearn.preprocessing import StandardScaler

    pos_mask = np.array([(c == TYPHOON_CLASS) and (p == profile) for c, p in zip(y, profiles)])
    neg_mask = np.array([c == target_class for c in y])
    if pos_mask.sum() < MIN_SAMPLES_PER_CLASS or neg_mask.sum() < MIN_SAMPLES_PER_CLASS:
        return None

    X_pos = X[pos_mask]
    X_neg = X[neg_mask]
    X_pair = np.vstack([X_pos, X_neg])
    y_pair = np.concatenate([np.ones(int(pos_mask.sum())), np.zeros(int(neg_mask.sum()))])

    scaler = StandardScaler()
    rf = RandomForestClassifier(n_estimators=RF_N_ESTIMATORS, random_state=RF_RANDOM_STATE, class_weight="balanced")
    skf = StratifiedKFold(n_splits=KFOLD_SPLITS, shuffle=True, random_state=RF_RANDOM_STATE)
    pipe = Pipeline([("scaler", scaler), ("rf", rf)])
    proba = cross_val_predict(pipe, X_pair, y_pair, cv=skf, method="predict_proba")[:, 1]

    auc = float(roc_auc_score(y_pair, proba))
    threshold, tpr = _tpr_at_fpr(proba[y_pair == 1], proba[y_pair == 0], PAIR_FPR_TARGET)

    # Feature importance: average across per-fold RFs trained inside the same
    # pipeline.  We do this with a separate manual loop so the importances come
    # from the *training-fold* fit each time — never from the held-out half.
    importances = np.zeros(X_pair.shape[1])
    for train_idx, _ in skf.split(X_pair, y_pair):
        fold_pipe = Pipeline([
            ("scaler", StandardScaler()),
            ("rf", RandomForestClassifier(n_estimators=RF_N_ESTIMATORS, random_state=RF_RANDOM_STATE, class_weight="balanced")),
        ])
        fold_pipe.fit(X_pair[train_idx], y_pair[train_idx])
        importances += fold_pipe.named_steps["rf"].feature_importances_
    importances /= KFOLD_SPLITS

    # Z-scored mean comparison against the pooled pair distribution.  Fitting
    # on the negative class alone makes features where bg has near-zero
    # variance (e.g. rtp_voice always-20 ms IAT) blow up to ±200σ; pooled
    # scaling bounds Δ in interpretable [-3, +3] territory while still
    # showing direction.
    pair_scaler = StandardScaler().fit(X_pair)
    pos_z = pair_scaler.transform(X_pos).mean(axis=0)
    neg_z = pair_scaler.transform(X_neg).mean(axis=0)

    return {
        "n_pos":       int(pos_mask.sum()),
        "n_neg":       int(neg_mask.sum()),
        "auc":         auc,
        "tpr":         tpr,
        "threshold":   threshold,
        "importances": importances,
        "pos_z":       pos_z,
        "neg_z":       neg_z,
    }


def _run_closed_world(X: np.ndarray, y: list[str]) -> dict[str, object]:
    """Stratified-5-fold (n+1)-class classifier; report per-class metrics + confusion matrix."""
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.metrics import classification_report, confusion_matrix
    from sklearn.model_selection import StratifiedKFold, cross_val_predict
    from sklearn.pipeline import Pipeline
    from sklearn.preprocessing import StandardScaler

    classes = sorted(set(y))
    cls_to_idx = {c: i for i, c in enumerate(classes)}
    y_idx = np.array([cls_to_idx[c] for c in y])

    counts = np.bincount(y_idx, minlength=len(classes))
    keep_classes = {c for c, n in zip(classes, counts) if n >= MIN_SAMPLES_PER_CLASS}
    if len(keep_classes) < 2 or TYPHOON_CLASS not in keep_classes:
        return {"error": "insufficient samples per class for k-fold"}
    keep_mask = np.array([c in keep_classes for c in y])
    X_k = X[keep_mask]
    y_k = [c for c, m in zip(y, keep_mask) if m]
    classes_k = sorted(keep_classes)
    cls_to_idx_k = {c: i for i, c in enumerate(classes_k)}
    y_k_idx = np.array([cls_to_idx_k[c] for c in y_k])

    scaler = StandardScaler()
    rf = RandomForestClassifier(n_estimators=RF_N_ESTIMATORS, random_state=RF_RANDOM_STATE, class_weight="balanced")
    pipe = Pipeline([("scaler", scaler), ("rf", rf)])
    skf = StratifiedKFold(n_splits=KFOLD_SPLITS, shuffle=True, random_state=RF_RANDOM_STATE)
    pred_idx = cross_val_predict(pipe, X_k, y_k_idx, cv=skf)

    report = classification_report(y_k_idx, pred_idx, target_names=classes_k, output_dict=True, zero_division=0)
    cm = confusion_matrix(y_k_idx, pred_idx, labels=list(range(len(classes_k))))
    return {
        "classes":            classes_k,
        "report":             report,
        "confusion_matrix":   cm,
        "skipped_classes":    sorted(set(classes) - keep_classes),
    }


def _print_pair_binary(rows: list[tuple[str, str, dict[str, object] | None]]) -> None:
    """Render Test A results: summary table + per-pair feature-importance breakdowns."""
    summary = Table(show_header=True, title="Test A — pair-binary detection (stratified 5-fold CV)", title_style="bold")
    summary.add_column("TYPHOON profile", style="magenta")
    summary.add_column("Target class", style="cyan")
    summary.add_column("N+ / N−", justify="right")
    summary.add_column("AUC-ROC", justify="right")
    summary.add_column("TPR @ 1% FPR", justify="right")
    summary.add_column("Verdict", style="dim")
    for prof, target, res in rows:
        if res is None:
            summary.add_row(prof, target, "—", "—", "—", "[yellow]skipped (too few samples)[/yellow]")
            continue
        auc = float(res["auc"])  # type: ignore[arg-type]
        verdict = (
            "[green]indistinguishable[/green]" if auc < 0.6
            else "[yellow]weakly detectable[/yellow]" if auc < 0.8
            else "[red]strongly detectable[/red]"
        )
        summary.add_row(
            prof,
            target,
            f"{res['n_pos']} / {res['n_neg']}",
            f"{auc:.3f}",
            f"{float(res['tpr']):.1%}",
            verdict,
        )
    console.print(summary)
    console.print(
        "[dim]AUC closer to 0.50 means the censor cannot tell TYPHOON-as-X from real X.  "
        "AUC = 1.0 means the pair is trivially separable.[/dim]\n"
    )

    # Per-pair feature-importance diagnostics.
    for prof, target, res in rows:
        if res is None or not isinstance(res.get("importances"), np.ndarray):
            continue
        importances: np.ndarray = res["importances"]   # type: ignore[assignment]
        pos_z: np.ndarray = res["pos_z"]               # type: ignore[assignment]
        neg_z: np.ndarray = res["neg_z"]               # type: ignore[assignment]
        order = np.argsort(importances)[::-1][:PAIR_TOP_FEATURES]
        ftbl = Table(show_header=True,
                     title=f"  {prof} vs {target} — top {PAIR_TOP_FEATURES} discriminating features",
                     title_style="dim")
        ftbl.add_column("Feature", style="cyan")
        ftbl.add_column("Importance", justify="right")
        ftbl.add_column(f"{prof} mean (z)", justify="right")
        ftbl.add_column(f"{target} mean (z)", justify="right")
        ftbl.add_column("Δ", justify="right")
        for i in order:
            delta = pos_z[i] - neg_z[i]
            colour = "[red]" if abs(delta) > LARGE_DELTA else "[yellow]" if abs(delta) > MEDIUM_DELTA else ""
            end = "[/red]" if abs(delta) > LARGE_DELTA else "[/yellow]" if abs(delta) > MEDIUM_DELTA else ""
            ftbl.add_row(
                FEATURE_NAMES[i],
                f"{importances[i]:.3f}",
                f"{pos_z[i]:+.3f}",
                f"{neg_z[i]:+.3f}",
                f"{colour}{delta:+.3f}{end}",
            )
        console.print(ftbl)
    console.print()


def _print_closed_world(result: dict[str, object]) -> None:
    """Render Test B results."""
    if "error" in result:
        console.print(f"[red]Test B skipped: {result['error']}[/red]")
        return

    classes: list[str] = result["classes"]   # type: ignore[assignment]
    report: dict = result["report"]          # type: ignore[assignment]
    cm: np.ndarray = result["confusion_matrix"]   # type: ignore[assignment]
    skipped: list[str] = result["skipped_classes"]   # type: ignore[assignment]

    console.print(f"[bold]Test B — closed-world ({len(classes)}-class classifier, stratified 5-fold CV)[/bold]")
    console.print(f"  Accuracy: [bold]{report['accuracy']:.3f}[/bold]   "
                  f"Macro-F1: [bold]{report['macro avg']['f1-score']:.3f}[/bold]")
    if skipped:
        console.print(f"  [dim]Classes skipped (< {MIN_SAMPLES_PER_CLASS} samples): {', '.join(skipped)}[/dim]")

    perclass = Table(show_header=True, title="Per-class precision / recall / F1", title_style="bold")
    perclass.add_column("Class", style="cyan")
    perclass.add_column("Support", justify="right")
    perclass.add_column("Precision", justify="right")
    perclass.add_column("Recall", justify="right")
    perclass.add_column("F1", justify="right")
    for cls in classes:
        row = report[cls]
        is_typhoon = cls == TYPHOON_CLASS
        style = "bold magenta" if is_typhoon else ""
        perclass.add_row(
            f"[{style}]{cls}[/]" if style else cls,
            str(int(row["support"])),
            f"{row['precision']:.3f}",
            f"{row['recall']:.3f}",
            f"{row['f1-score']:.3f}",
        )
    console.print(perclass)
    console.print(
        f"[dim]Headline: TYPHOON recall = {report[TYPHOON_CLASS]['recall']:.1%}.  "
        f"Lower is better for blending — a censor running this classifier mistakes TYPHOON for a natural class "
        f"{1 - report[TYPHOON_CLASS]['recall']:.0%} of the time.[/dim]\n"
    )

    # Confusion-matrix row for TYPHOON: where do the missed flows go?
    if TYPHOON_CLASS in classes:
        idx = classes.index(TYPHOON_CLASS)
        row = cm[idx]
        total = int(row.sum())
        correct = int(row[idx])
        misses = [(classes[j], int(row[j])) for j in range(len(classes)) if j != idx and row[j] > 0]
        misses.sort(key=lambda kv: -kv[1])
        if total > 0:
            console.print(f"[bold]TYPHOON misclassification breakdown[/bold] ({correct}/{total} correctly identified):")
            mtable = Table(show_header=True)
            mtable.add_column("Mistaken-for class", style="cyan")
            mtable.add_column("Count", justify="right")
            mtable.add_column("Share of TYPHOON", justify="right")
            for cls, cnt in misses:
                mtable.add_row(cls, str(cnt), f"{cnt / total:.1%}")
            console.print(mtable)


@click.command(context_settings={"help_option_names": ["-h", "--help"]})
@click.option("--corpus-root", default=None, type=click.Path(),
              help="Corpus root directory (default: results/background).")
def main(corpus_root: str | None) -> None:
    """Held-out detectability metrics: Test A (pair-binary) + Test B (closed-world n+1)."""
    root = Path(corpus_root) if corpus_root else Path(__file__).parent.parent.parent.parent / "results" / "background"
    if not root.is_dir():
        console.print(f"[red]Corpus root not found:[/red] {root}")
        sys.exit(1)

    X, y, profiles, _ = _load_corpus(root)
    if X.size == 0:
        console.print("[yellow]No flows extracted from corpus.[/yellow]")
        sys.exit(1)

    bg_count = sum(1 for c in y if c != TYPHOON_CLASS)
    typhoon_count = sum(1 for c in y if c == TYPHOON_CLASS)
    console.print(f"[bold]Corpus:[/bold] {typhoon_count} TYPHOON flows, {bg_count} background flows\n")

    # ── Test A — Pair-binary detection ──────────────────────────────────────
    rows = []
    for prof, target in PROFILE_TARGET_CLASS.items():
        rows.append((prof, target, _run_pair_binary(prof, target, X, y, profiles)))
    _print_pair_binary(rows)

    # ── Test B — Closed-world (n+1)-class ───────────────────────────────────
    _print_closed_world(_run_closed_world(X, y))


if __name__ == "__main__":
    main()
