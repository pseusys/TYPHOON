"""Primary blending metric for Part 3 — Test C (open-world confidence-threshold detection).

Models the realistic-adversary threat model: an observer that has labels for
the background classes only (no TYPHOON samples), runs a multi-class
classifier over the traffic mix, and thresholds prediction confidence.  The
headline number is the confident-blend fraction — the share of TYPHOON flows
the classifier confidently labels as a concrete background class.

The adversary picks their own classifier, so Test C is **not** tied to one
estimator: it evaluates every Barradas classifier (``rf`` / ``dt`` / ``xgb``)
and reports all of them, with the *adversary-strongest* one — the classifier
that catches the most TYPHOON at the shared ~1 % background false-positive
operating point — as the headline (worst case for TYPHOON).  Whichever
estimator is strongest today wins automatically; adding one to
``classifiers.py`` folds it into the sweep with no change here.

Scoring is k-fold out-of-fold: the multi-class classifier is trained on
background flows only (``StratifiedKFold``), TYPHOON flows are always fully
held out and scored by every fold's model (probabilities averaged), and the
background baseline confidence comes from clean out-of-fold predictions.  The
Barradas USENIX'18 feature pipeline and corpus loader live in ``features.py``
and are shared with the held-out detectability tests.
"""

from __future__ import annotations

from collections import defaultdict
from json import dumps
from pathlib import Path
from sys import exit

import numpy as np
from click import Choice, command, option
from click import Path as ClickPath
from rich.console import Console
from rich.table import Table
from sklearn.model_selection import StratifiedKFold
from sklearn.preprocessing import StandardScaler

from typhoon_eval.background.classifiers import (
    CLASSIFIER_LABELS,
    RF_RANDOM_STATE,
    make_classifier,
    resolve_classifiers,
)
from typhoon_eval.background.features import (
    FEATURE_SETS,
    TYPHOON_CLASS,
    _load_corpus,
    get_feature_names,
)
from typhoon_eval.shared.profiles import HELD_OUT_BG_CLASSES

console = Console()

CONFIDENT_THRESHOLD = 0.9
# k for the background out-of-fold cross-validation.  Reduced automatically when
# a background class has fewer than k flows (StratifiedKFold needs ≥ k per class).
BLEND_KFOLD_SPLITS = 5
MIN_KFOLD_SPLITS = 2
# Operating point for the confidence-threshold detector: the background 1st
# percentile of confidence → ~1 % background false-positive rate.  The TYPHOON
# detection rate at this fixed FPR is what ranks the classifiers.
DETECTOR_BG_PERCENTILE = 1


def _align_proba(proba: np.ndarray, classes_: np.ndarray, n_classes: int) -> np.ndarray:
    """Expand a fold's ``predict_proba`` to the full background-class column space.

    A fold's training split may (rarely) miss a background class, so its
    ``classes_`` is a subset of ``0..n_classes-1``.  Scatter the columns back
    into a full-width array so per-fold TYPHOON probabilities can be summed and
    ``argmax`` maps to the global class order.
    """
    if proba.shape[1] == n_classes:
        return proba
    full = np.zeros((proba.shape[0], n_classes), dtype=np.float64)
    full[:, classes_] = proba
    return full


def _evaluate_blend(
    X_bg: np.ndarray,
    y_bg_idx: np.ndarray,
    X_typhoon: np.ndarray,
    n_classes: int,
    classifier_name: str,
    k: int,
) -> dict[str, object]:
    """Open-world blend evaluation for one classifier, k-fold out-of-fold.

    Trains a multi-class classifier on background flows only.  Background
    confidence is out-of-fold (each flow scored by the one fold that held it
    out); TYPHOON flows are never trained on, so every fold's model scores them
    and the probabilities are averaged.  Returns confidences, predictions, and
    the blend + confidence-threshold-detector metrics.
    """
    skf = StratifiedKFold(n_splits=k, shuffle=True, random_state=RF_RANDOM_STATE)
    oof_bg_conf = np.zeros(len(X_bg), dtype=np.float64)
    typhoon_proba_sum = np.zeros((len(X_typhoon), n_classes), dtype=np.float64)
    n_folds = 0
    for train_idx, test_idx in skf.split(X_bg, y_bg_idx):
        scaler = StandardScaler().fit(X_bg[train_idx])
        clf = make_classifier(classifier_name)
        clf.fit(scaler.transform(X_bg[train_idx]), y_bg_idx[train_idx])
        oof_bg_conf[test_idx] = clf.predict_proba(scaler.transform(X_bg[test_idx])).max(axis=1)
        t_proba = clf.predict_proba(scaler.transform(X_typhoon))
        typhoon_proba_sum += _align_proba(t_proba, clf.classes_, n_classes)
        n_folds += 1

    typhoon_proba = typhoon_proba_sum / n_folds
    confidence = typhoon_proba.max(axis=1)
    pred_idx = typhoon_proba.argmax(axis=1)

    blend_fraction = float((confidence >= CONFIDENT_THRESHOLD).sum()) / len(confidence)
    bg_p = float(np.percentile(oof_bg_conf, DETECTOR_BG_PERCENTILE))
    typhoon_caught = float((confidence < bg_p).sum()) / len(confidence)
    bg_caught = float((oof_bg_conf < bg_p).sum()) / len(oof_bg_conf)
    return {
        "classifier":        classifier_name,
        "confidence":        confidence,
        "pred_idx":          pred_idx,
        "bg_holdout_conf":   oof_bg_conf,
        "blend_fraction":    blend_fraction,
        "detector_threshold": bg_p,
        "typhoon_caught":    typhoon_caught,
        "bg_false_positive": bg_caught,
        "n_folds":           n_folds,
    }


def _predicted_distribution(pred_classes: list[str], confidence: np.ndarray) -> dict[str, dict]:
    """Group TYPHOON predictions by predicted background class.  Returns ``{class: stats}``."""
    by_pred: dict[str, list[float]] = defaultdict(list)
    for cls, conf in zip(pred_classes, confidence, strict=True):
        by_pred[cls].append(float(conf))
    return {
        cls: {
            "count":     len(confs),
            "share":     len(confs) / len(pred_classes),
            "mean_conf": float(np.mean(confs)),
        }
        for cls, confs in by_pred.items()
    }


def _per_profile_breakdown(
    typhoon_profiles: np.ndarray,
    confidence: np.ndarray,
    pred_classes: list[str],
) -> dict[str, dict]:
    """Group blending stats by TYPHOON profile.  Returns ``{profile: stats}``."""
    out: dict[str, dict] = {}
    for prof in sorted(set(typhoon_profiles)):
        idx = typhoon_profiles == prof
        if not idx.any():
            continue
        prof_conf = confidence[idx]
        prof_preds = [pred_classes[i] for i in range(len(pred_classes)) if idx[i]]
        by_pred: dict[str, list[float]] = defaultdict(list)
        for cls, conf in zip(prof_preds, prof_conf, strict=True):
            by_pred[cls].append(conf)
        out[prof] = {
            "n_flows":            int(idx.sum()),
            "confident_fraction": float((prof_conf >= CONFIDENT_THRESHOLD).sum()) / len(prof_conf),
            "mean_confidence":    float(prof_conf.mean()),
            "predicted_distribution": {
                cls: {"count": len(confs), "mean_conf": float(np.mean(confs))}
                for cls, confs in by_pred.items()
            },
        }
    return out


def _result_to_json(res: dict[str, object], bg_classes: list[str]) -> dict[str, object]:
    """Serialize one classifier's blend result (scalars + predicted distribution)."""
    confidence: np.ndarray = res["confidence"]              # type: ignore[assignment]
    pred_idx: np.ndarray = res["pred_idx"]                  # type: ignore[assignment]
    bg_holdout_conf: np.ndarray = res["bg_holdout_conf"]    # type: ignore[assignment]
    pred_classes = [bg_classes[i] for i in pred_idx]
    return {
        "classifier":                 res["classifier"],
        "blend_fraction":             res["blend_fraction"],
        "typhoon_mean_confidence":    float(confidence.mean()),
        "typhoon_median_confidence":  float(np.median(confidence)),
        "typhoon_max_confidence":     float(confidence.max()),
        "bg_holdout_mean_confidence": float(bg_holdout_conf.mean()),
        "bg_holdout_median_confidence": float(np.median(bg_holdout_conf)),
        "detector_threshold_bg_p1":   res["detector_threshold"],
        "typhoon_caught_fraction":    res["typhoon_caught"],
        "bg_false_positive_fraction": res["bg_false_positive"],
        "n_folds":                    res["n_folds"],
        "predicted_distribution":     _predicted_distribution(pred_classes, confidence),
    }


@command(context_settings={"help_option_names": ["-h", "--help"]})
@option("--corpus-root", default=None, type=ClickPath(),
              help="Corpus root directory (default: results/background).")
@option("--features", "feature_set", default="stats",
              type=Choice(list(FEATURE_SETS)), show_default=True,
              help="Barradas USENIX'18 feature set: stats (174 features), histogram (300 features), or both.")
@option("--classifier", "classifier_spec", default="all", show_default=True,
              help="Barradas classifiers to evaluate: comma-separated subset of (rf, dt, xgb) or 'all'. "
                   "The adversary-strongest of the selected set is reported as the headline.")
@option("--out-dir", default=None, type=ClickPath(),
              help="Directory for the blending.json result summary (default: <corpus-root>/plots).")
def main(corpus_root: str | None, feature_set: str, classifier_spec: str, out_dir: str | None) -> None:
    """Confident-blend fraction across every Barradas classifier, headline = adversary-strongest.

    Each classifier is evaluated with k-fold out-of-fold scoring; the headline
    classifier is the one that catches the most TYPHOON flows at the shared
    ~1 % background false-positive operating point (the worst case for TYPHOON).
    """

    root = Path(corpus_root) if corpus_root else Path(__file__).parent.parent.parent.parent / "results" / "background"
    if not root.is_dir():
        console.print(f"[red]Corpus root not found:[/red] {root}")
        exit(1)

    classifiers = resolve_classifiers(classifier_spec)
    feature_names = get_feature_names(feature_set)
    console.print(
        f"[dim]Feature set: [bold]{feature_set}[/bold] ({len(feature_names)} features per flow, "
        f"Barradas USENIX'18 layout) · Classifiers: [bold]{', '.join(classifiers)}[/bold][/dim]"
    )

    X, y, profiles, _run_ids, skipped = _load_corpus(root, feature_set)
    if X.size == 0:
        console.print("[yellow]No flows extracted from corpus.[/yellow]")
        exit(1)

    bg_mask = np.array([lbl != TYPHOON_CLASS and lbl not in HELD_OUT_BG_CLASSES for lbl in y])
    typhoon_mask = np.array([lbl == TYPHOON_CLASS for lbl in y])
    if bg_mask.sum() == 0 or typhoon_mask.sum() == 0:
        console.print("[red]Corpus must contain both TYPHOON and background flows.[/red]")
        exit(1)

    n_held_out = sum(1 for lbl in y if lbl in HELD_OUT_BG_CLASSES)
    if n_held_out:
        console.print(f"  [dim]Excluded {n_held_out} held-out-class flows ({', '.join(sorted(HELD_OUT_BG_CLASSES))}) from training.[/dim]")

    bg_classes = sorted({lbl for lbl, m in zip(y, bg_mask, strict=True) if m})
    class_to_idx = {c: i for i, c in enumerate(bg_classes)}
    y_bg_idx = np.array([class_to_idx[lbl] for lbl, m in zip(y, bg_mask, strict=True) if m])
    X_bg = X[bg_mask]
    X_typhoon = X[typhoon_mask]
    profiles_arr = np.array(profiles)[typhoon_mask]

    # StratifiedKFold needs ≥ k flows in the rarest background class; shrink k to fit.
    min_class_count = int(np.bincount(y_bg_idx).min())
    k = min(BLEND_KFOLD_SPLITS, min_class_count)
    if k < MIN_KFOLD_SPLITS:
        console.print(f"[red]Rarest background class has only {min_class_count} flow(s) — need ≥ {MIN_KFOLD_SPLITS} for cross-validation.[/red]")
        exit(1)
    if k < BLEND_KFOLD_SPLITS:
        console.print(f"[dim]Reduced k to {k} (rarest background class has {min_class_count} flows).[/dim]")

    console.print(
        f"[bold]Background-blending[/bold]  "
        f"({int(typhoon_mask.sum())} TYPHOON flows, {int(bg_mask.sum())} background flows "
        f"over {len(bg_classes)} classes, {k}-fold OOF)\n"
    )

    results = {name: _evaluate_blend(X_bg, y_bg_idx, X_typhoon, len(bg_classes), name, k) for name in classifiers}

    # Adversary-strongest = catches the most TYPHOON at the shared ~1 % bg FPR.
    headline = max(classifiers, key=lambda n: results[n]["typhoon_caught"])

    # ── Per-classifier comparison (report every case) ───────────────────────
    table = Table(show_header=True, title="Test C — blending per classifier", title_style="bold")
    table.add_column("Classifier", style="cyan")
    table.add_column("Blend-frac (conf≥0.9)", justify="right")
    table.add_column("TYPHOON mean conf", justify="right")
    table.add_column("bg-holdout mean conf", justify="right")
    table.add_column("Detector thr (bg p1)", justify="right")
    table.add_column("TYPHOON caught", justify="right")
    table.add_column("bg FP", justify="right")
    for name in classifiers:
        res = results[name]
        conf: np.ndarray = res["confidence"]              # type: ignore[assignment]
        bg_conf: np.ndarray = res["bg_holdout_conf"]      # type: ignore[assignment]
        is_headline = name == headline
        label = CLASSIFIER_LABELS.get(name, name) + (" ★" if is_headline else "")
        style = "bold red" if is_headline else ""
        row = [
            f"[{style}]{label}[/]" if style else label,
            f"{res['blend_fraction']:.1%}",
            f"{conf.mean():.3f}",
            f"{bg_conf.mean():.3f}",
            f"{res['detector_threshold']:.3f}",
            f"{res['typhoon_caught']:.1%}",
            f"{res['bg_false_positive']:.1%}",
        ]
        table.add_row(*row)
    console.print(table)
    console.print(
        f"[dim]★ = adversary-strongest ({CLASSIFIER_LABELS.get(headline, headline)}): catches the most TYPHOON "
        f"at the shared ~1 % bg false-positive point — the worst case for TYPHOON.  "
        f"Uniform-over-{len(bg_classes)}-classes confidence baseline = {1.0 / len(bg_classes):.3f}; "
        f"TYPHOON should approach the bg-holdout figure to blend perfectly.[/dim]\n"
    )

    # ── Headline classifier detail: predicted-class distribution + per-profile ──
    head_res = results[headline]
    head_conf: np.ndarray = head_res["confidence"]        # type: ignore[assignment]
    head_pred_idx: np.ndarray = head_res["pred_idx"]      # type: ignore[assignment]
    head_pred_classes = [bg_classes[i] for i in head_pred_idx]

    console.print(f"[bold]Predicted class distribution for TYPHOON flows[/bold] (headline: {CLASSIFIER_LABELS.get(headline, headline)}):")
    dist = _predicted_distribution(head_pred_classes, head_conf)
    dtable = Table(show_header=True)
    dtable.add_column("Predicted class", style="cyan")
    dtable.add_column("Count", justify="right")
    dtable.add_column("Share", justify="right")
    dtable.add_column("Mean conf", justify="right")
    for cls, stats in sorted(dist.items(), key=lambda kv: -kv[1]["count"]):
        dtable.add_row(cls, str(stats["count"]), f"{stats['share']:.1%}", f"{stats['mean_conf']:.3f}")
    console.print(dtable)

    breakdown = _per_profile_breakdown(profiles_arr, head_conf, head_pred_classes)
    if breakdown:
        console.print("\n[bold]Per-profile breakdown[/bold] (headline classifier):")
        ptable = Table(show_header=True)
        ptable.add_column("TYPHOON profile", style="magenta")
        ptable.add_column("N", justify="right")
        ptable.add_column("Conf-blend", justify="right")
        ptable.add_column("Mean conf", justify="right")
        ptable.add_column("Top predicted (count, conf)")
        for prof, stats in sorted(breakdown.items()):
            top = sorted(stats["predicted_distribution"].items(), key=lambda kv: -kv[1]["count"])[:3]
            top_str = ", ".join(f"{c}({s['count']}, {s['mean_conf']:.2f})" for c, s in top)
            ptable.add_row(prof, str(stats["n_flows"]), f"{stats['confident_fraction']:.1%}", f"{stats['mean_confidence']:.3f}", top_str)
        console.print(ptable)
    if skipped:
        console.print(f"\n  [dim]Skipped {len(skipped)} runs without metadata.[/dim]")

    # ── Persist metrics: every classifier + the headline selection ──────────
    out_root = Path(out_dir) if out_dir else root / "plots"
    out_root.mkdir(parents=True, exist_ok=True)
    result = {
        "feature_set":          feature_set,
        "n_features":           len(feature_names),
        "confident_threshold":  CONFIDENT_THRESHOLD,
        "kfold_splits":         k,
        "n_typhoon_flows":      int(typhoon_mask.sum()),
        "n_background_flows":   int(bg_mask.sum()),
        "n_background_classes": len(bg_classes),
        "uniform_baseline":     1.0 / len(bg_classes),
        "classifiers":          classifiers,
        "headline_classifier":  headline,
        "headline_selection":   "max TYPHOON-caught at ~1% bg false-positive (adversary-strongest)",
        "per_classifier":       {name: _result_to_json(results[name], bg_classes) for name in classifiers},
        "headline_per_profile": breakdown,
        "skipped_runs":         len(skipped),
    }
    result_path = out_root / "blending.json"
    result_path.write_text(dumps(result, indent=2))
    console.print(f"\n  [green]wrote[/green] {result_path}")


if __name__ == "__main__":
    main()
