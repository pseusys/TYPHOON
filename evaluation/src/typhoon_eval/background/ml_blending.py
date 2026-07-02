"""Primary blending metric for Part 3 — Test C (open-world confidence-threshold detection).

Models the realistic-adversary threat model: an observer that has labels for
the background classes only (no TYPHOON samples), runs a multi-class
classifier over the traffic mix, and thresholds prediction confidence.  The
headline number is the confident-blend fraction — the share of TYPHOON flows
the classifier confidently labels as a concrete background class.

The Barradas USENIX'18 feature pipeline and corpus loader live in
``features.py`` and are shared with the held-out detectability tests
(``detectability`` package).  This module trains a classifier on
background-only flows and reports, for each TYPHOON profile:

  * Confident-blend fraction (pred. prob ≥ THRESHOLD)
  * Mean predicted-class confidence
  * Predicted-class distribution with mean confidence per class
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
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler

from typhoon_eval.background.features import (
    FEATURE_SETS,
    TYPHOON_CLASS,
    _load_corpus,
    get_feature_names,
)

console = Console()

CONFIDENT_THRESHOLD = 0.9


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


@command(context_settings={"help_option_names": ["-h", "--help"]})
@option("--corpus-root", default=None, type=ClickPath(),
              help="Corpus root directory (default: results/background).")
@option("--features", "feature_set", default="stats",
              type=Choice(list(FEATURE_SETS)), show_default=True,
              help="Barradas USENIX'18 feature set: stats (174 features), histogram (300 features), or both.")
@option("--out-dir", default=None, type=ClickPath(),
              help="Directory for the blending.json result summary (default: <corpus-root>/plots).")
def main(corpus_root: str | None, feature_set: str, out_dir: str | None) -> None:
    """Compute confident-blend fraction + per-profile breakdown from a finished corpus."""

    root = Path(corpus_root) if corpus_root else Path(__file__).parent.parent.parent.parent / "results" / "background"
    if not root.is_dir():
        console.print(f"[red]Corpus root not found:[/red] {root}")
        exit(1)

    feature_names = get_feature_names(feature_set)
    console.print(f"[dim]Feature set: [bold]{feature_set}[/bold] ({len(feature_names)} features per flow, Barradas USENIX'18 layout)[/dim]")

    X, y, profiles, skipped = _load_corpus(root, feature_set)
    if X.size == 0:
        console.print("[yellow]No flows extracted from corpus.[/yellow]")
        exit(1)

    bg_mask = np.array([lbl != TYPHOON_CLASS for lbl in y])
    typhoon_mask = ~bg_mask
    if bg_mask.sum() == 0 or typhoon_mask.sum() == 0:
        console.print("[red]Corpus must contain both TYPHOON and background flows.[/red]")
        exit(1)

    bg_classes = sorted({lbl for lbl, m in zip(y, bg_mask, strict=True) if m})
    class_to_idx = {c: i for i, c in enumerate(bg_classes)}
    y_bg_idx_full = np.array([class_to_idx[lbl] for lbl in y if lbl != TYPHOON_CLASS])

    # Hold out 30% of background flows for a "what does a real natural flow
    # score look like?" baseline.  Without this baseline the TYPHOON confidence
    # is meaningless; with it we can see whether TYPHOON's mean confidence is
    # similar to (good blending) or much lower than (poor blending) bg flows.
    rng = np.random.default_rng(42)
    bg_indices = np.arange(int(bg_mask.sum()))
    rng.shuffle(bg_indices)
    split = int(0.7 * len(bg_indices))
    train_idx, holdout_idx = bg_indices[:split], bg_indices[split:]

    scaler = StandardScaler().fit(X[bg_mask][train_idx])
    X_bg_train = scaler.transform(X[bg_mask][train_idx])
    X_bg_holdout = scaler.transform(X[bg_mask][holdout_idx])
    X_t  = scaler.transform(X[typhoon_mask])

    # Barradas USENIX'18 RF defaults: n_estimators=100, default split criterion.
    clf = RandomForestClassifier(n_estimators=100, random_state=42)
    clf.fit(X_bg_train, y_bg_idx_full[train_idx])

    proba = clf.predict_proba(X_t)
    confidence = proba.max(axis=1)
    pred_idx = proba.argmax(axis=1)
    pred_classes = [bg_classes[i] for i in pred_idx]

    # Baseline: confidence on held-out *real* background flows.
    bg_holdout_proba = clf.predict_proba(X_bg_holdout)
    bg_holdout_conf = bg_holdout_proba.max(axis=1)

    confident = confidence >= CONFIDENT_THRESHOLD
    blend_fraction = float(confident.sum()) / len(confidence)

    console.print(
        f"[bold]Background-blending result[/bold]  "
        f"({len(confidence)} TYPHOON flows, "
        f"{bg_mask.sum()} background flows: {len(train_idx)} train + {len(holdout_idx)} hold-out)"
    )
    console.print(f"  Confident-blend fraction (conf ≥ {CONFIDENT_THRESHOLD:.2f}): [bold]{blend_fraction:.1%}[/bold]")
    console.print(f"  TYPHOON   mean confidence: [bold]{confidence.mean():.3f}[/bold]  median {float(np.median(confidence)):.3f}  (max {confidence.max():.3f})")
    console.print(f"  Held-out background:       mean {bg_holdout_conf.mean():.3f}  median {float(np.median(bg_holdout_conf)):.3f}  (max {bg_holdout_conf.max():.3f})")
    console.print(f"  [dim]Uniform-over-{len(bg_classes)}-classes baseline = {1.0 / len(bg_classes):.3f}; TYPHOON should approach the held-out figure to blend perfectly.[/dim]")

    # Confidence-threshold detector: an adversary without labelled TYPHOON data
    # can still flag flows whose multi-class confidence falls below a
    # threshold.  We pick the threshold at the 1st-percentile of held-out
    # background confidence (i.e. allow ~1 % bg false-positives) and report
    # the TYPHOON detection rate at that operating point.
    bg_p1 = float(np.percentile(bg_holdout_conf, 1))
    typhoon_caught = float((confidence < bg_p1).sum()) / len(confidence)
    bg_caught       = float((bg_holdout_conf < bg_p1).sum()) / len(bg_holdout_conf)
    console.print(
        f"  Confidence-threshold detector: threshold = {bg_p1:.3f} (bg 1st pctile)  "
        f"→ TYPHOON caught [bold]{typhoon_caught:.1%}[/bold] / bg false-pos {bg_caught:.1%}"
    )
    if skipped:
        console.print(f"  [dim]Skipped {len(skipped)} runs without metadata.[/dim]")

    # Predicted-class distribution.
    console.print("\n[bold]Predicted class distribution for TYPHOON flows:[/bold]")
    table = Table(show_header=True)
    table.add_column("Predicted class", style="cyan")
    table.add_column("Count", justify="right")
    table.add_column("Share", justify="right")
    table.add_column("Mean conf", justify="right")
    by_pred: dict[str, list[float]] = defaultdict(list)
    for cls, conf in zip(pred_classes, confidence, strict=True):
        by_pred[cls].append(conf)
    for cls, confs in sorted(by_pred.items(), key=lambda kv: -len(kv[1])):
        table.add_row(cls, str(len(confs)),
                      f"{len(confs) / len(pred_classes):.1%}",
                      f"{np.mean(confs):.3f}")
    console.print(table)

    # Per-profile breakdown.
    profiles_arr = np.array(profiles)[typhoon_mask]
    breakdown = _per_profile_breakdown(profiles_arr, confidence, pred_classes)
    if breakdown:
        console.print("\n[bold]Per-profile breakdown:[/bold]")
        ptable = Table(show_header=True)
        ptable.add_column("TYPHOON profile", style="magenta")
        ptable.add_column("N", justify="right")
        ptable.add_column("Conf-blend", justify="right")
        ptable.add_column("Mean conf", justify="right")
        ptable.add_column("Top predicted (count, conf)")
        for prof, stats in sorted(breakdown.items()):
            top = sorted(stats["predicted_distribution"].items(),
                         key=lambda kv: -kv[1]["count"])[:3]
            top_str = ", ".join(f"{c}({s['count']}, {s['mean_conf']:.2f})" for c, s in top)
            ptable.add_row(
                prof,
                str(stats["n_flows"]),
                f"{stats['confident_fraction']:.1%}",
                f"{stats['mean_confidence']:.3f}",
                top_str,
            )
        console.print(ptable)

    # Persist the metrics so the pipeline can pick them up as an artifact —
    # mirrors what background-detectability / -distplot write to --out-dir.
    out_root = Path(out_dir) if out_dir else root / "plots"
    out_root.mkdir(parents=True, exist_ok=True)
    result = {
        "feature_set":              feature_set,
        "n_features":               len(feature_names),
        "confident_threshold":      CONFIDENT_THRESHOLD,
        "n_typhoon_flows":          len(confidence),
        "n_background_flows":       int(bg_mask.sum()),
        "n_background_train":       len(train_idx),
        "n_background_holdout":     len(holdout_idx),
        "n_background_classes":     len(bg_classes),
        "blend_fraction":           blend_fraction,
        "typhoon_mean_confidence":  float(confidence.mean()),
        "typhoon_median_confidence": float(np.median(confidence)),
        "typhoon_max_confidence":   float(confidence.max()),
        "bg_holdout_mean_confidence":   float(bg_holdout_conf.mean()),
        "bg_holdout_median_confidence": float(np.median(bg_holdout_conf)),
        "uniform_baseline":         1.0 / len(bg_classes),
        "detector_threshold_bg_p1": bg_p1,
        "typhoon_caught_fraction":  typhoon_caught,
        "bg_false_positive_fraction": bg_caught,
        "skipped_runs":             len(skipped),
        "predicted_distribution": {
            cls: {
                "count":     len(confs),
                "share":     len(confs) / len(pred_classes),
                "mean_conf": float(np.mean(confs)),
            }
            for cls, confs in by_pred.items()
        },
        "per_profile": breakdown,
    }
    result_path = out_root / "blending.json"
    result_path.write_text(dumps(result, indent=2))
    console.print(f"\n  [green]wrote[/green] {result_path}")


if __name__ == "__main__":
    main()
