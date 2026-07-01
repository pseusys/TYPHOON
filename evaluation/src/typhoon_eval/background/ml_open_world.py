"""Methodologically-grounded detectability metrics for Part 3.

Two tests, both with 10-fold ``GroupKFold`` cross-validation, grouped by
corpus run id, so reported numbers reflect held-out performance, never
training-set memorisation nor same-run leakage:

  * Test A — Pair-binary detection.  For each TYPHOON profile that targets a
    natural class (e.g. ``as_quic_d`` mimics ``quic_download``), train a
    binary classifier on (TYPHOON-as-X) vs (real-X) flows only, with
    ``GroupKFold(10)``.  Report AUC-ROC and TPR @ 1% FPR aggregated
    from out-of-fold predictions.  AUC ≈ 0.5 means perfectly indistinguishable;
    AUC = 1.0 means trivially detected.  This is the threat model from
    Tschantz et al. S&P 2016: a censor who *suspects* the protocol and
    trains a pair-specific classifier.

  * Test B — Closed-world (n+1)-class.  Train a multi-class classifier on
    all natural classes plus TYPHOON, with ``GroupKFold(10)`` and
    ``cross_val_predict`` for clean out-of-fold predictions.  Report
    accuracy, macro-F1, per-class precision/recall/F1, and a confusion
    matrix.  TYPHOON's recall is the headline: lower means the censor more
    often mistakes TYPHOON for a natural class.

Grouping by run id is a deliberate departure from Barradas USENIX'18's plain
non-stratified ``KFold(shuffle=True)``: a corpus run applies one chaos
(latency/jitter/loss) draw to every flow captured in it, so a run's TYPHOON
flow and any background flow captured alongside it share that draw.  Without
grouping, a fold could train on one and test on the other, leaking a
class-independent, run-specific signal into what should be a held-out
estimate.  ``GroupKFold`` has no ``shuffle``/``random_state`` — its fold
assignment is a deterministic, size-balanced partition of the run groups,
which is the accepted trade-off for eliminating that leakage.

The Test C (open-world unknown-class detection) lives in ``ml_blending.py``
and remains the realistic-censor metric — a censor without TYPHOON labels
runs a multi-class classifier and thresholds confidence.
"""

from __future__ import annotations

from itertools import combinations
from json import dumps
from pathlib import Path
from sys import exit
from typing import Any

import numpy as np
from click import BadParameter, Choice, command, option
from click import Path as ClickPath
from matplotlib import pyplot as plt
from rich.console import Console
from rich.table import Table
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score
from sklearn.model_selection import GroupKFold, cross_val_predict
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.svm import OneClassSVM
from sklearn.tree import DecisionTreeClassifier
from sklearn.utils.class_weight import compute_sample_weight

from typhoon_eval.background.ml_blending import (
    FEATURE_SETS,
    TYPHOON_CLASS,
    _load_corpus,
    get_feature_names,
)
from typhoon_eval.shared.profiles import HELD_OUT_BG_CLASSES

# XGBoost is optional — install via `poetry install --with ml -E xgboost`.
# We import it eagerly here (instead of lazily inside `_make_classifier`)
# so missing-module errors surface at module-load time with a helpful
# message rather than per-fold during a long run.  When missing, the
# `_make_classifier("xgb")` branch raises `ImportError`, which is caught
# in `main()`'s classifier-resolution loop and skipped with a warning.
try:
    from xgboost import XGBClassifier
except ImportError:
    XGBClassifier = None  # type: ignore[assignment, misc]

console = Console()

PAIR_TOP_FEATURES = 5
LARGE_DELTA = 1.0
MEDIUM_DELTA = 0.5

# Test A AUC verdict bands — "indistinguishable" if censor cannot tell TYPHOON
# from real X, "weakly detectable" if censor can find a workable threshold,
# "strongly detectable" if censor wins outright (AUC ≥ 0.8).
AUC_INDISTINGUISHABLE_BELOW = 0.6
AUC_WEAKLY_DETECTABLE_BELOW = 0.8

# FPR colour bands for the Barradas FPR-@-TPR table cells.  Green ≥ 50 % FPR
# (TYPHOON forces collateral damage), yellow 10–50 % (marginal), red < 10 %
# (detector wins cheaply).
FPR_HIGH_GREEN = 0.5
FPR_LOW_RED = 0.1

# Per-class FPR colour bands for the open-set test summaries.  Red ≥ 10 %
# (undeployable per-class collateral), yellow 2–10 % (marginal), no colour
# below 2 % (effectively unaffected).
PER_CLASS_FPR_RED = 0.10
PER_CLASS_FPR_YELLOW = 0.02

# Minimum number of samples needed to compute per-direction statistics, percentile
# bands, or per-fold variance.  Below this, the corresponding metric is zeroed
# out instead of raising — matches Barradas USENIX'18 behaviour for sparse flows.
MIN_SAMPLES_FOR_STATS = 2
# Minimum number of distinct classes required for the multi-class classifier to
# run (Test B) or for the 3-of-7 bg hold-out enumerator to produce a non-trivial
# split (Tests D, F).  Below this, the test reports a clean error instead of
# fitting a degenerate model.
MIN_CLASSES_FOR_FIT = 2
# Exactly two ":"-separated parts expected in the --pair flag (profile:target).
PAIR_SPEC_PARTS = 2

# TPR levels at which we report the matched FPR — matches Barradas USENIX'18,
# which reports the FPR a censor pays for each target TPR.  A lower FPR at the
# same TPR means a more accurate detector → harder for TYPHOON to hide.
BARRADAS_TPR_LEVELS: tuple[float, ...] = (0.70, 0.80, 0.90, 0.95)

# Each profile's intended natural-class target — the class the profile is
# designed to mimic.  Pairs not listed here are skipped in Test A.
PROFILE_TARGET_CLASS: dict[str, str] = {
    "as_quic_d":       "quic_download",
    "as_quic_u":       "quic_upload",
    "as_video":        "rtp_video",
    "as_video_bursty": "rtp_video",
    "as_voice":        "rtp_voice",
    "silent_idle":     "wireguard_idle",
    "raw_default":     "unknown",
    "tuned_default":   "unknown",
}

KFOLD_SPLITS = 10                    # Barradas USENIX'18 uses 10-fold non-stratified.
RF_N_ESTIMATORS = 100                # Barradas defaults: RF n_estimators=100.
RF_RANDOM_STATE = 42
PAIR_FPR_TARGET = 0.01               # 1% — small samples (~30-40) make 0.1% unreliable.
MIN_SAMPLES_PER_CLASS = KFOLD_SPLITS  # need ≥ k flows per class to run KFold(k).
MIN_GROUPS_FOR_KFOLD = KFOLD_SPLITS   # GroupKFold(k) needs ≥ k distinct corpus runs to fill every fold.

# Barradas USENIX'18 supervised classifiers — DT / RF / XGBoost.  All three
# share the same default hyperparameters from MPTAnalysis except for
# random_state, which we pin to make the evaluation reproducible.
CLASSIFIER_NAMES: tuple[str, ...] = ("rf", "dt", "xgb")
CLASSIFIER_LABELS: dict[str, str] = {
    "rf":  "Random Forest",
    "dt":  "Decision Tree",
    "xgb": "XGBoost",
}


def _make_classifier(name: str) -> Any:
    """Construct a Barradas-default classifier instance.

    Random Forest and Decision Tree are always available (sklearn).  XGBoost is
    an optional dependency; raises ImportError if unavailable so callers can
    surface a helpful skip message.

    RF/DT use ``class_weight="balanced"`` (matching Test B's convention) so a
    class with more captured flows — a corpus artefact of run scheduling, not
    a real signal — doesn't dominate the trained decision boundary.  XGBoost
    has no equivalent constructor option; callers weight it instead via
    ``_balanced_sample_weight_params`` and a ``clf__sample_weight`` fit param.
    """
    if name == "rf":
        return RandomForestClassifier(
            n_estimators=RF_N_ESTIMATORS,
            max_features="sqrt",
            random_state=RF_RANDOM_STATE,
            class_weight="balanced",
            n_jobs=-1,
        )
    if name == "dt":
        return DecisionTreeClassifier(random_state=RF_RANDOM_STATE, class_weight="balanced")
    if name == "xgb":
        if XGBClassifier is None:
            raise ImportError(
                "xgboost is required for --classifier=xgb; install via the optional"
                " 'ml' poetry group: poetry install --with ml -E xgboost"
            )
        return XGBClassifier(
            n_estimators=RF_N_ESTIMATORS,
            random_state=RF_RANDOM_STATE,
            verbosity=0,
            n_jobs=-1,
        )
    raise ValueError(f"Unknown classifier: {name!r} (expected one of {CLASSIFIER_NAMES})")


def _balanced_sample_weight_params(classifier_name: str, y: np.ndarray) -> dict[str, np.ndarray]:
    """``clf__sample_weight`` fit param giving XGBoost the same class balancing RF/DT get via
    ``class_weight="balanced"``.  Empty for RF/DT — weighting them again on top of their own
    ``class_weight`` would double-apply the correction.
    """
    if classifier_name != "xgb":
        return {}
    return {"clf__sample_weight": compute_sample_weight("balanced", y)}


def _threshold_for_tpr(scores_pos: np.ndarray, target_tpr: float) -> float:
    """Smallest *observed* positive score achieving TPR ``(# pos >= threshold) / n_pos ≥ target_tpr``.

    Selects an actual order statistic rather than ``np.quantile``'s default
    linearly-interpolated value — interpolation can land strictly between two
    tied scores and silently overshoot or undershoot ``target_tpr`` when the
    classifier emits few distinct probabilities (routine for DT/RF/XGB, whose
    ``predict_proba`` output is bounded by leaf/tree-vote granularity).
    """
    sorted_pos = np.sort(scores_pos)
    quantile_idx = int(np.floor((1.0 - target_tpr) * len(sorted_pos)))
    quantile_idx = max(0, min(quantile_idx, len(sorted_pos) - 1))
    return float(sorted_pos[quantile_idx])


def _threshold_for_fpr(scores_neg: np.ndarray, target_fpr: float) -> float:
    """Largest *observed* negative score achieving FPR ``(# neg >= threshold) / n_neg`` closest to
    *target_fpr*.  Mirrors ``_threshold_for_tpr``'s order-statistic convention (same reasoning:
    ``np.quantile`` interpolation can silently overshoot or undershoot the target), applied to the
    negative side instead of the positive side.
    """
    sorted_neg = np.sort(scores_neg)
    quantile_idx = int(np.floor((1.0 - target_fpr) * len(sorted_neg)))
    quantile_idx = max(0, min(quantile_idx, len(sorted_neg) - 1))
    return float(sorted_neg[quantile_idx])


def _tpr_at_fpr(scores_pos: np.ndarray, scores_neg: np.ndarray, target_fpr: float) -> tuple[float, float]:
    """TPR at FPR ≈ *target_fpr* given out-of-fold positive (TYPHOON) and negative (natural) scores."""
    if len(scores_neg) == 0 or len(scores_pos) == 0:
        return float("nan"), float("nan")
    # The "captured" side must use >= (not >), same reasoning as `_fpr_at_tpr` below — otherwise
    # the achieved FPR lands one sample short of target_fpr.
    threshold = _threshold_for_fpr(scores_neg, target_fpr)
    tpr = float((scores_pos >= threshold).sum()) / len(scores_pos)
    return threshold, tpr


def _fpr_at_tpr(scores_pos: np.ndarray, scores_neg: np.ndarray, target_tpr: float) -> float:
    """FPR achieved when the threshold is set so the classifier captures ≥ ``target_tpr`` of positives.

    Mirrors the Barradas USENIX'18 reporting convention: "what's the false-
    positive cost of catching X% of tunnel traffic?".  Returns NaN when either
    side is empty.
    """
    if len(scores_neg) == 0 or len(scores_pos) == 0:
        return float("nan")
    # Threshold is the (1 - target_tpr) quantile of the positive scores.  The
    # "captured" side must use >= (not >) — the threshold score itself has to
    # count as caught, otherwise the achieved TPR lands one sample short of
    # target_tpr.
    threshold = _threshold_for_tpr(scores_pos, target_tpr)
    return float((scores_neg >= threshold).sum()) / len(scores_neg)


def _run_pair_binary(
    profile: str,
    target_class: str,
    X: np.ndarray,
    y: list[str],
    profiles: list[str],
    groups: np.ndarray,
    classifier_name: str = "rf",
) -> dict[str, object] | None:
    """Barradas USENIX'18 pair-binary test: 10-fold GroupKFold, AUC + FPR @ TPR thresholds.

    AUC and the FPR-at-TPR table come from out-of-fold predictions (no
    leakage).  Feature importance is averaged across the per-fold models — the
    same models that produced the AUC, so the importances correspond to
    *generalising* signal, not training-set memorisation.  Δ values are
    computed in z-space against a scaler fit on the pooled pair.

    *classifier_name* selects DT / RF / XGBoost — Barradas reports all three.
    *groups* is the per-row corpus run id (see ``ml_blending._load_corpus``);
    folds never split a run's TYPHOON and real-X flows across train/test.
    """

    pos_mask = np.array([(c == TYPHOON_CLASS) and (p == profile) for c, p in zip(y, profiles, strict=True)])
    neg_mask = np.array([c == target_class for c in y])
    if pos_mask.sum() < MIN_SAMPLES_PER_CLASS or neg_mask.sum() < MIN_SAMPLES_PER_CLASS:
        return None

    X_pos = X[pos_mask]
    X_neg = X[neg_mask]
    X_pair = np.vstack([X_pos, X_neg])
    y_pair = np.concatenate([np.ones(int(pos_mask.sum())), np.zeros(int(neg_mask.sum()))])
    groups_pair = np.concatenate([groups[pos_mask], groups[neg_mask]])
    if len(np.unique(groups_pair)) < MIN_GROUPS_FOR_KFOLD:
        return None

    # 10-fold GroupKFold, grouped by corpus run id — see module docstring for
    # why plain (non-grouped) KFold would leak a run's shared chaos draw
    # across train/test.  `_make_classifier` weights RF/DT by
    # class_weight="balanced" so the *fitted model* isn't biased toward
    # whichever side of the pair has more captured flows; XGBoost gets the
    # same balancing via a `clf__sample_weight` fit param instead.
    #
    # Hand-rolled OOF loop (rather than `cross_val_predict`) for two reasons:
    # it lets XGBoost's sample weights be recomputed from each fold's own
    # training labels — `compute_sample_weight("balanced", ...)` on the full
    # pooled y_pair would apply the *global* class balance to every fold,
    # drifting from the fold's actual balance when GroupKFold produces
    # unevenly-sized folds — and it reuses the one fitted model per fold for
    # both the OOF prediction and the feature-importance average, instead of
    # fitting every fold twice (once inside `cross_val_predict`, again here).
    kfold = GroupKFold(n_splits=KFOLD_SPLITS)
    proba = np.empty(len(y_pair))
    importances = np.zeros(X_pair.shape[1])
    importance_folds = 0
    for train_idx, test_idx in kfold.split(X_pair, y_pair, groups=groups_pair):
        fold_pipe = Pipeline([
            ("scaler", StandardScaler()),
            ("clf", _make_classifier(classifier_name)),
        ])
        fold_fit_params = _balanced_sample_weight_params(classifier_name, y_pair[train_idx])
        fold_pipe.fit(X_pair[train_idx], y_pair[train_idx], **fold_fit_params)
        proba[test_idx] = fold_pipe.predict_proba(X_pair[test_idx])[:, 1]
        fold_clf = fold_pipe.named_steps["clf"]
        fimp = getattr(fold_clf, "feature_importances_", None)
        if fimp is not None:
            importances += np.asarray(fimp, dtype=np.float64)
            importance_folds += 1
    if importance_folds > 0:
        importances /= importance_folds

    pos_scores = proba[y_pair == 1]
    neg_scores = proba[y_pair == 0]

    auc = float(roc_auc_score(y_pair, proba))
    threshold, tpr = _tpr_at_fpr(pos_scores, neg_scores, PAIR_FPR_TARGET)

    # Barradas-style FPR @ target TPR table.  One FPR value per requested TPR.
    fpr_at_tpr = {target: _fpr_at_tpr(pos_scores, neg_scores, target)
                  for target in BARRADAS_TPR_LEVELS}

    # Z-scored mean comparison against the pooled pair distribution.  Fitting
    # on the negative class alone makes features where bg has near-zero
    # variance (e.g. rtp_voice always-20 ms IAT) blow up to ±200σ; pooled
    # scaling bounds Δ in interpretable [-3, +3] territory while still
    # showing direction.
    pair_scaler = StandardScaler().fit(X_pair)
    pos_z = pair_scaler.transform(X_pos).mean(axis=0)
    neg_z = pair_scaler.transform(X_neg).mean(axis=0)

    return {
        "classifier":  classifier_name,
        "n_pos":       int(pos_mask.sum()),
        "n_neg":       int(neg_mask.sum()),
        "auc":         auc,
        "tpr":         tpr,
        "threshold":   threshold,
        "fpr_at_tpr":  fpr_at_tpr,
        "importances": importances,
        "pos_z":       pos_z,
        "neg_z":       neg_z,
    }


def _run_closed_world(X: np.ndarray, y: list[str], groups: np.ndarray) -> dict[str, object]:
    """Barradas-style closed-world (n+1)-class classifier: 10-fold GroupKFold, grouped by run id."""

    classes = sorted(set(y))
    cls_to_idx = {c: i for i, c in enumerate(classes)}
    y_idx = np.array([cls_to_idx[c] for c in y])

    counts = np.bincount(y_idx, minlength=len(classes))
    keep_classes = {c for c, n in zip(classes, counts, strict=True) if n >= MIN_SAMPLES_PER_CLASS}
    if len(keep_classes) < MIN_CLASSES_FOR_FIT or TYPHOON_CLASS not in keep_classes:
        return {"error": "insufficient samples per class for k-fold"}
    keep_mask = np.array([c in keep_classes for c in y])
    X_k = X[keep_mask]
    y_k = [c for c, m in zip(y, keep_mask, strict=True) if m]
    groups_k = groups[keep_mask]
    if len(np.unique(groups_k)) < MIN_GROUPS_FOR_KFOLD:
        return {"error": "insufficient distinct corpus runs for k-fold"}
    classes_k = sorted(keep_classes)
    cls_to_idx_k = {c: i for i, c in enumerate(classes_k)}
    y_k_idx = np.array([cls_to_idx_k[c] for c in y_k])

    scaler = StandardScaler()
    rf = RandomForestClassifier(n_estimators=RF_N_ESTIMATORS, random_state=RF_RANDOM_STATE, class_weight="balanced")
    pipe = Pipeline([("scaler", scaler), ("rf", rf)])
    # 10-fold GroupKFold, grouped by corpus run id — see module docstring.
    kfold = GroupKFold(n_splits=KFOLD_SPLITS)
    pred_idx = cross_val_predict(pipe, X_k, y_k_idx, groups=groups_k, cv=kfold)

    report = classification_report(y_k_idx, pred_idx, target_names=classes_k, output_dict=True, zero_division=0)
    cm = confusion_matrix(y_k_idx, pred_idx, labels=list(range(len(classes_k))))
    return {
        "classes":            classes_k,
        "report":             report,
        "confusion_matrix":   cm,
        "skipped_classes":    sorted(set(classes) - keep_classes),
    }


def _print_pair_binary(
    rows: list[tuple[str, str, str, dict[str, object] | None]],
    feature_names: list[str],
) -> None:
    """Render Test A results: summary table + Barradas FPR @ TPR + per-pair feature importance.

    Each row is ``(profile, target, classifier_name, result_or_None)``.
    """
    summary = Table(show_header=True,
                    title=f"Test A — pair-binary detection (Barradas USENIX'18: {KFOLD_SPLITS}-fold GroupKFold, n_estimators={RF_N_ESTIMATORS})",
                    title_style="bold")
    summary.add_column("TYPHOON profile", style="magenta")
    summary.add_column("Target class", style="cyan")
    summary.add_column("Classifier", style="yellow")
    summary.add_column("N+ / N−", justify="right")
    summary.add_column("AUC-ROC", justify="right")
    summary.add_column("TPR @ 1% FPR", justify="right")
    summary.add_column("Verdict", style="dim")
    last_pair: tuple[str, str] | None = None
    for prof, target, clf_name, res in rows:
        prof_cell = prof if (prof, target) != last_pair else ""
        target_cell = target if (prof, target) != last_pair else ""
        last_pair = (prof, target)
        clf_label = CLASSIFIER_LABELS.get(clf_name, clf_name)
        if res is None:
            summary.add_row(prof_cell, target_cell, clf_label, "—", "—", "—",
                            "[yellow]skipped (too few samples)[/yellow]")
            continue
        auc = float(res["auc"])  # type: ignore[arg-type]
        verdict = (
            "[green]indistinguishable[/green]" if auc < AUC_INDISTINGUISHABLE_BELOW
            else "[yellow]weakly detectable[/yellow]" if auc < AUC_WEAKLY_DETECTABLE_BELOW
            else "[red]strongly detectable[/red]"
        )
        summary.add_row(
            prof_cell, target_cell, clf_label,
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

    # Barradas FPR @ TPR table.
    barradas = Table(show_header=True,
                     title="Test A — Barradas FPR @ TPR table",
                     title_style="bold")
    barradas.add_column("TYPHOON profile", style="magenta")
    barradas.add_column("Target class", style="cyan")
    barradas.add_column("Classifier", style="yellow")
    for tpr_level in BARRADAS_TPR_LEVELS:
        barradas.add_column(f"FPR @ TPR={tpr_level:.0%}", justify="right")
    last_pair = None
    for prof, target, clf_name, res in rows:
        prof_cell = prof if (prof, target) != last_pair else ""
        target_cell = target if (prof, target) != last_pair else ""
        last_pair = (prof, target)
        clf_label = CLASSIFIER_LABELS.get(clf_name, clf_name)
        if res is None or not isinstance(res.get("fpr_at_tpr"), dict):
            barradas.add_row(prof_cell, target_cell, clf_label,
                             *("—" for _ in BARRADAS_TPR_LEVELS))
            continue
        fpr_map: dict[float, float] = res["fpr_at_tpr"]  # type: ignore[assignment]
        cells: list[str] = []
        for tpr_level in BARRADAS_TPR_LEVELS:
            fpr = fpr_map.get(tpr_level, float("nan"))
            if np.isnan(fpr):
                cells.append("—")
            else:
                colour = "[green]" if fpr > FPR_HIGH_GREEN else "[yellow]" if fpr > FPR_LOW_RED else "[red]"
                end    = "[/green]" if fpr > FPR_HIGH_GREEN else "[/yellow]" if fpr > FPR_LOW_RED else "[/red]"
                cells.append(f"{colour}{fpr:.2%}{end}")
        barradas.add_row(prof_cell, target_cell, clf_label, *cells)
    console.print(barradas)
    console.print(
        "[dim]Barradas USENIX'18 metric: at each TPR level (column), the FPR shows the false-positive "
        "rate the censor pays to capture that fraction of TYPHOON flows.  Higher FPR = harder to "
        "detect TYPHOON without flooding alerts.  Green = good blending; red = strongly detectable.[/dim]\n"
    )

    # Per-pair feature-importance diagnostics.  Skipped for classifiers that
    # don't expose feature_importances_ (all our supported classifiers do).
    for prof, target, clf_name, res in rows:
        if res is None or not isinstance(res.get("importances"), np.ndarray):
            continue
        importances: np.ndarray = res["importances"]   # type: ignore[assignment]
        if not np.any(importances):
            continue
        pos_z: np.ndarray = res["pos_z"]               # type: ignore[assignment]
        neg_z: np.ndarray = res["neg_z"]               # type: ignore[assignment]
        order = np.argsort(importances)[::-1][:PAIR_TOP_FEATURES]
        clf_label = CLASSIFIER_LABELS.get(clf_name, clf_name)
        ftbl = Table(show_header=True,
                     title=f"  {prof} vs {target} [{clf_label}] — top {PAIR_TOP_FEATURES} discriminating features",
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
                feature_names[i] if i < len(feature_names) else f"feat_{i}",
                f"{importances[i]:.3f}",
                f"{pos_z[i]:+.3f}",
                f"{neg_z[i]:+.3f}",
                f"{colour}{delta:+.3f}{end}",
            )
        console.print(ftbl)
    console.print()


def _print_confusion_matrix(test_label: str, result: dict[str, object], typhoon_row_label: str | None = None) -> None:
    """Render the full multi-class confusion matrix from `_run_closed_world`."""
    if "error" in result:
        console.print(f"[red]{test_label} skipped: {result['error']}[/red]")
        return
    classes: list[str] = result["classes"]            # type: ignore[assignment]
    cm: np.ndarray     = result["confusion_matrix"]   # type: ignore[assignment]
    row_sums = cm.sum(axis=1)

    table = Table(title=test_label, title_style="bold", show_lines=True)
    table.add_column("true \\ predicted", style="bold cyan")
    for c in classes:
        header = f"[bold magenta]{c}[/]" if c == TYPHOON_CLASS else c
        table.add_column(header, justify="right")
    for i, true_class in enumerate(classes):
        is_typhoon_row = (true_class == TYPHOON_CLASS)
        label = typhoon_row_label if (is_typhoon_row and typhoon_row_label) else true_class
        styled_label = f"[bold magenta]{label}[/]" if is_typhoon_row else label
        row = [styled_label]
        for j in range(len(classes)):
            cnt = int(cm[i, j])
            total = int(row_sums[i])
            pct = (100.0 * cnt / total) if total > 0 else 0.0
            highlight_diag = (i == j) and cnt > 0
            cell_count = f"[bold green]{cnt}[/]" if highlight_diag else str(cnt)
            row.append(f"{cell_count}\n[dim]{pct:.0f}%[/dim]")
        table.add_row(*row)
    console.print(table)
    console.print(
        "[dim]Each cell shows the count of (true class) flows predicted as (column class); "
        "percentage is row-normalized (per true-class).  Diagonal in green is the correctly-classified count.[/dim]\n"
    )


def _print_closed_world(result: dict[str, object]) -> None:
    """Render Test B results."""
    if "error" in result:
        console.print(f"[red]Test B skipped: {result['error']}[/red]")
        return

    classes: list[str] = result["classes"]   # type: ignore[assignment]
    report: dict = result["report"]          # type: ignore[assignment]
    cm: np.ndarray = result["confusion_matrix"]   # type: ignore[assignment]
    skipped: list[str] = result["skipped_classes"]   # type: ignore[assignment]

    console.print(f"[bold]Test B — closed-world ({len(classes)}-class classifier, {KFOLD_SPLITS}-fold GroupKFold CV)[/bold]")
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
        if total > 0 and misses:
            console.print(f"[bold]TYPHOON misclassification breakdown[/bold] ({correct}/{total} correctly identified):")
            mtable = Table(show_header=True)
            mtable.add_column("Mistaken-for class", style="cyan")
            mtable.add_column("Count", justify="right")
            mtable.add_column("Share of TYPHOON", justify="right")
            for cls, cnt in misses:
                mtable.add_row(cls, str(cnt), f"{cnt / total:.1%}")
            console.print(mtable)
        elif total > 0:
            console.print(f"[dim]TYPHOON: {correct}/{total} correctly identified — no misclassifications.[/dim]")


def _plot_fpr_at_tpr(rows: list[tuple[str, str, str, dict[str, object] | None]], out_path: Path) -> None:
    """Faceted grouped bar chart: one sub-plot per classifier, one group per (profile, target) pair.

    Lower bars (lower FPR) = the censor pays less to catch that TPR fraction →
    TYPHOON more detectable; higher bars = better blending.  When only one
    classifier was evaluated, falls back to a single panel.
    """

    # Bucket the rows by classifier; within each classifier, keep the (pair → fpr_map) list.
    by_clf: dict[str, list[tuple[str, str, dict[float, float]]]] = {}
    for prof, target, clf_name, res in rows:
        if res is None or not isinstance(res.get("fpr_at_tpr"), dict):
            continue
        by_clf.setdefault(clf_name, []).append((prof, target, res["fpr_at_tpr"]))  # type: ignore[arg-type]
    if not by_clf:
        return

    classifier_order = [c for c in CLASSIFIER_NAMES if c in by_clf]
    n_clf = len(classifier_order)
    n_tprs = len(BARRADAS_TPR_LEVELS)
    max_pairs = max(len(by_clf[c]) for c in classifier_order)
    bar_w = 0.18
    colours = ["#c0392b", "#e67e22", "#2980b9", "#27ae60"]

    fig, axes = plt.subplots(n_clf, 1, figsize=(max(8, max_pairs * 1.5), 4.0 * n_clf), squeeze=False)
    for ax_row, clf_name in enumerate(classifier_order):
        ax = axes[ax_row][0]
        pairs = by_clf[clf_name]
        x = np.arange(len(pairs))
        for i, tpr_level in enumerate(BARRADAS_TPR_LEVELS):
            ys = [pair[2].get(tpr_level, float("nan")) for pair in pairs]
            ax.bar(x + (i - (n_tprs - 1) / 2) * bar_w, ys, bar_w,
                   label=f"TPR={tpr_level:.0%}", color=colours[i % len(colours)])
        ax.set_xticks(x)
        ax.set_xticklabels([f"{prof}\nvs {target}" for prof, target, _ in pairs], rotation=20, ha="right")
        ax.set_ylabel("FPR")
        ax.set_ylim(0.0, 1.0)
        ax.axhline(0.01, color="grey", linestyle="--", linewidth=0.6, alpha=0.7)
        ax.set_title(f"{CLASSIFIER_LABELS.get(clf_name, clf_name)} — Barradas FPR @ TPR per pair",
                     fontweight="bold")
        ax.legend(loc="upper right", fontsize=8)
        ax.grid(alpha=0.25, axis="y", linestyle="--")
    fig.suptitle("Test A — Barradas FPR @ TPR (higher bars = better blending)",
                 fontsize=12, fontweight="bold", y=0.995)
    fig.tight_layout(rect=(0, 0, 1, 0.985))
    fig.savefig(out_path, format="pdf", bbox_inches="tight")
    plt.close(fig)


# Test D / E — open-set evaluation parameters.  Train on a random subset of
# the *known* bg classes; hold the remainder out as "unseen natural", and
# always hold out the synthetic `unknown` class as a separate evaluation
# bucket modelling the long-tail of private / custom / legacy UDP protocols.
OPEN_SET_TPR_TARGET = 0.95
# Number of *known* bg classes held out per fold as "unseen natural".  Set to 3
# of 7 — empirical observation from Wireshark/nDPI/MAWI is that real DPI tools
# catalogue only a fraction of UDP protocols; holding out ~43% of the
# catalogued bg surface per fold mirrors that catalogue sparsity.  Folds are
# enumerated via ``itertools.combinations`` so every (n choose k) hold-out is
# evaluated exactly once.
OPEN_SET_HOLDOUT_K = 3
OPEN_SET_N_FOLDS = 10
OCSVM_NU = 0.05
OCSVM_GAMMA = "scale"


def _enumerate_known_bg_splits(
    y: list[str],
    holdout_k: int,
) -> list[tuple[set[str], set[str]]]:
    """Enumerate every (train_classes, unseen_classes) split of the *known* bg
    classes with exactly ``holdout_k`` classes held out per split.

    Returns a list of ``(train_set, unseen_set)`` pairs covering all
    ``C(n_known, holdout_k)`` combinations.  Held-out classes (currently just
    ``"unknown"``) are excluded from both — they are evaluated separately as
    the synthetic unknown bucket.  Falls back to leave-one-out when there are
    too few known classes to hold out *holdout_k* at once.
    """
    known: set[str] = {c for c in set(y) if c != TYPHOON_CLASS and c not in HELD_OUT_BG_CLASSES}
    if len(known) < MIN_CLASSES_FOR_FIT:
        return [(known, set())]
    known_sorted = sorted(known)
    effective_k = min(max(1, holdout_k), len(known_sorted) - 1)
    splits: list[tuple[set[str], set[str]]] = []
    for unseen_combo in combinations(known_sorted, effective_k):
        unseen_set = set(unseen_combo)
        train_set = set(known_sorted) - unseen_set
        splits.append((train_set, unseen_set))
    return splits


def _run_open_set_binary(
    X: np.ndarray,
    y: list[str],
    profiles: list[str],
    groups: np.ndarray,
    classifier_name: str = "rf",
) -> dict[str, object]:
    """Test D — Barradas-style binary detector with open-set evaluation.

    Each fold trains a TYPHOON-vs-known-bg-subset classifier and evaluates
    on three disjoint buckets:

      * In-distribution bg flows from the train-time classes → FPR_in_dist.
      * Held-out bg flows from classes the model never saw (rotated per
        fold so every known bg class plays the unseen role) → FPR_unseen.
      * Synthetic `unknown` flows (the per-run long-tail-UDP generator),
        always held out → FPR_unknown.

    Threshold is calibrated so TYPHOON TPR ≥ ``OPEN_SET_TPR_TARGET`` on
    that fold's held-out TYPHOON flows.  Reports mean ± std across folds
    plus per-class FPR breakdown (which natural classes the detector most
    often mistakes for TYPHOON).

    Cites: Wang & Dyer CCS'15 (binary detection of obfuscated tunnelling
    against background traffic), Barradas USENIX'18 (RF/DT/XGB family),
    Wu USENIX'23 (real-world censor threat model: exempt known protocols,
    block unknown-fully-encrypted), Geng TPAMI'20 (open-set evaluation).

    *groups* (per-row corpus run id) drives a single train-runs/test-runs
    partition per fold (derived from the TYPHOON GroupKFold split below) —
    every training-time signal (TYPHOON flows *and* in-distribution bg
    flows) comes only from train-runs, and every evaluation bucket
    (in-distribution held-out, unseen, synthetic unknown, per-class
    breakdown) comes only from test-runs.  No run ever contributes both
    training and held-out evaluation data, closing the gap where a bg flow
    could previously land in the eval set for a run that also fed training.
    """

    typhoon_mask = np.array([c == TYPHOON_CLASS for c in y])
    if typhoon_mask.sum() < OPEN_SET_N_FOLDS:
        return {"error": f"need ≥ {OPEN_SET_N_FOLDS} TYPHOON flows, found {int(typhoon_mask.sum())}"}

    held_out_mask = np.array([c in HELD_OUT_BG_CLASSES for c in y])
    if held_out_mask.sum() == 0:
        return {"error": "no `unknown` flows in corpus — run the corpus with the unknown generator first"}

    typhoon_idx = np.flatnonzero(typhoon_mask)
    typhoon_groups = groups[typhoon_idx]
    if len(np.unique(typhoon_groups)) < OPEN_SET_N_FOLDS:
        return {"error": f"need ≥ {OPEN_SET_N_FOLDS} distinct corpus runs with a TYPHOON flow, found {len(np.unique(typhoon_groups))}"}
    typhoon_kfold = GroupKFold(n_splits=OPEN_SET_N_FOLDS)
    typhoon_folds = list(typhoon_kfold.split(typhoon_idx, groups=typhoon_groups))

    # Enumerate every C(n_known, k) hold-out combination; each combination
    # becomes an outer-fold paired with one TYPHOON GroupKFold split (round-robin).
    bg_splits = _enumerate_known_bg_splits(y, OPEN_SET_HOLDOUT_K)

    per_fold_tpr: list[float] = []
    per_fold_fpr_in: list[float] = []
    per_fold_fpr_unseen: list[float] = []
    per_fold_fpr_unknown: list[float] = []
    per_class_fpr: dict[str, list[float]] = {}

    for fold_id, (train_classes, unseen_classes) in enumerate(bg_splits):
        if not train_classes:
            continue
        train_typhoon_local, test_typhoon_local = typhoon_folds[fold_id % len(typhoon_folds)]
        train_typhoon_idx = typhoon_idx[train_typhoon_local]
        test_typhoon_idx  = typhoon_idx[test_typhoon_local]

        # GroupKFold guarantees these two run sets are disjoint — every row
        # in the corpus is unambiguously training-side or evaluation-side.
        train_run_mask = np.isin(groups, groups[train_typhoon_idx])
        test_run_mask  = np.isin(groups, groups[test_typhoon_idx])

        train_bg_mask   = np.array([c in train_classes for c in y]) & train_run_mask
        in_dist_eval_mask = np.array([c in train_classes for c in y]) & test_run_mask
        unseen_bg_mask  = np.array([c in unseen_classes for c in y]) & test_run_mask
        held_out_eval_mask = held_out_mask & test_run_mask

        train_idx = np.concatenate([train_typhoon_idx, np.flatnonzero(train_bg_mask)])
        X_train = X[train_idx]
        y_train = np.array([1.0 if y[i] == TYPHOON_CLASS else 0.0 for i in train_idx])

        clf = _make_classifier(classifier_name)
        pipe = Pipeline([("scaler", StandardScaler()), ("clf", clf)])
        pipe.fit(X_train, y_train, **_balanced_sample_weight_params(classifier_name, y_train))

        scores_typhoon = pipe.predict_proba(X[test_typhoon_idx])[:, 1]
        threshold = _threshold_for_tpr(scores_typhoon, OPEN_SET_TPR_TARGET)
        tpr = float((scores_typhoon >= threshold).sum()) / max(len(scores_typhoon), 1)
        per_fold_tpr.append(tpr)

        scores_in     = pipe.predict_proba(X[in_dist_eval_mask])[:, 1] if in_dist_eval_mask.any() else np.array([])
        scores_unseen = pipe.predict_proba(X[unseen_bg_mask])[:, 1] if unseen_bg_mask.any() else np.array([])
        scores_unknown = pipe.predict_proba(X[held_out_eval_mask])[:, 1] if held_out_eval_mask.any() else np.array([])

        if len(scores_in):
            per_fold_fpr_in.append(float((scores_in >= threshold).sum()) / len(scores_in))
        if len(scores_unseen):
            per_fold_fpr_unseen.append(float((scores_unseen >= threshold).sum()) / len(scores_unseen))
        if len(scores_unknown):
            per_fold_fpr_unknown.append(float((scores_unknown >= threshold).sum()) / len(scores_unknown))

        # Per-class FPR contributions for the breakdown table — test-runs only,
        # same as every other evaluation bucket above.
        for cls in train_classes | unseen_classes | HELD_OUT_BG_CLASSES:
            cls_mask = np.array([c == cls for c in y]) & test_run_mask
            if not cls_mask.any():
                continue
            cls_scores = pipe.predict_proba(X[cls_mask])[:, 1]
            per_class_fpr.setdefault(cls, []).append(float((cls_scores >= threshold).sum()) / len(cls_scores))

    if not per_fold_tpr:
        return {"error": "no known bg classes available for training (the corpus needs at least 2 catalogued bg classes besides the held-out `unknown`)"}
    return {
        "classifier": classifier_name,
        "tpr":            (float(np.mean(per_fold_tpr)),            float(np.std(per_fold_tpr))),
        "fpr_in_dist":    (float(np.mean(per_fold_fpr_in)),         float(np.std(per_fold_fpr_in))) if per_fold_fpr_in else None,
        "fpr_unseen":     (float(np.mean(per_fold_fpr_unseen)),     float(np.std(per_fold_fpr_unseen))) if per_fold_fpr_unseen else None,
        "fpr_unknown":    (float(np.mean(per_fold_fpr_unknown)),    float(np.std(per_fold_fpr_unknown))) if per_fold_fpr_unknown else None,
        "per_class_fpr":  {c: (float(np.mean(v)), float(np.std(v))) for c, v in per_class_fpr.items()},
        "tpr_target":     OPEN_SET_TPR_TARGET,
        "n_folds":        len(per_fold_tpr),
        "holdout_k":      OPEN_SET_HOLDOUT_K,
    }


def _run_one_class_typhoon(
    X: np.ndarray,
    y: list[str],
    groups: np.ndarray,
) -> dict[str, object]:
    """Test E — one-class TYPHOON detector with open-set evaluation.

    Trains a one-class SVM on TYPHOON flows only (no bg labels).  At
    inference, ``decision_function`` scores measure "TYPHOON-likeness";
    threshold is calibrated for TYPHOON TPR ≥ ``OPEN_SET_TPR_TARGET`` on
    the held-out TYPHOON fold.  Reports FPR breakdown identical to Test D
    (in-distribution bg / unseen natural / synthetic unknown).

    Cites: Ruff ICML'18 (Deep SVDD — same intuition, deep variant; OCSVM
    is the citation-clean baseline), AAE-DSVDD Computer Networks 2023
    (one-class for VPN/tunnel detection — argues label-free training is
    the right framing when the negative class is unenumerable).

    *groups* restricts every evaluation bucket (bg / unknown / per-class) to
    the fold's test-run set — a bg flow from a run that fed training is
    never scored as if it were held out, even though the OCSVM never saw
    its label.
    """

    typhoon_mask = np.array([c == TYPHOON_CLASS for c in y])
    if typhoon_mask.sum() < OPEN_SET_N_FOLDS:
        return {"error": f"need ≥ {OPEN_SET_N_FOLDS} TYPHOON flows, found {int(typhoon_mask.sum())}"}

    held_out_mask = np.array([c in HELD_OUT_BG_CLASSES for c in y])
    bg_mask = ~typhoon_mask & ~held_out_mask
    typhoon_idx = np.flatnonzero(typhoon_mask)
    typhoon_groups = groups[typhoon_idx]
    if len(np.unique(typhoon_groups)) < OPEN_SET_N_FOLDS:
        return {"error": f"need ≥ {OPEN_SET_N_FOLDS} distinct corpus runs with a TYPHOON flow, found {len(np.unique(typhoon_groups))}"}
    typhoon_kfold = GroupKFold(n_splits=OPEN_SET_N_FOLDS)

    per_fold_tpr: list[float] = []
    per_fold_fpr_known: list[float] = []
    per_fold_fpr_unknown: list[float] = []
    per_class_fpr: dict[str, list[float]] = {}

    for train_local, test_local in typhoon_kfold.split(typhoon_idx, groups=typhoon_groups):
        train_idx = typhoon_idx[train_local]
        test_idx  = typhoon_idx[test_local]
        test_run_mask = np.isin(groups, groups[test_idx])
        pipe = Pipeline([
            ("scaler", StandardScaler()),
            ("ocsvm",  OneClassSVM(kernel="rbf", gamma=OCSVM_GAMMA, nu=OCSVM_NU)),
        ])
        pipe.fit(X[train_idx])
        scores_typhoon = pipe.decision_function(X[test_idx])
        threshold = _threshold_for_tpr(scores_typhoon, OPEN_SET_TPR_TARGET)
        tpr = float((scores_typhoon >= threshold).sum()) / max(len(scores_typhoon), 1)
        per_fold_tpr.append(tpr)

        bg_eval_mask = bg_mask & test_run_mask
        held_out_eval_mask = held_out_mask & test_run_mask
        if bg_eval_mask.any():
            bg_scores = pipe.decision_function(X[bg_eval_mask])
            per_fold_fpr_known.append(float((bg_scores >= threshold).sum()) / len(bg_scores))
        if held_out_eval_mask.any():
            unk_scores = pipe.decision_function(X[held_out_eval_mask])
            per_fold_fpr_unknown.append(float((unk_scores >= threshold).sum()) / len(unk_scores))

        for cls in (set(y) - {TYPHOON_CLASS}):
            cls_mask = np.array([c == cls for c in y]) & test_run_mask
            if not cls_mask.any():
                continue
            cls_scores = pipe.decision_function(X[cls_mask])
            per_class_fpr.setdefault(cls, []).append(float((cls_scores >= threshold).sum()) / len(cls_scores))

    return {
        "tpr":            (float(np.mean(per_fold_tpr)),         float(np.std(per_fold_tpr))),
        "fpr_known":      (float(np.mean(per_fold_fpr_known)),   float(np.std(per_fold_fpr_known))) if per_fold_fpr_known else None,
        "fpr_unknown":    (float(np.mean(per_fold_fpr_unknown)), float(np.std(per_fold_fpr_unknown))) if per_fold_fpr_unknown else None,
        "per_class_fpr":  {c: (float(np.mean(v)), float(np.std(v))) for c, v in per_class_fpr.items()},
        "tpr_target":     OPEN_SET_TPR_TARGET,
        "n_folds":        len(per_fold_tpr),
    }


def _run_one_class_open_set(
    X: np.ndarray,
    y: list[str],
    groups: np.ndarray,
) -> dict[str, object]:
    """Test F — one-class TYPHOON detector with 3-of-7 bg evaluation hold-out.

    Same training as Test E (OCSVM on TYPHOON only) but evaluation reuses
    Test D's bg-class hold-out structure: each of the ``C(n_known, k)``
    bg splits assigns ``k`` catalogued bg classes to the "censor's catalog
    gap" bucket and the remaining ``n_known - k`` to the "catalog subset"
    bucket.  Since the OCSVM does not train on bg, this hold-out is purely
    a *post-hoc* labelling of evaluation data — modelling a censor who runs
    an OCSVM trained on leaked TYPHOON samples *and* has a partial DPI
    catalog they use as a filter (not training data).

    Threat model: "leaked-client + partial-catalog censor".  Bridges the
    gap between Test D (TYPHOON + bg labels in training) and Test E
    (TYPHOON labels only, no bg classification at evaluation).

    *groups* restricts every evaluation bucket (catalog / unseen / unknown /
    per-class) to the fold's test-run set, same rationale as Test E.
    """

    typhoon_mask = np.array([c == TYPHOON_CLASS for c in y])
    if typhoon_mask.sum() < OPEN_SET_N_FOLDS:
        return {"error": f"need ≥ {OPEN_SET_N_FOLDS} TYPHOON flows, found {int(typhoon_mask.sum())}"}

    held_out_mask = np.array([c in HELD_OUT_BG_CLASSES for c in y])
    if held_out_mask.sum() == 0:
        return {"error": "no `unknown` flows in corpus — run the corpus with the unknown generator first"}

    typhoon_idx = np.flatnonzero(typhoon_mask)
    typhoon_groups = groups[typhoon_idx]
    if len(np.unique(typhoon_groups)) < OPEN_SET_N_FOLDS:
        return {"error": f"need ≥ {OPEN_SET_N_FOLDS} distinct corpus runs with a TYPHOON flow, found {len(np.unique(typhoon_groups))}"}
    typhoon_kfold = GroupKFold(n_splits=OPEN_SET_N_FOLDS)
    typhoon_folds = list(typhoon_kfold.split(typhoon_idx, groups=typhoon_groups))

    bg_splits = _enumerate_known_bg_splits(y, OPEN_SET_HOLDOUT_K)

    per_fold_tpr: list[float] = []
    per_fold_fpr_in: list[float] = []
    per_fold_fpr_unseen: list[float] = []
    per_fold_fpr_unknown: list[float] = []
    per_class_fpr: dict[str, list[float]] = {}

    for fold_id, (catalog_classes, unseen_classes) in enumerate(bg_splits):
        if not catalog_classes:
            continue
        train_typhoon_local, test_typhoon_local = typhoon_folds[fold_id % len(typhoon_folds)]
        train_idx = typhoon_idx[train_typhoon_local]
        test_idx = typhoon_idx[test_typhoon_local]
        test_run_mask = np.isin(groups, groups[test_idx])

        pipe = Pipeline([
            ("scaler", StandardScaler()),
            ("ocsvm", OneClassSVM(kernel="rbf", gamma=OCSVM_GAMMA, nu=OCSVM_NU)),
        ])
        pipe.fit(X[train_idx])
        scores_typhoon = pipe.decision_function(X[test_idx])
        threshold = _threshold_for_tpr(scores_typhoon, OPEN_SET_TPR_TARGET)
        tpr = float((scores_typhoon >= threshold).sum()) / max(len(scores_typhoon), 1)
        per_fold_tpr.append(tpr)

        catalog_mask = np.array([c in catalog_classes for c in y]) & test_run_mask
        unseen_bg_mask = np.array([c in unseen_classes for c in y]) & test_run_mask
        held_out_eval_mask = held_out_mask & test_run_mask

        if catalog_mask.any():
            catalog_scores = pipe.decision_function(X[catalog_mask])
            per_fold_fpr_in.append(float((catalog_scores >= threshold).sum()) / len(catalog_scores))
        if unseen_bg_mask.any():
            unseen_scores = pipe.decision_function(X[unseen_bg_mask])
            per_fold_fpr_unseen.append(float((unseen_scores >= threshold).sum()) / len(unseen_scores))
        if held_out_eval_mask.any():
            unknown_scores = pipe.decision_function(X[held_out_eval_mask])
            per_fold_fpr_unknown.append(float((unknown_scores >= threshold).sum()) / len(unknown_scores))

        for cls in catalog_classes | unseen_classes | HELD_OUT_BG_CLASSES:
            cls_mask = np.array([c == cls for c in y]) & test_run_mask
            if not cls_mask.any():
                continue
            cls_scores = pipe.decision_function(X[cls_mask])
            per_class_fpr.setdefault(cls, []).append(float((cls_scores >= threshold).sum()) / len(cls_scores))

    if not per_fold_tpr:
        return {"error": "no known bg classes available for evaluation (the corpus needs at least 2 catalogued bg classes besides the held-out `unknown`)"}

    return {
        "tpr":            (float(np.mean(per_fold_tpr)),            float(np.std(per_fold_tpr))),
        "fpr_in_dist":    (float(np.mean(per_fold_fpr_in)),         float(np.std(per_fold_fpr_in))) if per_fold_fpr_in else None,
        "fpr_unseen":     (float(np.mean(per_fold_fpr_unseen)),     float(np.std(per_fold_fpr_unseen))) if per_fold_fpr_unseen else None,
        "fpr_unknown":    (float(np.mean(per_fold_fpr_unknown)),    float(np.std(per_fold_fpr_unknown))) if per_fold_fpr_unknown else None,
        "per_class_fpr":  {c: (float(np.mean(v)), float(np.std(v))) for c, v in per_class_fpr.items()},
        "tpr_target":     OPEN_SET_TPR_TARGET,
        "n_folds":        len(per_fold_tpr),
        "holdout_k":      OPEN_SET_HOLDOUT_K,
    }


def _print_open_set(test_label: str, result: dict[str, object]) -> None:
    """Render Test D or Test E summary.

    Headline rows show TPR at the calibration target plus FPRs on the three
    buckets (in-distribution / unseen-natural / synthetic-unknown).  The
    per-class breakdown shows which natural classes each detector confuses
    with TYPHOON most often — useful to identify which bg generators carry
    the residual fingerprint signal.
    """
    if "error" in result:
        console.print(f"[red]{test_label} skipped: {result['error']}[/red]")
        return
    tpr_mean, tpr_std = result["tpr"]               # type: ignore[misc]
    summary = Table(show_header=True, title=test_label, title_style="bold")
    summary.add_column("Metric", style="cyan")
    summary.add_column("Mean ± std", justify="right")
    summary.add_column("Bucket", style="dim")
    summary.add_row(f"TPR (calibrated TPR target = {result['tpr_target']:.0%})",
                    f"{tpr_mean:.1%} ± {tpr_std:.1%}",
                    "held-out TYPHOON")
    for key, label, bucket in (
        ("fpr_in_dist", "FPR (in-distribution)",     "bg classes seen during training"),
        ("fpr_known",   "FPR (known bg)",            "all bg classes except `unknown`"),
        ("fpr_unseen",  "FPR (unseen natural)",      "known bg classes held out from training"),
        ("fpr_unknown", "FPR (synthetic unknown)",   "long-tail UDP — `unknown` generator"),
    ):
        val = result.get(key)
        if val is None:
            continue
        m, s = val                                  # type: ignore[misc]
        summary.add_row(label, f"{m:.1%} ± {s:.1%}", bucket)
    console.print(summary)

    per_class = result.get("per_class_fpr") or {}
    if per_class:
        breakdown = Table(show_header=True, title=f"{test_label} — per-class FPR",
                          title_style="dim")
        breakdown.add_column("Class", style="cyan")
        breakdown.add_column("FPR mean ± std", justify="right")
        for cls in sorted(per_class.keys()):
            m, s = per_class[cls]                   # type: ignore[misc]
            colour = "[red]" if m >= PER_CLASS_FPR_RED else "[yellow]" if m >= PER_CLASS_FPR_YELLOW else ""
            end    = "[/red]" if m >= PER_CLASS_FPR_RED else "[/yellow]" if m >= PER_CLASS_FPR_YELLOW else ""
            breakdown.add_row(cls, f"{colour}{m:.1%} ± {s:.1%}{end}")
        console.print(breakdown)
    holdout_note = (
        f", hold-out k = {result['holdout_k']} unseen-natural class(es) per fold"
        if "holdout_k" in result else ""
    )
    console.print(
        f"[dim]N folds: {result['n_folds']}{holdout_note}.  TPR target = {result['tpr_target']:.0%} — "
        f"threshold calibrated per fold so the held-out TYPHOON detection rate hits the target; "
        f"FPRs are measured at that same threshold.[/dim]\n"
    )


def _resolve_classifiers(spec: str) -> list[str]:
    """Parse the --classifier flag.  Accepts ``all`` or a comma-separated subset."""
    if spec == "all":
        return list(CLASSIFIER_NAMES)
    names = [c.strip() for c in spec.split(",") if c.strip()]
    unknown = [c for c in names if c not in CLASSIFIER_NAMES]
    if unknown:
        raise BadParameter(f"unknown classifier(s): {', '.join(unknown)}; valid: {', '.join(CLASSIFIER_NAMES)} or 'all'")
    return names


def _ms(mean_std: tuple[float, float] | None) -> dict[str, float] | None:
    """Convert a (mean, std) tuple to a JSON-friendly dict, preserving None."""
    if mean_std is None:
        return None
    m, s = mean_std
    return {"mean": float(m), "std": float(s)}


def _pair_result_to_json(prof: str, target: str, clf_name: str, res: dict[str, object] | None, feature_names: list[str]) -> dict[str, object]:
    """Serialize one Test A pair-binary result to a JSON-friendly dict."""
    base: dict[str, object] = {"profile": prof, "target": target, "classifier": clf_name}
    if res is None:
        base["status"] = "skipped"
        return base
    importances: np.ndarray = res["importances"]              # type: ignore[assignment]
    pos_z: np.ndarray = res["pos_z"]                          # type: ignore[assignment]
    neg_z: np.ndarray = res["neg_z"]                          # type: ignore[assignment]
    fpr_at_tpr: dict[float, float] = res["fpr_at_tpr"]        # type: ignore[assignment]
    ranked = sorted(
        ({"feature": feature_names[i] if i < len(feature_names) else f"feat_{i}",
          "importance": float(importances[i]),
          "typhoon_z": float(pos_z[i]),
          "target_z": float(neg_z[i]),
          "delta_z": float(pos_z[i] - neg_z[i])}
         for i in range(len(importances))),
        key=lambda r: -r["importance"],
    )
    base.update({
        "status":          "ok",
        "n_pos":           int(res["n_pos"]),                 # type: ignore[arg-type]
        "n_neg":           int(res["n_neg"]),                 # type: ignore[arg-type]
        "auc":             float(res["auc"]),                 # type: ignore[arg-type]
        "tpr_at_1pct_fpr": float(res["tpr"]),                 # type: ignore[arg-type]
        "threshold":       float(res["threshold"]),           # type: ignore[arg-type]
        "fpr_at_tpr":      {f"{int(k * 100)}%": float(v) for k, v in fpr_at_tpr.items()},
        "features":        ranked,
    })
    return base


def _closed_world_to_json(result: dict[str, object]) -> dict[str, object]:
    """Serialize Test B closed-world result to a JSON-friendly dict."""
    if "error" in result:
        return {"status": "error", "error": result["error"]}
    classes: list[str] = result["classes"]                    # type: ignore[assignment]
    report: dict = result["report"]                           # type: ignore[assignment]
    cm: np.ndarray = result["confusion_matrix"]               # type: ignore[assignment]
    skipped: list[str] = result["skipped_classes"]            # type: ignore[assignment]
    typhoon_breakdown = None
    if TYPHOON_CLASS in classes:
        idx = classes.index(TYPHOON_CLASS)
        row = cm[idx]
        total = int(row.sum())
        misses = {classes[j]: int(row[j]) for j in range(len(classes)) if j != idx and row[j] > 0}
        typhoon_breakdown = {
            "correct":    int(row[idx]),
            "total":      total,
            "mistaken_for": dict(sorted(misses.items(), key=lambda kv: -kv[1])),
        }
    return {
        "status":           "ok",
        "classes":          classes,
        "accuracy":         float(report["accuracy"]),
        "macro_f1":         float(report["macro avg"]["f1-score"]),
        "per_class":        {cls: {"precision": float(report[cls]["precision"]),
                                    "recall":    float(report[cls]["recall"]),
                                    "f1":        float(report[cls]["f1-score"]),
                                    "support":   int(report[cls]["support"])}
                              for cls in classes},
        "confusion_matrix": [[int(v) for v in row] for row in cm],
        "skipped_classes":  skipped,
        "typhoon":          typhoon_breakdown,
    }


def _open_set_to_json(result: dict[str, object]) -> dict[str, object]:
    """Serialize Test D/E open-set result to a JSON-friendly dict."""
    if "error" in result:
        return {"status": "error", "error": result["error"]}
    serialized: dict[str, object] = {
        "status":         "ok",
        "tpr":            _ms(result["tpr"]),                 # type: ignore[arg-type]
        "tpr_target":     float(result["tpr_target"]),        # type: ignore[arg-type]
        "n_folds":        int(result["n_folds"]),             # type: ignore[arg-type]
    }
    for key in ("fpr_in_dist", "fpr_known", "fpr_unseen", "fpr_unknown"):
        if key in result:
            serialized[key] = _ms(result.get(key))            # type: ignore[arg-type]
    pcf = result.get("per_class_fpr") or {}
    serialized["per_class_fpr"] = {cls: _ms(v) for cls, v in pcf.items()}        # type: ignore[arg-type]
    if "classifier" in result:
        serialized["classifier"] = result["classifier"]
    if "holdout_k" in result:
        serialized["holdout_k"] = int(result["holdout_k"])    # type: ignore[arg-type]
    return serialized


@command(context_settings={"help_option_names": ["-h", "--help"]})
@option("--corpus-root", default=None, type=ClickPath(),
              help="Corpus root directory (default: results/background).")
@option("--features", "feature_set", default="stats",
              type=Choice(list(FEATURE_SETS)), show_default=True,
              help="Barradas USENIX'18 feature set: stats (174 features), histogram (300 features), or both.")
@option("--classifier", "classifier_spec", default="all", show_default=True,
              help="Barradas classifiers to run: comma-separated subset of (rf, dt, xgb) or 'all'.")
@option("--pair", "pair_spec", default=None, type=str,
              help="Restrict TYPHOON to a single profile and Test A to the named pair, format "
                   "`profile:target` (e.g. `raw_default:unknown`).  Tests B/C/D/E run on the "
                   "filtered TYPHOON flows + the full bg corpus.")
@option("--out-dir", default=None, type=ClickPath(),
              help="Output directory for the Barradas FPR-at-TPR diagram (default: <corpus-root>/plots).")
def main(corpus_root: str | None, feature_set: str, classifier_spec: str, pair_spec: str | None, out_dir: str | None) -> None:
    """Held-out detectability metrics — Tests A / B / D / E / F.

    * Test A replicates the Barradas USENIX'18 protocol, grouped by corpus run
      (see module docstring) instead of Barradas's plain non-grouped KFold —
      AUC + FPR @ TPR ∈ {70%, 80%, 90%, 95%}, run independently for each
      selected classifier (DT / RF / XGBoost).
    * Test B is our closed-world (n+1)-class extension, RF-only.
    * Test D is open-set binary detection with 3-of-7 bg hold-out — TYPHOON +
      bg labels in training, evaluated against in-dist / unseen / unknown bg.
    * Test E is the one-class OCSVM baseline (TYPHOON labels only, pooled bg).
    * Test F combines Test E's OCSVM training with Test D's 3-of-7 hold-out
      evaluation — "leaked-client + partial DPI catalog" threat model.
    """
    root = Path(corpus_root) if corpus_root else Path(__file__).parent.parent.parent.parent / "results" / "background"
    if not root.is_dir():
        console.print(f"[red]Corpus root not found:[/red] {root}")
        exit(1)

    selected_profile: str | None = None
    selected_target: str | None = None
    if pair_spec:
        parts = pair_spec.split(":", 1)
        if len(parts) != PAIR_SPEC_PARTS or not all(parts):
            console.print(f"[red]--pair must be of the form PROFILE:TARGET (got {pair_spec!r})[/red]")
            exit(1)
        selected_profile, selected_target = parts[0], parts[1]

    classifiers = _resolve_classifiers(classifier_spec)
    feature_names = get_feature_names(feature_set)
    console.print(
        f"[dim]Feature set: [bold]{feature_set}[/bold] ({len(feature_names)} features per flow, "
        f"Barradas USENIX'18 layout) · Classifiers: [bold]{', '.join(classifiers)}[/bold][/dim]"
    )

    X, y, profiles, run_ids, _ = _load_corpus(root, feature_set)
    if X.size == 0:
        console.print("[yellow]No flows extracted from corpus.[/yellow]")
        exit(1)
    groups = np.array(run_ids)

    if selected_profile is not None:
        keep = np.array([
            (cls != TYPHOON_CLASS) or (prof == selected_profile)
            for cls, prof in zip(y, profiles, strict=True)
        ])
        kept_typhoon = int(((np.array(y) == TYPHOON_CLASS) & keep).sum())
        X = X[keep]
        y = [cls for cls, k in zip(y, keep, strict=True) if k]
        profiles = [prof for prof, k in zip(profiles, keep, strict=True) if k]
        groups = groups[keep]
        console.print(
            f"[dim]Pair filter active: TYPHOON profile = "
            f"[bold]{selected_profile}[/bold] ({kept_typhoon} flows kept); "
            f"Test A target = [bold]{selected_target}[/bold].[/dim]"
        )
        if kept_typhoon == 0:
            console.print(
                f"[red]No TYPHOON flows found for profile {selected_profile!r} — "
                f"check the corpus ran with that profile.[/red]"
            )
            exit(1)

    bg_count = sum(1 for c in y if c != TYPHOON_CLASS)
    typhoon_count = sum(1 for c in y if c == TYPHOON_CLASS)
    console.print(f"[bold]Corpus:[/bold] {typhoon_count} TYPHOON flows, {bg_count} background flows\n")

    # ── Test A — Pair-binary detection (Barradas USENIX'18 protocol) ───────
    # Iterate (pair, classifier) so the report groups consecutive rows for
    # the same pair together (read top-to-bottom: vary classifier within
    # each pair).  Skip a classifier entirely if its optional dep is missing.
    pair_iter = tuple(PROFILE_TARGET_CLASS.items()) if selected_profile is None else ((selected_profile, selected_target),)
    rows: list[tuple[str, str, str, dict[str, object] | None]] = []
    skipped_classifiers: set[str] = set()
    for prof, target in pair_iter:
        for clf_name in classifiers:
            if clf_name in skipped_classifiers:
                continue
            try:
                res = _run_pair_binary(prof, target, X, y, profiles, groups, classifier_name=clf_name)
            except ImportError as exc:
                console.print(f"[yellow]Skipping {CLASSIFIER_LABELS.get(clf_name, clf_name)}: {exc}[/yellow]")
                skipped_classifiers.add(clf_name)
                continue
            rows.append((prof, target, clf_name, res))
    _print_pair_binary(rows, feature_names)

    # Write the Barradas FPR-at-TPR diagram (faceted by classifier).
    out_root = Path(out_dir) if out_dir else root / "plots"
    out_root.mkdir(parents=True, exist_ok=True)
    barradas_path = out_root / "barradas_fpr_at_tpr.pdf"
    _plot_fpr_at_tpr(rows, barradas_path)
    console.print(f"  [green]wrote[/green] {barradas_path}\n")

    # ── Test B — Closed-world (n+1)-class ───────────────────────────────────
    # Test B is our extension to Barradas — kept as RF-only since the multi-
    # classifier sweep is meaningful only in the binary detection setting.
    b_res = _run_closed_world(X, y, groups)
    _print_closed_world(b_res)

    # ── Test D — Open-set binary detection ──────────────────────────────────
    # Mirrors Barradas's binary detection but with open-set evaluation:
    # FPR is measured separately on training-time bg classes, on unseen
    # natural bg classes, and on the synthetic `unknown` long-tail class.
    # Reported once per classifier so DT/RF/XGBoost can be compared directly.
    test_d_results: list[tuple[str, dict[str, object]]] = []
    for clf_name in classifiers:
        if clf_name in skipped_classifiers:
            continue
        try:
            d_res = _run_open_set_binary(X, y, profiles, groups, classifier_name=clf_name)
        except ImportError as exc:
            console.print(f"[yellow]Test D skipping {CLASSIFIER_LABELS.get(clf_name, clf_name)}: {exc}[/yellow]")
            continue
        _print_open_set(f"Test D — Open-set binary detection [{CLASSIFIER_LABELS.get(clf_name, clf_name)}]", d_res)
        test_d_results.append((clf_name, d_res))

    # ── Test E — One-class TYPHOON detector ─────────────────────────────────
    # OneClassSVM trained on TYPHOON flows only; FPR breakdown matches Test D.
    e_res = _run_one_class_typhoon(X, y, groups)
    _print_open_set("Test E — One-class TYPHOON detector (OCSVM)", e_res)

    # ── Test F — One-class OCSVM + 3-of-7 bg evaluation hold-out ───────────
    # Same OCSVM training as Test E but the FPR breakdown uses Test D's
    # 3-of-7 bg hold-out so the in_dist / unseen / unknown buckets are
    # directly comparable.  Models a "leaked-client + partial DPI catalog"
    # censor — has TYPHOON labels via OCSVM, uses a partial catalog as
    # filter (not training data).
    f_res = _run_one_class_open_set(X, y, groups)
    _print_open_set("Test F — One-class OCSVM with 3-of-7 bg eval hold-out", f_res)

    # ── Confusion matrix — emitted when --pair is used so the per-class
    #    breakdown of (true → predicted) is visible for the named profile.
    if selected_profile is not None:
        cm_label = (
            f"Multi-class confusion matrix — TYPHOON({selected_profile}) vs all bg "
            f"({KFOLD_SPLITS}-fold GroupKFold, n_estimators={RF_N_ESTIMATORS})"
        )
        _print_confusion_matrix(cm_label, b_res, typhoon_row_label=f"TYPHOON({selected_profile})")

    # ── JSON output: every test's machine-readable result for downstream analysis ──
    summary = {
        "feature_set":       feature_set,
        "classifiers":       classifiers,
        "n_typhoon_flows":   typhoon_count,
        "n_bg_flows":        bg_count,
        "pair_filter":       {"profile": selected_profile, "target": selected_target} if selected_profile else None,
        "test_a_pair_binary": [_pair_result_to_json(p, t, c, r, feature_names) for p, t, c, r in rows],
        "test_b_closed_world": _closed_world_to_json(b_res),
        "test_d_open_set_binary": [
            {"classifier": clf_name, **{k: v for k, v in _open_set_to_json(r).items() if k != "classifier"}}
            for clf_name, r in test_d_results
        ],
        "test_e_one_class_typhoon": _open_set_to_json(e_res),
        "test_f_one_class_open_set": _open_set_to_json(f_res),
    }
    json_path = out_root / "detection_results.json"
    json_path.write_text(dumps(summary, indent=2))
    console.print(f"  [green]wrote[/green] {json_path}\n")


if __name__ == "__main__":
    main()
