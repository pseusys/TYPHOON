"""Shared plumbing for the held-out detectability tests (Part 3).

Cross-validation / threshold-metric helpers reused across the pair-binary
(Test A), closed-world (Test B), and open-set (Tests D/E/F) test modules.
Holds no test logic of its own; the Barradas classifier catalogue lives in
``classifiers.py``.
"""

from __future__ import annotations

import numpy as np

from typhoon_eval.shared.console import console as console  # re-exported for pair_binary/closed_world/open_set/cli

KFOLD_SPLITS = 10                    # Barradas USENIX'18 uses 10-fold non-stratified.
MIN_SAMPLES_PER_CLASS = KFOLD_SPLITS  # need ≥ k flows per class to run KFold(k).
MIN_GROUPS_FOR_KFOLD = KFOLD_SPLITS   # GroupKFold(k) needs ≥ k distinct corpus runs to fill every fold.

# Minimum number of distinct classes required for the multi-class classifier to
# run (Test B) or for the 3-of-7 bg hold-out enumerator to produce a non-trivial
# split (Tests D, F).  Below this, the test reports a clean error instead of
# fitting a degenerate model.
MIN_CLASSES_FOR_FIT = 2


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


def _ms(mean_std: tuple[float, float] | None) -> dict[str, float] | None:
    """Convert a (mean, std) tuple to a JSON-friendly dict, preserving None."""
    if mean_std is None:
        return None
    m, s = mean_std
    return {"mean": float(m), "std": float(s)}
