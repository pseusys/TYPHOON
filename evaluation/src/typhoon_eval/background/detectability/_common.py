"""Shared plumbing for the held-out detectability tests (Part 3).

Cross-validation / threshold-metric helpers reused across the pair-binary
(Test A), closed-world (Test B), and open-set (Tests D/E/F) test modules.
Holds no test logic of its own; the Barradas classifier catalogue lives in
``classifiers.py``.
"""

from __future__ import annotations

import numpy as np
from rich.console import Console

console = Console()

KFOLD_SPLITS = 10                    # Barradas USENIX'18 uses 10-fold non-stratified.
MIN_SAMPLES_PER_CLASS = KFOLD_SPLITS  # need ≥ k flows per class to run KFold(k).

# Minimum number of distinct classes required for the multi-class classifier to
# run (Test B) or for the 3-of-7 bg hold-out enumerator to produce a non-trivial
# split (Tests D, F).  Below this, the test reports a clean error instead of
# fitting a degenerate model.
MIN_CLASSES_FOR_FIT = 2


def _tpr_at_fpr(scores_pos: np.ndarray, scores_neg: np.ndarray, target_fpr: float) -> tuple[float, float]:
    """TPR at FPR ≤ *target_fpr* given out-of-fold positive (TYPHOON) and negative (natural) scores."""
    if len(scores_neg) == 0 or len(scores_pos) == 0:
        return float("nan"), float("nan")
    sorted_neg = np.sort(scores_neg)[::-1]
    cutoff_idx = max(0, int(np.floor(target_fpr * len(sorted_neg))) - 1)
    threshold = float(sorted_neg[cutoff_idx])
    tpr = float((scores_pos > threshold).sum()) / len(scores_pos)
    return threshold, tpr


def _fpr_at_tpr(scores_pos: np.ndarray, scores_neg: np.ndarray, target_tpr: float) -> float:
    """FPR achieved when the threshold is set so the classifier captures ≥ ``target_tpr`` of positives.

    Mirrors the Barradas USENIX'18 reporting convention: "what's the false-
    positive cost of catching X% of tunnel traffic?".  Returns NaN when either
    side is empty.
    """
    if len(scores_neg) == 0 or len(scores_pos) == 0:
        return float("nan")
    sorted_pos = np.sort(scores_pos)
    # We want the smallest threshold such that TPR = (# pos > threshold) / n_pos >= target.
    # Equivalent: threshold is the (1 - target_tpr) quantile of the positive scores.
    quantile_idx = int(np.floor((1.0 - target_tpr) * len(sorted_pos)))
    quantile_idx = max(0, min(quantile_idx, len(sorted_pos) - 1))
    threshold = float(sorted_pos[quantile_idx])
    return float((scores_neg > threshold).sum()) / len(scores_neg)


def _ms(mean_std: tuple[float, float] | None) -> dict[str, float] | None:
    """Convert a (mean, std) tuple to a JSON-friendly dict, preserving None."""
    if mean_std is None:
        return None
    m, s = mean_std
    return {"mean": float(m), "std": float(s)}
