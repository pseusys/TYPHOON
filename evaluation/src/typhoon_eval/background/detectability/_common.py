"""Shared plumbing for the held-out detectability tests (Part 3).

Barradas USENIX'18 classifier factory, threshold metrics, and the small
JSON / CLI helpers reused across the pair-binary (Test A), closed-world
(Test B), and open-set (Tests D/E/F) test modules.  Holds no test logic of
its own — only the pieces every test depends on.
"""

from __future__ import annotations

from typing import Any

import numpy as np
from click import BadParameter
from rich.console import Console
from sklearn.ensemble import RandomForestClassifier
from sklearn.tree import DecisionTreeClassifier
from xgboost import XGBClassifier

console = Console()

KFOLD_SPLITS = 10                    # Barradas USENIX'18 uses 10-fold non-stratified.
RF_N_ESTIMATORS = 100                # Barradas defaults: RF n_estimators=100.
RF_RANDOM_STATE = 42
MIN_SAMPLES_PER_CLASS = KFOLD_SPLITS  # need ≥ k flows per class to run KFold(k).

# Minimum number of distinct classes required for the multi-class classifier to
# run (Test B) or for the 3-of-7 bg hold-out enumerator to produce a non-trivial
# split (Tests D, F).  Below this, the test reports a clean error instead of
# fitting a degenerate model.
MIN_CLASSES_FOR_FIT = 2

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
    """Construct a Barradas-default classifier instance (RF / DT / XGBoost)."""
    if name == "rf":
        return RandomForestClassifier(
            n_estimators=RF_N_ESTIMATORS,
            max_features="sqrt",
            random_state=RF_RANDOM_STATE,
            n_jobs=-1,
        )
    if name == "dt":
        return DecisionTreeClassifier(random_state=RF_RANDOM_STATE)
    if name == "xgb":
        return XGBClassifier(
            n_estimators=RF_N_ESTIMATORS,
            random_state=RF_RANDOM_STATE,
            verbosity=0,
            n_jobs=-1,
        )
    raise ValueError(f"Unknown classifier: {name!r} (expected one of {CLASSIFIER_NAMES})")


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
