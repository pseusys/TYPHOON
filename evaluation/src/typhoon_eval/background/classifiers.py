"""Barradas USENIX'18 supervised classifier factory, shared across Part 3.

One home for the DT / RF / XGBoost catalogue so every Part 3 metric — the
blending metric (Test C) and the held-out detectability tests (A/B/D/E/F) —
draws from the same set.  Adding a classifier here makes it available to
every test at once, so no metric hard-codes a single estimator.
"""

from __future__ import annotations

from typing import Any

from click import BadParameter
from sklearn.ensemble import RandomForestClassifier
from sklearn.tree import DecisionTreeClassifier
from xgboost import XGBClassifier

RF_N_ESTIMATORS = 100                # Barradas defaults: RF n_estimators=100.
RF_RANDOM_STATE = 42                 # Pinned so every evaluation is reproducible.

# Barradas USENIX'18 supervised classifiers — DT / RF / XGBoost.  All three
# share the same default hyperparameters from MPTAnalysis except for
# random_state, which we pin to make the evaluation reproducible.
CLASSIFIER_NAMES: tuple[str, ...] = ("rf", "dt", "xgb")
CLASSIFIER_LABELS: dict[str, str] = {
    "rf":  "Random Forest",
    "dt":  "Decision Tree",
    "xgb": "XGBoost",
}


def make_classifier(name: str) -> Any:
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


def resolve_classifiers(spec: str) -> list[str]:
    """Parse a --classifier flag.  Accepts ``all`` or a comma-separated subset."""
    if spec == "all":
        return list(CLASSIFIER_NAMES)
    names = [c.strip() for c in spec.split(",") if c.strip()]
    unknown = [c for c in names if c not in CLASSIFIER_NAMES]
    if unknown:
        raise BadParameter(f"unknown classifier(s): {', '.join(unknown)}; valid: {', '.join(CLASSIFIER_NAMES)} or 'all'")
    return names
