"""Tests D / E / F — open-set detectability.

Three open-set threat models sharing one FPR-breakdown reporting format
(in-distribution background / unseen natural / synthetic ``unknown``):

  * Test D — Open-set binary detection.  Train a TYPHOON-vs-known-background
    classifier on a random subset of the catalogued background classes
    (3-of-7 held out per fold); measure FPR on training-time, unseen, and
    ``unknown`` flows separately.  Models an adversary with a *partial*
    protocol catalogue.
  * Test E — One-class TYPHOON detector.  Train a one-class SVM on TYPHOON
    flows only (no background labels); models an adversary with leaked
    TYPHOON samples but no background classification.
  * Test F — One-class OCSVM with 3-of-7 background hold-out.  Same OCSVM
    training as E, but the FPR breakdown reuses D's hold-out structure —
    models a "leaked-client + partial-catalogue" adversary, bridging D and E.
"""

from __future__ import annotations

from itertools import combinations

import numpy as np
from rich.table import Table
from sklearn.model_selection import KFold
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.svm import OneClassSVM

from typhoon_eval.background.detectability._common import (
    MIN_CLASSES_FOR_FIT,
    RF_RANDOM_STATE,
    _make_classifier,
    _ms,
    console,
)
from typhoon_eval.background.features import TYPHOON_CLASS
from typhoon_eval.shared.profiles import HELD_OUT_BG_CLASSES

# Per-class FPR colour bands for the open-set test summaries.  Red ≥ 10 %
# (undeployable per-class collateral), yellow 2–10 % (marginal), no colour
# below 2 % (effectively unaffected).
PER_CLASS_FPR_RED = 0.10
PER_CLASS_FPR_YELLOW = 0.02


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
    Wu USENIX'23 (real-world adversary threat model: exempt known protocols,
    flag unknown-fully-encrypted), Geng TPAMI'20 (open-set evaluation).
    """

    typhoon_mask = np.array([c == TYPHOON_CLASS for c in y])
    if typhoon_mask.sum() < OPEN_SET_N_FOLDS:
        return {"error": f"need ≥ {OPEN_SET_N_FOLDS} TYPHOON flows, found {int(typhoon_mask.sum())}"}

    held_out_mask = np.array([c in HELD_OUT_BG_CLASSES for c in y])
    if held_out_mask.sum() == 0:
        return {"error": "no `unknown` flows in corpus — run the corpus with the unknown generator first"}

    typhoon_idx = np.flatnonzero(typhoon_mask)
    typhoon_kfold = KFold(n_splits=OPEN_SET_N_FOLDS, shuffle=True, random_state=RF_RANDOM_STATE)
    typhoon_folds = list(typhoon_kfold.split(typhoon_idx))

    # Enumerate every C(n_known, k) hold-out combination; each combination
    # becomes an outer-fold paired with one TYPHOON KFold split (round-robin).
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
        fold_rng = np.random.default_rng(RF_RANDOM_STATE + fold_id + 1)

        train_bg_mask = np.array([c in train_classes for c in y])
        unseen_bg_mask = np.array([c in unseen_classes for c in y])
        train_typhoon_idx = typhoon_idx[train_typhoon_local]
        test_typhoon_idx  = typhoon_idx[test_typhoon_local]

        # Hold out half of the in-distribution bg flows for FPR_in.  Stable
        # split per fold seeded by fold_rng so the eval-set composition is
        # reproducible.
        in_dist_idx = np.flatnonzero(train_bg_mask)
        in_dist_perm = fold_rng.permutation(len(in_dist_idx))
        in_dist_train = in_dist_idx[in_dist_perm[: len(in_dist_idx) // 2]]
        in_dist_test  = in_dist_idx[in_dist_perm[len(in_dist_idx) // 2 :]]

        train_idx = np.concatenate([train_typhoon_idx, in_dist_train])
        X_train = X[train_idx]
        y_train = np.array([1.0 if y[i] == TYPHOON_CLASS else 0.0 for i in train_idx])

        clf = _make_classifier(classifier_name)
        pipe = Pipeline([("scaler", StandardScaler()), ("clf", clf)])
        pipe.fit(X_train, y_train)

        scores_typhoon = pipe.predict_proba(X[test_typhoon_idx])[:, 1]
        threshold = float(np.quantile(scores_typhoon, 1.0 - OPEN_SET_TPR_TARGET))
        tpr = float((scores_typhoon >= threshold).sum()) / max(len(scores_typhoon), 1)
        per_fold_tpr.append(tpr)

        scores_in    = pipe.predict_proba(X[in_dist_test])[:, 1] if len(in_dist_test) else np.array([])
        scores_unseen = pipe.predict_proba(X[unseen_bg_mask])[:, 1] if unseen_bg_mask.any() else np.array([])
        scores_unknown = pipe.predict_proba(X[held_out_mask])[:, 1] if held_out_mask.any() else np.array([])

        if len(scores_in):
            per_fold_fpr_in.append(float((scores_in >= threshold).sum()) / len(scores_in))
        if len(scores_unseen):
            per_fold_fpr_unseen.append(float((scores_unseen >= threshold).sum()) / len(scores_unseen))
        if len(scores_unknown):
            per_fold_fpr_unknown.append(float((scores_unknown >= threshold).sum()) / len(scores_unknown))

        # Per-class FPR contributions for the breakdown table.
        for cls in train_classes | unseen_classes | HELD_OUT_BG_CLASSES:
            cls_mask = np.array([c == cls for c in y])
            eval_mask = cls_mask & ~np.isin(np.arange(len(y)), train_idx)
            if not eval_mask.any():
                continue
            cls_scores = pipe.predict_proba(X[eval_mask])[:, 1]
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
) -> dict[str, object]:
    """Test E — one-class TYPHOON detector with open-set evaluation.

    Trains a one-class SVM on TYPHOON flows only (no bg labels).  At
    inference, ``decision_function`` scores measure "TYPHOON-likeness";
    threshold is calibrated for TYPHOON TPR ≥ ``OPEN_SET_TPR_TARGET`` on
    the held-out TYPHOON fold.  Reports FPR breakdown identical to Test D
    (in-distribution bg / unseen natural / synthetic unknown).

    Cites: Ruff ICML'18 (Deep SVDD — same intuition, deep variant; OCSVM
    is the citation-clean baseline), AAE-DSVDD Computer Networks 2023
    (one-class for encrypted-tunnel detection — argues label-free training is
    the right framing when the negative class is unenumerable).
    """

    typhoon_mask = np.array([c == TYPHOON_CLASS for c in y])
    if typhoon_mask.sum() < OPEN_SET_N_FOLDS:
        return {"error": f"need ≥ {OPEN_SET_N_FOLDS} TYPHOON flows, found {int(typhoon_mask.sum())}"}

    held_out_mask = np.array([c in HELD_OUT_BG_CLASSES for c in y])
    bg_mask = ~typhoon_mask & ~held_out_mask
    typhoon_idx = np.flatnonzero(typhoon_mask)
    typhoon_kfold = KFold(n_splits=OPEN_SET_N_FOLDS, shuffle=True, random_state=RF_RANDOM_STATE)

    per_fold_tpr: list[float] = []
    per_fold_fpr_known: list[float] = []
    per_fold_fpr_unknown: list[float] = []
    per_class_fpr: dict[str, list[float]] = {}

    for train_local, test_local in typhoon_kfold.split(typhoon_idx):
        train_idx = typhoon_idx[train_local]
        test_idx  = typhoon_idx[test_local]
        pipe = Pipeline([
            ("scaler", StandardScaler()),
            ("ocsvm",  OneClassSVM(kernel="rbf", gamma=OCSVM_GAMMA, nu=OCSVM_NU)),
        ])
        pipe.fit(X[train_idx])
        scores_typhoon = pipe.decision_function(X[test_idx])
        threshold = float(np.quantile(scores_typhoon, 1.0 - OPEN_SET_TPR_TARGET))
        tpr = float((scores_typhoon >= threshold).sum()) / max(len(scores_typhoon), 1)
        per_fold_tpr.append(tpr)

        if bg_mask.any():
            bg_scores = pipe.decision_function(X[bg_mask])
            per_fold_fpr_known.append(float((bg_scores >= threshold).sum()) / len(bg_scores))
        if held_out_mask.any():
            unk_scores = pipe.decision_function(X[held_out_mask])
            per_fold_fpr_unknown.append(float((unk_scores >= threshold).sum()) / len(unk_scores))

        for cls in (set(y) - {TYPHOON_CLASS}):
            cls_mask = np.array([c == cls for c in y])
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
) -> dict[str, object]:
    """Test F — one-class TYPHOON detector with 3-of-7 bg evaluation hold-out.

    Same training as Test E (OCSVM on TYPHOON only) but evaluation reuses
    Test D's bg-class hold-out structure: each of the ``C(n_known, k)``
    bg splits assigns ``k`` catalogued bg classes to the "catalogue gap"
    bucket and the remaining ``n_known - k`` to the "catalogue subset"
    bucket.  Since the OCSVM does not train on bg, this hold-out is purely
    a *post-hoc* labelling of evaluation data — modelling an adversary who
    runs an OCSVM trained on leaked TYPHOON samples *and* has a partial DPI
    catalogue they use as a filter (not training data).

    Threat model: "leaked-client + partial-catalogue adversary".  Bridges the
    gap between Test D (TYPHOON + bg labels in training) and Test E
    (TYPHOON labels only, no bg classification at evaluation).
    """

    typhoon_mask = np.array([c == TYPHOON_CLASS for c in y])
    if typhoon_mask.sum() < OPEN_SET_N_FOLDS:
        return {"error": f"need ≥ {OPEN_SET_N_FOLDS} TYPHOON flows, found {int(typhoon_mask.sum())}"}

    held_out_mask = np.array([c in HELD_OUT_BG_CLASSES for c in y])
    if held_out_mask.sum() == 0:
        return {"error": "no `unknown` flows in corpus — run the corpus with the unknown generator first"}

    typhoon_idx = np.flatnonzero(typhoon_mask)
    typhoon_kfold = KFold(n_splits=OPEN_SET_N_FOLDS, shuffle=True, random_state=RF_RANDOM_STATE)
    typhoon_folds = list(typhoon_kfold.split(typhoon_idx))

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

        pipe = Pipeline([
            ("scaler", StandardScaler()),
            ("ocsvm", OneClassSVM(kernel="rbf", gamma=OCSVM_GAMMA, nu=OCSVM_NU)),
        ])
        pipe.fit(X[train_idx])
        scores_typhoon = pipe.decision_function(X[test_idx])
        threshold = float(np.quantile(scores_typhoon, 1.0 - OPEN_SET_TPR_TARGET))
        tpr = float((scores_typhoon >= threshold).sum()) / max(len(scores_typhoon), 1)
        per_fold_tpr.append(tpr)

        catalog_mask = np.array([c in catalog_classes for c in y])
        unseen_bg_mask = np.array([c in unseen_classes for c in y])

        if catalog_mask.any():
            catalog_scores = pipe.decision_function(X[catalog_mask])
            per_fold_fpr_in.append(float((catalog_scores >= threshold).sum()) / len(catalog_scores))
        if unseen_bg_mask.any():
            unseen_scores = pipe.decision_function(X[unseen_bg_mask])
            per_fold_fpr_unseen.append(float((unseen_scores >= threshold).sum()) / len(unseen_scores))
        if held_out_mask.any():
            unknown_scores = pipe.decision_function(X[held_out_mask])
            per_fold_fpr_unknown.append(float((unknown_scores >= threshold).sum()) / len(unknown_scores))

        for cls in catalog_classes | unseen_classes | HELD_OUT_BG_CLASSES:
            cls_mask = np.array([c == cls for c in y])
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
    """Render a Test D / E / F open-set summary.

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


def _open_set_to_json(result: dict[str, object]) -> dict[str, object]:
    """Serialize a Test D/E/F open-set result to a JSON-friendly dict."""
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
