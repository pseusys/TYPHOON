"""Test A — pair-binary detection (Barradas USENIX'18).

Closed two-class detection: for each TYPHOON profile that mimics a natural
class (e.g. ``as_quic_d`` → ``quic_download``), train a binary classifier on
(TYPHOON-as-X) vs (real-X) flows only, with 10-fold ``KFold``.  Reports
AUC-ROC, TPR @ 1% FPR, and the Barradas FPR-@-TPR table from out-of-fold
predictions, plus per-pair feature-importance diagnostics.  AUC ≈ 0.5 means
indistinguishable; AUC = 1.0 means trivially detected.  Threat model:
Tschantz et al. S&P 2016 — an adversary who *suspects* the protocol and
trains a pair-specific classifier.
"""

from __future__ import annotations

from pathlib import Path

import numpy as np
from matplotlib import pyplot as plt
from rich.table import Table
from sklearn.metrics import roc_auc_score
from sklearn.model_selection import KFold, cross_val_predict
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from typhoon_eval.background.classifiers import (
    CLASSIFIER_LABELS,
    CLASSIFIER_NAMES,
    RF_N_ESTIMATORS,
    RF_RANDOM_STATE,
    make_classifier,
)
from typhoon_eval.background.detectability._common import (
    KFOLD_SPLITS,
    MIN_SAMPLES_PER_CLASS,
    _fpr_at_tpr,
    _tpr_at_fpr,
    console,
)
from typhoon_eval.background.features import TYPHOON_CLASS

PAIR_TOP_FEATURES = 5
LARGE_DELTA = 1.0
MEDIUM_DELTA = 0.5

# Test A AUC verdict bands — "indistinguishable" if the adversary cannot tell
# TYPHOON from real X, "weakly detectable" if a workable threshold exists,
# "strongly detectable" if the adversary wins outright (AUC ≥ 0.8).
AUC_INDISTINGUISHABLE_BELOW = 0.6
AUC_WEAKLY_DETECTABLE_BELOW = 0.8

# FPR colour bands for the Barradas FPR-@-TPR table cells.  Green ≥ 50 % FPR
# (TYPHOON forces collateral damage), yellow 10–50 % (marginal), red < 10 %
# (detector wins cheaply).
FPR_HIGH_GREEN = 0.5
FPR_LOW_RED = 0.1

# TPR levels at which we report the matched FPR — matches Barradas USENIX'18,
# which reports the FPR an adversary pays for each target TPR.  A lower FPR at the
# same TPR means a more accurate detector → harder for TYPHOON to hide.
BARRADAS_TPR_LEVELS: tuple[float, ...] = (0.70, 0.80, 0.90, 0.95)

PAIR_FPR_TARGET = 0.01               # 1% — small samples (~30-40) make 0.1% unreliable.

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


def _run_pair_binary(
    profile: str,
    target_class: str,
    X: np.ndarray,
    y: list[str],
    profiles: list[str],
    classifier_name: str = "rf",
) -> dict[str, object] | None:
    """Barradas USENIX'18 pair-binary test: 10-fold KFold, AUC + FPR @ TPR thresholds.

    AUC and the FPR-at-TPR table come from out-of-fold predictions (no
    leakage).  Feature importance is averaged across the per-fold models — the
    same models that produced the AUC, so the importances correspond to
    *generalising* signal, not training-set memorisation.  Δ values are
    computed in z-space against a scaler fit on the pooled pair.

    *classifier_name* selects DT / RF / XGBoost — Barradas reports all three.
    """

    pos_mask = np.array([(c == TYPHOON_CLASS) and (p == profile) for c, p in zip(y, profiles, strict=True)])
    neg_mask = np.array([c == target_class for c in y])
    if pos_mask.sum() < MIN_SAMPLES_PER_CLASS or neg_mask.sum() < MIN_SAMPLES_PER_CLASS:
        return None

    X_pos = X[pos_mask]
    X_neg = X[neg_mask]
    X_pair = np.vstack([X_pos, X_neg])
    y_pair = np.concatenate([np.ones(int(pos_mask.sum())), np.zeros(int(neg_mask.sum()))])

    # 10-fold non-stratified CV with shuffling — matches Barradas USENIX'18.
    # Class-balance is approximate; the per-fold y can be skewed, but ROC-AUC
    # and threshold-based metrics are robust to mild imbalance.
    scaler = StandardScaler()
    clf = make_classifier(classifier_name)
    kfold = KFold(n_splits=KFOLD_SPLITS, shuffle=True, random_state=RF_RANDOM_STATE)
    pipe = Pipeline([("scaler", scaler), ("clf", clf)])
    proba = cross_val_predict(pipe, X_pair, y_pair, cv=kfold, method="predict_proba")[:, 1]

    pos_scores = proba[y_pair == 1]
    neg_scores = proba[y_pair == 0]

    auc = float(roc_auc_score(y_pair, proba))
    threshold, tpr = _tpr_at_fpr(pos_scores, neg_scores, PAIR_FPR_TARGET)

    # Barradas-style FPR @ target TPR table.  One FPR value per requested TPR.
    fpr_at_tpr = {target: _fpr_at_tpr(pos_scores, neg_scores, target)
                  for target in BARRADAS_TPR_LEVELS}

    # Feature importance: average across per-fold classifiers trained inside
    # the same pipeline.  Only tree-based classifiers expose
    # ``feature_importances_`` directly; if a particular classifier doesn't,
    # we record zeros (XGBoost provides it; RF/DT obviously do).
    importances = np.zeros(X_pair.shape[1])
    importance_folds = 0
    for train_idx, _ in kfold.split(X_pair, y_pair):
        fold_pipe = Pipeline([
            ("scaler", StandardScaler()),
            ("clf", make_classifier(classifier_name)),
        ])
        fold_pipe.fit(X_pair[train_idx], y_pair[train_idx])
        fold_clf = fold_pipe.named_steps["clf"]
        fimp = getattr(fold_clf, "feature_importances_", None)
        if fimp is not None:
            importances += np.asarray(fimp, dtype=np.float64)
            importance_folds += 1
    if importance_folds > 0:
        importances /= importance_folds

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


def _print_pair_binary(
    rows: list[tuple[str, str, str, dict[str, object] | None]],
    feature_names: list[str],
) -> None:
    """Render Test A results: summary table + Barradas FPR @ TPR + per-pair feature importance.

    Each row is ``(profile, target, classifier_name, result_or_None)``.
    """
    summary = Table(show_header=True,
                    title=f"Test A — pair-binary detection (Barradas USENIX'18: {KFOLD_SPLITS}-fold KFold, n_estimators={RF_N_ESTIMATORS})",
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
        "[dim]AUC closer to 0.50 means the adversary cannot tell TYPHOON-as-X from real X.  "
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
        "rate the adversary pays to capture that fraction of TYPHOON flows.  Higher FPR = harder to "
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


def _plot_fpr_at_tpr(rows: list[tuple[str, str, str, dict[str, object] | None]], out_path: Path) -> None:
    """Faceted grouped bar chart: one sub-plot per classifier, one group per (profile, target) pair.

    Lower bars (lower FPR) = the adversary pays less to catch that TPR fraction →
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
