"""CLI entry point for the held-out detectability tests — Tests A / B / D / E / F.

Loads the shared Barradas feature corpus once, then runs each test and writes
a combined ``detection_results.json`` plus the Barradas FPR-@-TPR diagram.
Test C (the primary blending metric) lives in ``ml_blending.py`` and is run
separately.
"""

from __future__ import annotations

from json import dumps
from pathlib import Path
from sys import exit

import numpy as np
from click import Choice, command, option
from click import Path as ClickPath

from typhoon_eval.background.classifiers import (
    CLASSIFIER_LABELS,
    RF_N_ESTIMATORS,
    resolve_classifiers,
)
from typhoon_eval.background.detectability._common import (
    KFOLD_SPLITS,
    console,
)
from typhoon_eval.background.detectability.closed_world import (
    _closed_world_to_json,
    _print_closed_world,
    _print_confusion_matrix,
    _run_closed_world,
)
from typhoon_eval.background.detectability.open_set import (
    _open_set_to_json,
    _print_open_set,
    _run_one_class_open_set,
    _run_one_class_typhoon,
    _run_open_set_binary,
)
from typhoon_eval.background.detectability.pair_binary import (
    PROFILE_TARGET_CLASS,
    _pair_result_to_json,
    _plot_fpr_at_tpr,
    _print_pair_binary,
    _run_pair_binary,
)
from typhoon_eval.background.features import (
    FEATURE_SETS,
    TYPHOON_CLASS,
    _load_corpus,
    get_feature_names,
)

# Exactly two ":"-separated parts expected in the --pair flag (profile:target).
PAIR_SPEC_PARTS = 2


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
                   "`profile:target` (e.g. `raw_default:unknown`).  Tests B/D/E/F run on the "
                   "filtered TYPHOON flows + the full bg corpus.")
@option("--out-dir", default=None, type=ClickPath(),
              help="Output directory for the Barradas FPR-at-TPR diagram (default: <corpus-root>/plots).")
def main(corpus_root: str | None, feature_set: str, classifier_spec: str, pair_spec: str | None, out_dir: str | None) -> None:
    """Held-out detectability metrics — Tests A / B / D / E / F.

    Every test cross-validates with ``GroupKFold``, grouped by corpus run id,
    instead of Barradas USENIX'18's plain non-grouped ``KFold`` — a run's
    flows share one chaos (latency/jitter/loss) draw, so an ungrouped split
    could train and test on flows from the same run.  Tests D/E/F
    additionally restrict every evaluation bucket (held-out background,
    unseen classes, `unknown`, per-class breakdown) to the fold's test-run
    set, so a background flow from a run that fed training is never scored
    as if it were independently held out.

    * Test A replicates the Barradas USENIX'18 protocol, grouped by corpus run
      (see above) instead of Barradas's plain non-grouped KFold — AUC + FPR
      @ TPR ∈ {70%, 80%, 90%, 95%}, run independently for each
      selected classifier (DT / RF / XGBoost).
    * Test B is our closed-world (n+1)-class extension, RF-only.
    * Test D is open-set binary detection with 3-of-7 bg hold-out — TYPHOON +
      bg labels in training, evaluated against in-dist / unseen / unknown bg.
    * Test E is the one-class OCSVM baseline (TYPHOON labels only, pooled bg).
    * Test F combines Test E's OCSVM training with Test D's 3-of-7 hold-out
      evaluation — "leaked-client + partial DPI catalogue" threat model.
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

    classifiers = resolve_classifiers(classifier_spec)
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
    # each pair).
    pair_iter = tuple(PROFILE_TARGET_CLASS.items()) if selected_profile is None else ((selected_profile, selected_target),)
    rows: list[tuple[str, str, str, dict[str, object] | None]] = []
    for prof, target in pair_iter:
        for clf_name in classifiers:
            res = _run_pair_binary(prof, target, X, y, profiles, groups, classifier_name=clf_name)
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
        d_res = _run_open_set_binary(X, y, profiles, groups, classifier_name=clf_name)
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
    # adversary — has TYPHOON labels via OCSVM, uses a partial catalogue as
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

