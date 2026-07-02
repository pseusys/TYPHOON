"""Test B — closed-world (n+1)-class classifier.

Train one multi-class Random Forest on every natural class plus TYPHOON,
with 10-fold ``KFold`` and ``cross_val_predict`` for clean out-of-fold
predictions.  Reports accuracy, macro-F1, per-class precision/recall/F1, and
a confusion matrix.  TYPHOON's recall is the headline: lower means the
adversary more often mistakes TYPHOON for a natural class.  A strictly
closed-world threat model — the adversary is assumed to have labels for every
class, including TYPHOON itself.
"""

from __future__ import annotations

import numpy as np
from rich.table import Table
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.model_selection import KFold, cross_val_predict
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from typhoon_eval.background.classifiers import RF_N_ESTIMATORS, RF_RANDOM_STATE
from typhoon_eval.background.detectability._common import (
    KFOLD_SPLITS,
    MIN_CLASSES_FOR_FIT,
    MIN_SAMPLES_PER_CLASS,
    console,
)
from typhoon_eval.background.features import TYPHOON_CLASS


def _run_closed_world(X: np.ndarray, y: list[str]) -> dict[str, object]:
    """Barradas-style closed-world (n+1)-class classifier: 10-fold KFold."""

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
    classes_k = sorted(keep_classes)
    cls_to_idx_k = {c: i for i, c in enumerate(classes_k)}
    y_k_idx = np.array([cls_to_idx_k[c] for c in y_k])

    scaler = StandardScaler()
    rf = RandomForestClassifier(n_estimators=RF_N_ESTIMATORS, random_state=RF_RANDOM_STATE, class_weight="balanced")
    pipe = Pipeline([("scaler", scaler), ("rf", rf)])
    # 10-fold non-stratified CV — matches Barradas USENIX'18.
    kfold = KFold(n_splits=KFOLD_SPLITS, shuffle=True, random_state=RF_RANDOM_STATE)
    pred_idx = cross_val_predict(pipe, X_k, y_k_idx, cv=kfold)

    report = classification_report(y_k_idx, pred_idx, target_names=classes_k, output_dict=True, zero_division=0)
    cm = confusion_matrix(y_k_idx, pred_idx, labels=list(range(len(classes_k))))
    return {
        "classes":            classes_k,
        "report":             report,
        "confusion_matrix":   cm,
        "skipped_classes":    sorted(set(classes) - keep_classes),
    }


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

    console.print(f"[bold]Test B — closed-world ({len(classes)}-class classifier, {KFOLD_SPLITS}-fold CV)[/bold]")
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
        f"Lower is better for blending — an adversary running this classifier mistakes TYPHOON for a natural class "
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
