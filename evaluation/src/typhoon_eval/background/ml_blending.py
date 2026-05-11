"""Primary blending metric for Part 3.

Loads per-run pcaps from a corpus root, splits each pcap into per-flow
streams labelled by (src_ip, dst_ip) → service class via metadata.json,
trains a classifier on background-only flows, and reports for each
TYPHOON profile:

  * Confident-blend fraction (pred. prob ≥ THRESHOLD)
  * Mean predicted-class confidence
  * "Any-natural-class" fraction (always 100 % by construction since
     the classifier has no `typhoon` class — kept as a sanity check that
     the pipeline ran end-to-end without label leakage)
  * Predicted-class distribution with mean confidence per class
"""

from __future__ import annotations

import json
import sys
from collections import defaultdict
from pathlib import Path

import click
import numpy as np
from rich.console import Console
from rich.table import Table

from typhoon_eval.shared.pcap_stats import _entropy, _size_entropy

console = Console()

CONFIDENT_THRESHOLD = 0.9
TYPHOON_CLASS = "typhoon"

# Names of the 16 features extracted by `_features_from_records`, kept in
# sync with that function.  Used by ml_open_world for feature-importance
# reporting.
FEATURE_NAMES: list[str] = [
    "n_packets", "byte_sum",
    "size_mean", "size_std", "size_p5", "size_p50", "size_p95", "size_entropy",
    "iat_mean", "iat_std", "iat_p5", "iat_p50", "iat_p95", "iat_entropy",
    "payload_entropy", "duration_s",
]


def _per_flow_features(pcap: Path, ip_map: dict[str, dict]) -> dict[str, list[np.ndarray]]:
    """Group records by (src_ip, dst_ip) and emit one feature vector per flow."""
    ip_to_class: dict[tuple[str, str], str] = {}
    for cls, slot in ip_map.items():
        ip_to_class[(slot["client_ip"], slot["server_ip"])] = cls
        ip_to_class[(slot["server_ip"], slot["client_ip"])] = cls

    from scapy.layers.inet import IP, TCP, UDP
    from scapy.utils import PcapReader

    flows: dict[str, list[tuple[float, int, bytes]]] = defaultdict(list)
    with PcapReader(str(pcap)) as reader:
        for pkt in reader:
            if IP not in pkt:
                continue
            ip_layer = pkt[IP]
            cls = ip_to_class.get((ip_layer.src, ip_layer.dst))
            if cls is None:
                continue
            payload = b""
            if UDP in pkt:
                payload = bytes(pkt[UDP].payload)
            elif TCP in pkt:
                payload = bytes(pkt[TCP].payload)
            flows[cls].append((float(pkt.time), len(payload), payload))

    out: dict[str, list[np.ndarray]] = defaultdict(list)
    for cls, recs in flows.items():
        # Lowered from 5 to 2 so silent_idle flows (handshake-only, ~2 packets)
        # register in the analysis.  Most statistics degrade gracefully on
        # 2-sample inputs (std=0, percentiles=value); only IAT std is degenerate
        # but that's already a feature of "this flow has only one IAT value".
        if len(recs) < 2:
            continue
        out[cls].append(_features_from_records(recs))
    return out


def _features_from_records(recs: list[tuple[float, int, bytes]]) -> np.ndarray:
    """Extract a fixed-length feature vector from a single flow's records."""
    ts = np.array([r[0] for r in recs])
    sz = np.array([r[1] for r in recs], dtype=np.int64)
    payload = b"".join(r[2] for r in recs[:200])
    iats_ms = np.diff(np.sort(ts)) * 1000.0 if len(ts) > 1 else np.array([0.0])

    return np.array([
        len(recs),
        float(sz.sum()),
        float(sz.mean()) if len(sz) else 0.0,
        float(sz.std()) if len(sz) else 0.0,
        float(np.percentile(sz, 5)) if len(sz) else 0.0,
        float(np.percentile(sz, 50)) if len(sz) else 0.0,
        float(np.percentile(sz, 95)) if len(sz) else 0.0,
        float(_size_entropy(sz)) if len(sz) else 0.0,
        float(iats_ms.mean()) if len(iats_ms) else 0.0,
        float(iats_ms.std()) if len(iats_ms) else 0.0,
        float(np.percentile(iats_ms, 5)) if len(iats_ms) else 0.0,
        float(np.percentile(iats_ms, 50)) if len(iats_ms) else 0.0,
        float(np.percentile(iats_ms, 95)) if len(iats_ms) else 0.0,
        float(_size_entropy(np.round(iats_ms).astype(np.int64))) if len(iats_ms) else 0.0,
        float(_entropy(payload)),
        float(ts.max() - ts.min()) if len(ts) > 1 else 0.0,
    ])


def _load_corpus(corpus_root: Path) -> tuple[np.ndarray, list[str], list[str], list[Path]]:
    """Walk every run dir under *corpus_root* and assemble per-flow features + labels.

    Returns (X, class_labels, typhoon_profiles_or_na, skipped_runs).
    `typhoon_profiles_or_na[i]` is the profile name for typhoon flows and
    `"n/a"` for background flows — used by callers for per-profile slicing.
    """
    feats: list[np.ndarray] = []
    labels: list[str] = []
    profiles: list[str] = []
    skipped: list[Path] = []
    for run_dir in sorted(corpus_root.glob("run_*")):
        meta_path = run_dir / "metadata.json"
        if not meta_path.exists():
            skipped.append(run_dir)
            continue
        meta = json.loads(meta_path.read_text())
        ip_map = meta.get("ip_map", {})
        typhoon_profile = meta.get("typhoon_profile", "unknown")
        for pcap in run_dir.glob("*.pcap"):
            per_class = _per_flow_features(pcap, ip_map)
            for cls, vecs in per_class.items():
                for v in vecs:
                    feats.append(v)
                    labels.append(cls)
                    profiles.append(typhoon_profile if cls == TYPHOON_CLASS else "n/a")
    if not feats:
        return np.empty((0, 0)), [], [], skipped
    return np.vstack(feats), labels, profiles, skipped


def _per_profile_breakdown(
    typhoon_profiles: np.ndarray,
    confidence: np.ndarray,
    pred_classes: list[str],
) -> dict[str, dict]:
    """Group blending stats by TYPHOON profile.  Returns {profile: stats}."""
    out: dict[str, dict] = {}
    unique_profiles = sorted(set(typhoon_profiles))
    for prof in unique_profiles:
        idx = typhoon_profiles == prof
        if not idx.any():
            continue
        prof_conf = confidence[idx]
        prof_preds = [pred_classes[i] for i in range(len(pred_classes)) if idx[i]]

        by_pred: dict[str, list[float]] = defaultdict(list)
        for cls, conf in zip(prof_preds, prof_conf):
            by_pred[cls].append(conf)

        out[prof] = {
            "n_flows":              int(idx.sum()),
            "confident_fraction":   float((prof_conf >= CONFIDENT_THRESHOLD).sum()) / len(prof_conf),
            "mean_confidence":      float(prof_conf.mean()),
            "predicted_distribution": {cls: {"count": len(confs), "mean_conf": float(np.mean(confs))}
                                        for cls, confs in by_pred.items()},
        }
    return out


@click.command(context_settings={"help_option_names": ["-h", "--help"]})
@click.option("--corpus-root", default=None, type=click.Path(),
              help="Corpus root directory (default: results/background).")
def main(corpus_root: str | None) -> None:
    """Compute confident-blend fraction + per-profile breakdown from a finished corpus."""
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.preprocessing import StandardScaler

    root = Path(corpus_root) if corpus_root else Path(__file__).parent.parent.parent.parent / "results" / "background"
    if not root.is_dir():
        console.print(f"[red]Corpus root not found:[/red] {root}")
        sys.exit(1)

    X, y, profiles, skipped = _load_corpus(root)
    if X.size == 0:
        console.print("[yellow]No flows extracted from corpus.[/yellow]")
        sys.exit(1)

    bg_mask = np.array([lbl != TYPHOON_CLASS for lbl in y])
    typhoon_mask = ~bg_mask
    if bg_mask.sum() == 0 or typhoon_mask.sum() == 0:
        console.print("[red]Corpus must contain both TYPHOON and background flows.[/red]")
        sys.exit(1)

    bg_classes = sorted({lbl for lbl, m in zip(y, bg_mask) if m})
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

    clf = RandomForestClassifier(n_estimators=200, random_state=42)
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

    console.print(f"[bold]Background-blending result[/bold]  ({len(confidence)} TYPHOON flows, {bg_mask.sum()} background flows: {len(train_idx)} train + {len(holdout_idx)} hold-out)")
    console.print(f"  Confident-blend fraction (conf ≥ {CONFIDENT_THRESHOLD:.2f}): [bold]{blend_fraction:.1%}[/bold]")
    console.print(f"  TYPHOON   mean confidence: [bold]{confidence.mean():.3f}[/bold]  median {float(np.median(confidence)):.3f}  (max {confidence.max():.3f})")
    console.print(f"  Held-out background:       mean {bg_holdout_conf.mean():.3f}  median {float(np.median(bg_holdout_conf)):.3f}  (max {bg_holdout_conf.max():.3f})")
    console.print(f"  [dim]Uniform-over-{len(bg_classes)}-classes baseline = {1.0 / len(bg_classes):.3f}; TYPHOON should approach the held-out figure to blend perfectly.[/dim]")

    # Confidence-threshold detector: a censor without labelled TYPHOON data
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

    by_pred: dict[str, list[float]] = defaultdict(list)
    for cls, conf in zip(pred_classes, confidence):
        by_pred[cls].append(conf)

    console.print("\n[bold]Predicted class distribution for TYPHOON flows:[/bold]")
    table = Table(show_header=True)
    table.add_column("Predicted class", style="cyan")
    table.add_column("Count", justify="right")
    table.add_column("Share", justify="right")
    table.add_column("Mean conf", justify="right")
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


if __name__ == "__main__":
    main()
