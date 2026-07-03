"""Primary blending metric for Part 3 — Test C (open-world confidence-threshold detection).

Models the realistic-adversary threat model: an observer that has labels for
the background classes only (no TYPHOON samples), runs a multi-class
classifier over the traffic mix, and thresholds prediction confidence.  The
headline number is the confident-blend fraction — the share of TYPHOON flows
the classifier confidently labels as a concrete background class.

Implements the Barradas USENIX'18 feature pipeline literally: one feature
vector per flow, with statistics computed three times (total / c2s / s2c)
and concatenated, plus per-direction burst statistics.  The alternative
``histogram`` feature set is a 300-bin packet-length histogram over 0–1500B.

Selectable via ``--features {stats,histogram,both}``.  ``stats`` mirrors
Barradas's primary feature set (174 features); ``histogram`` mirrors the
alternative 5-byte-binning set (300 features); ``both`` concatenates them.

Trains a classifier on background-only flows and reports for each TYPHOON
profile:

  * Confident-blend fraction (pred. prob ≥ THRESHOLD)
  * Mean predicted-class confidence
  * Predicted-class distribution with mean confidence per class
"""

from __future__ import annotations

from collections import defaultdict
from json import dumps, loads
from pathlib import Path
from sys import exit

import numpy as np
from click import Choice, command, option
from click import Path as ClickPath
from rich.console import Console
from rich.table import Table
from scapy.layers.inet import IP, UDP
from scapy.utils import PcapReader
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler

from typhoon_eval.shared.pcap_stats import _entropy, _size_entropy

console = Console()

CONFIDENT_THRESHOLD = 0.9
TYPHOON_CLASS = "typhoon"
# Minimum packets per flow required to compute the Barradas feature vector.
MIN_SAMPLES_FOR_STATS = 2

# Direction grouping for the Barradas concatenated feature layout.
# ``DIRECTION_GROUPS`` covers what Barradas calls (total, out, in) — we use
# (total, c2s, s2c).  ``DIRECTIONS`` is the strict directional set used for
# burst attribution and per-direction visualisations.
DIRECTION_GROUPS: tuple[str, str, str] = ("total", "c2s", "s2c")
DIRECTIONS: tuple[str, str] = ("c2s", "s2c")

# Percentiles computed for sizes / IATs / burst stats — matches Barradas
# USENIX'18 (deciles p10..p90).
PERCENTILES: tuple[int, ...] = (10, 20, 30, 40, 50, 60, 70, 80, 90)

# Moment statistics computed alongside percentiles.  "var" and "std" both
# appear in Barradas; we keep both to stay literal to the reference set.
_MOMENT_NAMES: tuple[str, ...] = ("min", "max", "mean", "std", "var", "kurt", "skew")

# Barradas alternative feature set: 5-byte-bin packet-length histogram over
# 0..1500 B inclusive → 300 bins.
BARRADAS_HIST_BIN_WIDTH = 5
BARRADAS_HIST_MAX = 1500
BARRADAS_HIST_N_BINS = BARRADAS_HIST_MAX // BARRADAS_HIST_BIN_WIDTH


def _moment_and_percentile_names(prefix: str) -> list[str]:
    return [f"{prefix}_{m}" for m in _MOMENT_NAMES] + [f"{prefix}_p{p}" for p in PERCENTILES]


def _build_stats_feature_names() -> list[str]:
    """Layout: 3 globals + 3 × (entropies + size block + IAT block) + 2 × (burst-count + pkt block + byte block).

    Matches Barradas USENIX'18:
      total / c2s / s2c × (size entropy + IAT entropy + payload entropy + 7 moments + 9 deciles for sizes + 7 moments + 9 deciles for IATs)
      + outgoing-burst stats (count + 7 moments + 9 deciles for packet counts + same for byte sums)
      + incoming-burst stats (same)
    Resulting feature count: 3 + 3 × 35 + 2 × 33 = 174.
    """
    names: list[str] = ["n_packets", "byte_sum", "duration_s"]
    for group in DIRECTION_GROUPS:
        names += [
            f"{group}_size_entropy",
            f"{group}_iat_entropy",
            f"{group}_payload_entropy",
            *_moment_and_percentile_names(f"{group}_size"),
            *_moment_and_percentile_names(f"{group}_iat"),
        ]
    for direction in DIRECTIONS:
        names += [
            f"{direction}_burst_count",
            *_moment_and_percentile_names(f"{direction}_burst_pkts"),
            *_moment_and_percentile_names(f"{direction}_burst_bytes"),
        ]
    return names


STATS_FEATURE_NAMES: list[str] = _build_stats_feature_names()

HISTOGRAM_FEATURE_NAMES: list[str] = [
    f"hist_{i * BARRADAS_HIST_BIN_WIDTH}_{(i + 1) * BARRADAS_HIST_BIN_WIDTH}"
    for i in range(BARRADAS_HIST_N_BINS)
]

FEATURE_SETS: tuple[str, str, str] = ("stats", "histogram", "both")


def get_feature_names(feature_set: str) -> list[str]:
    """Return the ordered feature-name list for the requested feature_set."""
    if feature_set == "stats":
        return list(STATS_FEATURE_NAMES)
    if feature_set == "histogram":
        return list(HISTOGRAM_FEATURE_NAMES)
    if feature_set == "both":
        return list(STATS_FEATURE_NAMES) + list(HISTOGRAM_FEATURE_NAMES)
    raise ValueError(f"Unknown feature_set: {feature_set!r} (expected one of {FEATURE_SETS})")


# Back-compat alias for callers that still import FEATURE_NAMES.
FEATURE_NAMES: list[str] = STATS_FEATURE_NAMES


def _moment_and_decile_block(vals: np.ndarray) -> list[float]:
    """Compute the Barradas per-metric block: 7 moments + 9 deciles = 16 features.

    Order matches :data:`_MOMENT_NAMES` followed by :data:`PERCENTILES`.
    Skewness and kurtosis are computed manually (no scipy dependency) — kurtosis
    is Fisher / excess (subtract 3).  Returns zeros for empty inputs.
    """
    if len(vals) == 0:
        return [0.0] * (len(_MOMENT_NAMES) + len(PERCENTILES))
    arr = vals.astype(np.float64)
    mean = float(arr.mean())
    std  = float(arr.std())
    var  = float(arr.var())
    if std > 0:
        z = (arr - mean) / std
        skew = float(np.mean(z ** 3))
        kurt = float(np.mean(z ** 4) - 3.0)
    else:
        skew = 0.0
        kurt = 0.0
    moments = [float(arr.min()), float(arr.max()), mean, std, var, kurt, skew]
    deciles = [float(np.percentile(arr, p)) for p in PERCENTILES]
    return moments + deciles


def _compute_bursts_per_direction(
    timeline: list[tuple[float, int, str]],
) -> dict[str, dict[str, np.ndarray]]:
    """Identify contiguous same-direction runs (bursts) across the full flow.

    Returns ``{direction: {"pkts": np.ndarray, "bytes": np.ndarray}}`` where the
    arrays hold per-burst packet counts and byte sums.  Bursts are attributed
    to their direction — c2s bursts go in ``out["c2s"]`` etc.
    """
    bursts: dict[str, dict[str, list[int]]] = {d: {"pkts": [], "bytes": []} for d in DIRECTIONS}
    if not timeline:
        return {d: {"pkts": np.array([]), "bytes": np.array([])} for d in DIRECTIONS}

    sorted_timeline = sorted(timeline, key=lambda r: r[0])
    current_dir: str | None = None
    current_pkts = 0
    current_bytes = 0
    for _, size, direction in sorted_timeline:
        if direction != current_dir:
            if current_dir is not None and current_pkts > 0:
                bursts[current_dir]["pkts"].append(current_pkts)
                bursts[current_dir]["bytes"].append(current_bytes)
            current_dir = direction
            current_pkts = 1
            current_bytes = size
        else:
            current_pkts += 1
            current_bytes += size
    if current_dir is not None and current_pkts > 0:
        bursts[current_dir]["pkts"].append(current_pkts)
        bursts[current_dir]["bytes"].append(current_bytes)
    return {
        d: {"pkts": np.array(b["pkts"], dtype=np.int64),
            "bytes": np.array(b["bytes"], dtype=np.int64)}
        for d, b in bursts.items()
    }


def _packet_length_histogram(sizes: np.ndarray) -> np.ndarray:
    """Barradas alternative feature set — 5-byte-bin packet-length histogram 0..1500B.

    Returns ``BARRADAS_HIST_N_BINS`` (300) floats, where bin *i* counts packets
    with size in ``[i * 5, (i + 1) * 5)``.  Packets ≥ 1500 B fall outside the
    range and are dropped by ``np.histogram``.
    """
    if len(sizes) == 0:
        return np.zeros(BARRADAS_HIST_N_BINS, dtype=np.float64)
    edges = np.arange(0, BARRADAS_HIST_MAX + BARRADAS_HIST_BIN_WIDTH, BARRADAS_HIST_BIN_WIDTH)
    hist, _ = np.histogram(sizes, bins=edges)
    return hist.astype(np.float64)


def _features_stats(
    timeline: list[tuple[float, int, bytes, str]],
    bursts: dict[str, dict[str, np.ndarray]],
) -> np.ndarray:
    """Build the 174-element Barradas stats feature vector for one full flow.

    The layout exactly matches :data:`STATS_FEATURE_NAMES`: 3 global fields,
    then total / c2s / s2c entropy + size + IAT blocks, then per-direction
    burst blocks (count + pkts + bytes).  Missing directions yield zeros
    inside the corresponding block.
    """
    ts_all = np.array([r[0] for r in timeline])
    sz_all = np.array([r[1] for r in timeline], dtype=np.int64)
    duration_s = float(ts_all.max() - ts_all.min()) if len(ts_all) > 1 else 0.0
    globals_block = [float(len(timeline)), float(sz_all.sum()), duration_s]

    blocks: list[float] = list(globals_block)
    for group in DIRECTION_GROUPS:
        recs = timeline if group == "total" else [r for r in timeline if r[3] == group]
        ts = np.array([r[0] for r in recs])
        sz = np.array([r[1] for r in recs], dtype=np.int64)
        payload = b"".join(r[2] for r in recs[:200])
        iats_ms = np.diff(np.sort(ts)) * 1000.0 if len(ts) > 1 else np.array([])
        blocks.extend([
            float(_size_entropy(sz)) if len(sz) else 0.0,
            float(_size_entropy(np.round(iats_ms).astype(np.int64))) if len(iats_ms) else 0.0,
            float(_entropy(payload)),
        ])
        blocks.extend(_moment_and_decile_block(sz))
        blocks.extend(_moment_and_decile_block(iats_ms))

    for direction in DIRECTIONS:
        blocks.append(float(len(bursts[direction]["pkts"])))
        blocks.extend(_moment_and_decile_block(bursts[direction]["pkts"]))
        blocks.extend(_moment_and_decile_block(bursts[direction]["bytes"]))

    return np.array(blocks, dtype=np.float64)


def _features_histogram(timeline: list[tuple[float, int, bytes, str]]) -> np.ndarray:
    sizes = np.array([r[1] for r in timeline], dtype=np.int64)
    return _packet_length_histogram(sizes)


def _features_from_flow(
    timeline: list[tuple[float, int, bytes, str]],
    bursts: dict[str, dict[str, np.ndarray]],
    feature_set: str,
) -> np.ndarray:
    if feature_set == "stats":
        return _features_stats(timeline, bursts)
    if feature_set == "histogram":
        return _features_histogram(timeline)
    if feature_set == "both":
        return np.concatenate([_features_stats(timeline, bursts), _features_histogram(timeline)])
    raise ValueError(f"Unknown feature_set: {feature_set!r}")


def _per_flow_features(
    pcap: Path,
    ip_map: dict[str, dict],
    feature_set: str = "stats",
) -> list[tuple[str, np.ndarray]]:
    """Emit one feature row per wire flow (Barradas USENIX'18 concatenated layout).

    A "wire flow" is the 5-tuple as it would be seen by a passive observer:
    one (client_ip, server_ip, server_port) per class.  Background classes
    typically expose a single server port and contribute one row per run.
    TYPHOON exposes up to three server ports (see `eval_server.rs::PORTS`)
    and the client may open any subset of them, so it contributes 1–3 rows
    per run — matching what an adversary would actually classify.

    Server-port discovery is automatic: whichever IP matches the protocol's
    ``server_ip`` from ``ip_map`` contributes its UDP port number as the
    flow's discriminator.
    """
    ip_to_cls_role: dict[str, tuple[str, str]] = {}
    for cls, slot in ip_map.items():
        ip_to_cls_role[slot["client_ip"]] = (cls, "client")
        ip_to_cls_role[slot["server_ip"]] = (cls, "server")

    timelines: dict[tuple[str, int], list[tuple[float, int, bytes, str]]] = defaultdict(list)
    with PcapReader(str(pcap)) as reader:
        for pkt in reader:
            if IP not in pkt or UDP not in pkt:
                continue
            ip_layer = pkt[IP]
            src_meta = ip_to_cls_role.get(ip_layer.src)
            dst_meta = ip_to_cls_role.get(ip_layer.dst)
            if src_meta is None or dst_meta is None or src_meta[0] != dst_meta[0]:
                continue
            cls = src_meta[0]
            udp_layer = pkt[UDP]
            if src_meta[1] == "client" and dst_meta[1] == "server":
                direction = "c2s"
                server_port = int(udp_layer.dport)
            elif src_meta[1] == "server" and dst_meta[1] == "client":
                direction = "s2c"
                server_port = int(udp_layer.sport)
            else:
                continue
            payload = bytes(udp_layer.payload)
            timelines[(cls, server_port)].append((float(pkt.time), len(payload), payload, direction))

    out: list[tuple[str, np.ndarray]] = []
    for (cls, _port), timeline in timelines.items():
        # Need ≥ 2 packets total across both directions for the flow to be usable;
        # individual directions may have 0–1 packets and the corresponding blocks
        # land at zero (Barradas-compatible behaviour).
        if len(timeline) < MIN_SAMPLES_FOR_STATS:
            continue
        bursts = _compute_bursts_per_direction([(t, s, d) for t, s, _, d in timeline])
        out.append((cls, _features_from_flow(timeline, bursts, feature_set)))
    return out


def _load_corpus(
    corpus_root: Path,
    feature_set: str = "stats",
) -> tuple[np.ndarray, list[str], list[str], list[Path]]:
    """Walk every run dir under *corpus_root* and assemble per-flow features + labels.

    Returns ``(X, class_labels, typhoon_profiles_or_na, skipped_runs)``.  One
    row per (run × class) flow — Barradas USENIX'18 layout — with the row's
    feature vector encoding the full conversation in *feature_set* format.
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
        meta = loads(meta_path.read_text())
        ip_map = meta.get("ip_map", {})
        typhoon_profile = meta.get("typhoon_profile", "unknown")
        for pcap in run_dir.glob("*.pcap"):
            for cls, vec in _per_flow_features(pcap, ip_map, feature_set):
                feats.append(vec)
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
    """Group blending stats by TYPHOON profile.  Returns ``{profile: stats}``."""
    out: dict[str, dict] = {}
    for prof in sorted(set(typhoon_profiles)):
        idx = typhoon_profiles == prof
        if not idx.any():
            continue
        prof_conf = confidence[idx]
        prof_preds = [pred_classes[i] for i in range(len(pred_classes)) if idx[i]]
        by_pred: dict[str, list[float]] = defaultdict(list)
        for cls, conf in zip(prof_preds, prof_conf, strict=True):
            by_pred[cls].append(conf)
        out[prof] = {
            "n_flows":            int(idx.sum()),
            "confident_fraction": float((prof_conf >= CONFIDENT_THRESHOLD).sum()) / len(prof_conf),
            "mean_confidence":    float(prof_conf.mean()),
            "predicted_distribution": {
                cls: {"count": len(confs), "mean_conf": float(np.mean(confs))}
                for cls, confs in by_pred.items()
            },
        }
    return out


@command(context_settings={"help_option_names": ["-h", "--help"]})
@option("--corpus-root", default=None, type=ClickPath(),
              help="Corpus root directory (default: results/background).")
@option("--features", "feature_set", default="stats",
              type=Choice(list(FEATURE_SETS)), show_default=True,
              help="Barradas USENIX'18 feature set: stats (174 features), histogram (300 features), or both.")
@option("--out-dir", default=None, type=ClickPath(),
              help="Directory for the blending.json result summary (default: <corpus-root>/plots).")
def main(corpus_root: str | None, feature_set: str, out_dir: str | None) -> None:
    """Compute confident-blend fraction + per-profile breakdown from a finished corpus."""

    root = Path(corpus_root) if corpus_root else Path(__file__).parent.parent.parent.parent / "results" / "background"
    if not root.is_dir():
        console.print(f"[red]Corpus root not found:[/red] {root}")
        exit(1)

    feature_names = get_feature_names(feature_set)
    console.print(f"[dim]Feature set: [bold]{feature_set}[/bold] ({len(feature_names)} features per flow, Barradas USENIX'18 layout)[/dim]")

    X, y, profiles, skipped = _load_corpus(root, feature_set)
    if X.size == 0:
        console.print("[yellow]No flows extracted from corpus.[/yellow]")
        exit(1)

    bg_mask = np.array([lbl != TYPHOON_CLASS for lbl in y])
    typhoon_mask = ~bg_mask
    if bg_mask.sum() == 0 or typhoon_mask.sum() == 0:
        console.print("[red]Corpus must contain both TYPHOON and background flows.[/red]")
        exit(1)

    bg_classes = sorted({lbl for lbl, m in zip(y, bg_mask, strict=True) if m})
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

    # Barradas USENIX'18 RF defaults: n_estimators=100, default split criterion.
    clf = RandomForestClassifier(n_estimators=100, random_state=42)
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

    console.print(
        f"[bold]Background-blending result[/bold]  "
        f"({len(confidence)} TYPHOON flows, "
        f"{bg_mask.sum()} background flows: {len(train_idx)} train + {len(holdout_idx)} hold-out)"
    )
    console.print(f"  Confident-blend fraction (conf ≥ {CONFIDENT_THRESHOLD:.2f}): [bold]{blend_fraction:.1%}[/bold]")
    console.print(f"  TYPHOON   mean confidence: [bold]{confidence.mean():.3f}[/bold]  median {float(np.median(confidence)):.3f}  (max {confidence.max():.3f})")
    console.print(f"  Held-out background:       mean {bg_holdout_conf.mean():.3f}  median {float(np.median(bg_holdout_conf)):.3f}  (max {bg_holdout_conf.max():.3f})")
    console.print(f"  [dim]Uniform-over-{len(bg_classes)}-classes baseline = {1.0 / len(bg_classes):.3f}; TYPHOON should approach the held-out figure to blend perfectly.[/dim]")

    # Confidence-threshold detector: an adversary without labelled TYPHOON data
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

    # Predicted-class distribution.
    console.print("\n[bold]Predicted class distribution for TYPHOON flows:[/bold]")
    table = Table(show_header=True)
    table.add_column("Predicted class", style="cyan")
    table.add_column("Count", justify="right")
    table.add_column("Share", justify="right")
    table.add_column("Mean conf", justify="right")
    by_pred: dict[str, list[float]] = defaultdict(list)
    for cls, conf in zip(pred_classes, confidence, strict=True):
        by_pred[cls].append(conf)
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

    # Persist the metrics so the pipeline can pick them up as an artifact —
    # mirrors what background-openworld / -distplot write to --out-dir.
    out_root = Path(out_dir) if out_dir else root / "plots"
    out_root.mkdir(parents=True, exist_ok=True)
    result = {
        "feature_set":              feature_set,
        "n_features":               len(feature_names),
        "confident_threshold":      CONFIDENT_THRESHOLD,
        "n_typhoon_flows":          len(confidence),
        "n_background_flows":       int(bg_mask.sum()),
        "n_background_train":       len(train_idx),
        "n_background_holdout":     len(holdout_idx),
        "n_background_classes":     len(bg_classes),
        "blend_fraction":           blend_fraction,
        "typhoon_mean_confidence":  float(confidence.mean()),
        "typhoon_median_confidence": float(np.median(confidence)),
        "typhoon_max_confidence":   float(confidence.max()),
        "bg_holdout_mean_confidence":   float(bg_holdout_conf.mean()),
        "bg_holdout_median_confidence": float(np.median(bg_holdout_conf)),
        "uniform_baseline":         1.0 / len(bg_classes),
        "detector_threshold_bg_p1": bg_p1,
        "typhoon_caught_fraction":  typhoon_caught,
        "bg_false_positive_fraction": bg_caught,
        "skipped_runs":             len(skipped),
        "predicted_distribution": {
            cls: {
                "count":     len(confs),
                "share":     len(confs) / len(pred_classes),
                "mean_conf": float(np.mean(confs)),
            }
            for cls, confs in by_pred.items()
        },
        "per_profile": breakdown,
    }
    result_path = out_root / "blending.json"
    result_path.write_text(dumps(result, indent=2))
    console.print(f"\n  [green]wrote[/green] {result_path}")


if __name__ == "__main__":
    main()
