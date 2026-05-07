"""
Statistical analysis of TYPHOON capture log records.

Records come from the typhoon::capture logger (JSONL on stderr).
Packet records have: t (unix ms), dir, flow, kind, tailor, crypto, header, payload, body.
Config records have kind="Config": dir, flow, body_mode, header_len, decoy.
"""

import numpy as np

COMPONENTS = ["tailor", "crypto", "header", "payload", "body"]

COMP_COLORS = {
    "tailor":  "#555555",
    "crypto":  "#9b59b6",
    "header":  "#e67e22",
    "payload": "#2980b9",
    "body":    "#95a5a6",
}

USE_CASE_COLORS = {
    "throughput":  "#2ecc71",
    "interactive": "#3498db",
    "transparent": "#e67e22",
    "security":    "#e74c3c",
    "default":     "#9b59b6",
}


def _packet_size(r: dict) -> int:
    return sum(r.get(c, 0) for c in COMPONENTS)


def _size_entropy(vals: np.ndarray) -> float:
    if len(vals) == 0:
        return 0.0
    _, counts = np.unique(vals.astype(int), return_counts=True)
    probs = counts / counts.sum()
    probs = probs[probs > 0]
    return float(-np.sum(probs * np.log2(probs)))


def _iat_entropy(vals: np.ndarray) -> float:
    if len(vals) < 2:
        return 0.0
    n_bins = min(50, max(5, len(vals) // 5))
    counts, _ = np.histogram(vals, bins=n_bins)
    counts = counts[counts > 0]
    probs = counts / counts.sum()
    return float(-np.sum(probs * np.log2(probs)))


def _dist_stats(vals: np.ndarray, entropy_fn) -> dict:
    if len(vals) == 0:
        return {"mean": 0.0, "std": 0.0, "p5": 0.0, "p50": 0.0, "p95": 0.0, "entropy": 0.0, "raw": []}
    return {
        "mean": float(np.mean(vals)),
        "std": float(np.std(vals)),
        "p5": float(np.percentile(vals, 5)),
        "p50": float(np.percentile(vals, 50)),
        "p95": float(np.percentile(vals, 95)),
        "entropy": entropy_fn(vals),
        "raw": vals.tolist(),
    }


def _burstiness_regularity(iats: np.ndarray, sizes: np.ndarray) -> tuple[float, float]:
    iat_mean = float(np.mean(iats)) if len(iats) > 1 else 0.0
    burstiness = float(np.std(iats) / iat_mean) if iat_mean > 0 else 0.0
    size_regularity = float(len(np.unique(sizes.astype(int))) / len(sizes)) if len(sizes) > 0 else 0.0
    return burstiness, size_regularity


def _compute_dir_stats(records: list[dict]) -> dict:
    if not records:
        return {
            "packet_count": 0,
            "total_bytes": 0,
            "packet_size": _dist_stats(np.array([]), _size_entropy),
            "iat_ms": _dist_stats(np.array([]), _iat_entropy),
            "components": {c: 0.0 for c in COMPONENTS},
            "overhead_ratio": 0.0,
        }

    records = sorted(records, key=lambda r: r["t"])
    sizes = np.array([_packet_size(r) for r in records], dtype=float)

    # Compute IAT within each direction group to avoid artificial near-zero spikes
    # that appear when c2s and s2c timestamps are interleaved (request+echo pairs).
    dir_groups: dict[str, list[float]] = {}
    for r in records:
        dir_groups.setdefault(r.get("dir", ""), []).append(float(r["t"]))
    all_iats: list[float] = []
    for times in dir_groups.values():
        times_arr = np.array(sorted(times), dtype=float)
        if len(times_arr) > 1:
            all_iats.extend(np.diff(times_arr).tolist())
    iats = np.array(all_iats, dtype=float)

    components = {c: float(np.mean([r.get(c, 0) for r in records])) for c in COMPONENTS}
    total = float(np.sum(sizes))
    payload_total = float(np.sum([r.get("payload", 0) for r in records]))
    overhead_ratio = 1.0 - payload_total / total if total > 0 else 0.0

    burstiness, size_regularity = _burstiness_regularity(iats, sizes)

    return {
        "packet_count": len(records),
        "total_bytes": int(total),
        "packet_size": _dist_stats(sizes, _size_entropy),
        "iat_ms": _dist_stats(iats, _iat_entropy),
        "components": components,
        "overhead_ratio": overhead_ratio,
        "burstiness": burstiness,
        "size_regularity": size_regularity,
    }


def stats_from_records(packet_records: list[dict], config_records: list[dict]) -> dict:
    """Compute per-direction and combined traffic statistics from TYPHOON capture records."""
    c2s = [r for r in packet_records if r.get("dir") == "c2s"]
    s2c = [r for r in packet_records if r.get("dir") == "s2c"]
    return {
        "c2s": _compute_dir_stats(c2s),
        "s2c": _compute_dir_stats(s2c),
        "all": _compute_dir_stats(packet_records),
        "config": [
            {
                "dir": r.get("dir"),
                "body_mode": r.get("body_mode"),
                "header_len": r.get("header_len"),
                "decoy": r.get("decoy"),
            }
            for r in config_records
        ],
    }


def pool_stats(run_stats_list: list[dict], direction: str = "all") -> dict:
    """Pool raw arrays from multiple runs and recompute stats from the combined data."""
    all_sizes: list[float] = []
    all_iats: list[float] = []
    all_components: dict[str, list[float]] = {c: [] for c in COMPONENTS}
    total_bytes = 0

    for run in run_stats_list:
        ds = run.get(direction, {})
        all_sizes.extend(ds.get("packet_size", {}).get("raw", []))
        all_iats.extend(ds.get("iat_ms", {}).get("raw", []))
        total_bytes += ds.get("total_bytes", 0)
        comps = ds.get("components", {})
        for c in COMPONENTS:
            all_components[c].append(comps.get(c, 0.0))

    sizes = np.array(all_sizes, dtype=float)
    iats = np.array(all_iats, dtype=float)
    overhead_ratio = 1.0 - (sum(r.get(direction, {}).get("components", {}).get("payload", 0.0) * r.get(direction, {}).get("packet_count", 0) for r in run_stats_list) / max(total_bytes, 1))

    burstiness, size_regularity = _burstiness_regularity(iats, sizes)

    return {
        "packet_count": len(all_sizes),
        "total_bytes": total_bytes,
        "packet_size": _dist_stats(sizes, _size_entropy),
        "iat_ms": _dist_stats(iats, _iat_entropy),
        "components": {c: float(np.mean(all_components[c])) if all_components[c] else 0.0 for c in COMPONENTS},
        "overhead_ratio": overhead_ratio,
        "burstiness": burstiness,
        "size_regularity": size_regularity,
        "config": run_stats_list[0].get("config", []) if run_stats_list else [],
    }
