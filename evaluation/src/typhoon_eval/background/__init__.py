"""Part 3 — background-blending evaluation.

Modules:
    * `corpus`         — orchestrate randomised mixed-UDP captures.
    * `features`       — shared Barradas feature extraction + corpus loading.
    * `ml_blending`    — Test C: primary blending metric (confident-blend fraction).
    * `detectability`  — Tests A/B/D/E/F: held-out pair-binary, closed-world, and open-set metrics.
    * `dist_stats`     — corpus walk + macro aggregation/statistics for dist_plot.
    * `dist_plot`      — per-pair size/IAT distribution overlays (drawing + CLI).
"""
