# TYPHOON Evaluation

A Docker-based harness that captures TYPHOON traffic alongside other protocols and common UDP traffic classes, and answers the central question: **can a passive observer distinguish TYPHOON's wire-level characteristics — packet sizes, inter-arrival times, byte entropy, handshake structure — from the rest of the mix?**

For the protocol itself, see [PROTOCOL.md](../PROTOCOL.md).

## Contents

```text
evaluation/
├── protocols/             # Dockerfiles for the 15 comparison protocols
├── background/            # Dockerfiles for the 8 UDP-traffic generators + open-set unknown
├── compose/, observer/    # docker-compose stacks and the tcpdump observer container
├── chaos/                 # tc/netem sidecar for latency / jitter / loss
├── src/typhoon_eval/      # Python orchestrator, parsers, plots, ML
│   ├── shared/            # capture, parse pcaps, common stats
│   ├── self/              # Part 1
│   ├── protocols_op/      # Part 2
│   └── background/        # Part 3 corpus + ML (features, ml_blending = Test C, detectability/ = Tests A/B/D/E/F)
└── results/               # generated pcaps, plots, ML artefacts (gitignored)
```

## Experiments

Four independent parts; each answers one question.

### Part 1 — Self-comparison

*Is TYPHOON's traffic profile stable and reproducible?* Runs TYPHOON N times under identical or varying conditions and overlays size + IAT distributions. Tight envelopes under identical config = stable; clearly separated envelopes across scenarios = TYPHOON adapts to workload.

### Part 2 — Operational comparison

*Where does TYPHOON sit on throughput / overhead / handshake-cost relative to 15 other UDP/TCP secure-transport protocols?* Captures each protocol once under the same Docker network and emits direct operational metrics. **No classifiers** — a closed-world classifier across these 16 protocols would score near 100 % because each protocol has a distinct wire footprint by design, which says nothing about Part 3's question.

Protocols compared: `raw_udp`, `raw_tcp`, `tls`, `wireguard`, `quic`, `obfs4` (×3 IAT modes), `amneziawg`, `hysteria2`, `shadowsocks`, `tor`, `vless_reality`, `openvpn`, `wireguard_daita`, `typhoon`.

### Part 3 — Background-blending

*Can a passive observer pick TYPHOON out of a realistic UDP traffic mix?* Runs TYPHOON alongside a randomised subset of 8 generators producing common UDP traffic classes (QUIC d/l + u/l, DNS, RTP voice/video, gaming, WireGuard idle, control plane) plus one open-set `unknown` class held out from training. Six ML setups, each modelling a different threat model. Test C is the primary blending metric and lives in [`ml_blending.py`](src/typhoon_eval/background/ml_blending.py); Tests A, B, D, E and F live in the [`detectability/`](src/typhoon_eval/background/detectability/) package (`pair_binary.py` = A, `closed_world.py` = B, `open_set.py` = D/E/F). Both share the feature pipeline in [`features.py`](src/typhoon_eval/background/features.py):

| Test | Threat model | TYPHOON wins when… |
| --- | --- | --- |
| **A** Pair-binary | Observer suspects TYPHOON-as-X and trains a binary classifier on real X vs TYPHOON-as-X | AUC near 0.5 |
| **B** Closed-world | Observer has labels for every class incl. TYPHOON | TYPHOON recall low (often confused with a real class) |
| **C** Open-world threshold | Observer has labels for background only and flags low-confidence flows | TPR @ 1 % FPR low |
| **D** Open-set binary | Observer has labels for TYPHOON + a *subset* of background classes; unseen classes + `unknown` held out at test time | high FPR on unseen background and `unknown` |
| **E** One-class TYPHOON | Observer has only TYPHOON labels (e.g. from a leaked client) trained into a one-class SVM, evaluated against pooled background | high FPR on `unknown` |
| **F** One-class + partial catalogue | Same one-class TYPHOON SVM as E, but the FPR breakdown reuses D's 3-of-7 background hold-out — models a leaked-client observer who also has a *partial* protocol catalogue used post-hoc as a filter; bridges D and E | high FPR on unseen background and `unknown` |

### Part 4 — Rust-level benchmarking

*How fast is the TYPHOON implementation itself?* `cargo bench` roundtrip/handshake timings plus `perf`-based flamegraphs (kept as interactive `.svg` and a static `.pdf` for embedding) for every example binary. Linux only (needs `perf` + `cargo-flamegraph` on the host) — mirrors `.github/workflows/benchmarks.yaml` and auto-skips on non-Linux hosts.

## Requirements

- **Docker** (or rootful Podman — rootless cannot grant `NET_ADMIN` to the observer).
- **Python 3.11+** with [Poetry](https://python-poetry.org/). `poetry install` pulls in everything needed for Parts 1–3, including scikit-learn and XGBoost.
- Optional, Linux only: `perf` + [`cargo-flamegraph`](https://github.com/flamegraph-rs/flamegraph) — enables Part 4 (`benchmark`). Without them, `poe benchmark` / the pipeline's `benchmark` phase is skipped.
  Flamegraphs additionally need perf sampling access: set `kernel.perf_event_paranoid` low enough (see [Part 4](#part-4--rust-level-benchmarking-cli)) — otherwise `cargo flamegraph` fails and the flamegraph step is skipped (the `cargo bench` numbers are still produced).
  `rsvg-convert` (`librsvg2-bin`) is also recommended to additionally render flamegraphs as `.pdf`; without it, only the interactive `.svg` is produced.

## Installation

```shell
cd evaluation
poetry install                # Python deps (incl. scikit-learn, XGBoost)
poetry poe build               # build the 15 comparison-protocol images (once)
poetry poe background-build    # build the 9 background generator images (once, only for Part 3)
```

## Running the experiments

All commands run from `evaluation/` and accept `--help` for the full flag list. The most common invocations:

### Part 1 — Self-comparison (CLI)

```shell
poe self-compare              # repeat TYPHOON N times under identical config
poe traffic-compare           # 4 payload × wait scenarios
poe use-case-compare          # one capture per PROTOCOL.md use case
poe plot --example heavy_traffic --out-dir out/   # per-flow packet-structure SVG
```

### Part 2 — Operational comparison (CLI)

```shell
poe capture --all             # capture all 16 protocols (default: bulk, 10 MB)
poe capture --all --chaos     # …with latency + jitter + loss
poe analyze                   # parse pcaps → stats.json
poe proto-compare             # plots + comparison table for the latest run
```

Useful flags: `--protocol <name>` (single protocol), `--scenario {bulk,interactive,streaming,burst,echo,idle}`, `--run YYYYMMDD_HHMMSS` (target an earlier run).

### Part 3 — Background-blending (CLI)

```shell
poe background-corpus         # randomised corpus (default 70 runs)
poe background-blending       # Test C — confident-blend fraction (primary metric)
poe background-detectability  # Tests A, B, D, E, F held-out detectability scores
poe background-distplot       # per-pair size/IAT distribution overlays
```

### Part 4 — Rust-level benchmarking (CLI)

```shell
poe benchmark                 # cargo bench (roundtrip, handshake) + example flamegraphs
```

Linux only — requires `perf` and `cargo-flamegraph` already installed on the host (see `.github/workflows/benchmarks.yaml` for the one-time setup commands); this task does not install them for you. Each flamegraph is kept as the interactive `.svg` (search/zoom) plus a `.pdf` rendered via `rsvg-convert` (`librsvg2-bin`) for embedding in reports; without `rsvg-convert`, only the `.svg` is produced.

**perf sampling access.** `cargo flamegraph` runs `perf record`, which needs `kernel.perf_event_paranoid` low enough to sample CPU events.
To enable it:

```shell
echo -1 | sudo tee /proc/sys/kernel/perf_event_paranoid      # this session
echo 'kernel.perf_event_paranoid = -1' | sudo tee /etc/sysctl.d/99-perf.conf  # persist across reboots
```

Alternatively, run the benchmark under `sudo` (perf as root ignores the paranoid setting), though that also builds/runs cargo as root.

### Pipeline

```shell
poe evaluate                    # build → capture → analyze → Part 1 + 2 plots → background → benchmark → report.md
poe evaluate --skip background  # everything except the 7500-run Part 3 corpus
poe evaluate --skip build       # reuse existing Docker images
poe evaluate --skip benchmark   # skip cargo bench + flamegraphs (auto-skipped on non-Linux anyway)

# Re-analyze already-stored PCAPs without regenerating the corpus — e.g. after
# changing feature sets or classifier options:
poe evaluate --skip build,capture --corpus-root results/background/pipeline_<id>

poe clean                       # delete results/captures and results/background
```

## Reading the results

Outputs are split into two trees:

- **`results/`** — raw PCAPs (captures and background corpora). Too large to ship; regenerable via `poe evaluate`.
- **`artifacts/<pipeline_id>/`** — every derived output (plots, tables, stats.json, top-level `report.md`). Designed to be zipped and uploaded as a conference artifact bundle.

```text
results/
├── captures/run_<timestamp>/
│   ├── <protocol>.pcap            # raw capture (handshake + data)
│   ├── stats.json                 # per-pcap metrics — see below
│   ├── metadata.json              # transfer_bytes, scenario, timing
│   └── logs/<protocol>/           # client + server + observer container logs
└── background/pipeline_<id>/run_*/  # Part 3 per-run pcaps + metadata

artifacts/pipeline_<timestamp>/
├── pipeline_config.json           # resolved CLI parameters
├── report.md                      # top-level index with links to everything below
├── logs/<phase>.log               # per-phase invocation logs
├── analyze/run_*/stats.json       # copies of per-run stats
├── proto_compare/                 # Part 2 PDFs + markdown comparison table
├── flow_plots/                    # Part 1 per-flow packet-structure PDFs
├── self_compare/, use_case_compare/, traffic_compare/  # Part 1 PDFs + JSON
└── background/                    # Part 3 derived outputs (no PCAPs)
    ├── corpus_metadata/run_*/{metadata,config}.json
    ├── blending/blending.json     # confident-blend fraction + per-profile breakdown
    ├── detectability/             # Tests A, B, D, E, F PDFs + JSON
    └── distplot/                  # per-pair size/IAT overlays PDFs + JSON
```

### Per-pcap metrics (`stats.json`)

Computed separately per direction (`c2s`, `s2c`, `all`). Packet sizes are **transport-payload bytes** (UDP payload or TCP segment data) — IP/UDP/TCP header bytes are excluded so transport overhead doesn't leak into protocol stats.

| Metric | Meaning |
| --- | --- |
| `packet_count`, `byte_count`, `transmission_time_s` | Volume and duration |
| `packet_size.{mean,std,min,max,p5…p99,entropy}` | Size distribution |
| `iat_ms.{mean,std,p5…p99,entropy}` | Inter-arrival-time distribution |
| `entropy.{all,handshake,data}` | Shannon entropy of payload bytes (8.0 ≈ random) |
| `burstiness` | `std(IAT) / mean(IAT)` — temporal clustering |
| `size_regularity` | `n_distinct_sizes / n_packets` |
| `overhead_ratio`, `goodput_efficiency` | Wire bytes vs. user data |
| `direction_asymmetry` | `c2s_bytes / s2c_bytes` |
| `first_n_sizes[100]`, `first_n_iats[100]` | First-100 direction-signed sequences (for ML) |
| `hs_duration_s`, `hs_pkt_count`, `hs_byte_frac` | Handshake window (when sniffer configured) |

### Part 1 plots (under `artifacts/<pipeline_id>/`)

- `self_compare/default_self_compare.pdf` — overlaid size + IAT CDFs across N runs of identical config. Look for tight bands.
- `traffic_compare/default_traffic_compare.pdf` — same CDFs per scenario. Look for clearly separated bands.
- `use_case_compare/use_case_compare.pdf` — per-PROTOCOL.md-use-case profiles side by side.
- `flow_plots/run_<id>_pcap_flow.pdf` — stacked-bar of every wire packet showing fake-header / trailer / body composition. Useful to verify per-flow knobs.

### Part 2 plots (under `artifacts/<pipeline_id>/proto_compare/`)

- `run_<id>_proto_compare.pdf` — six panels: (A) size CDF, (B) IAT CDF, (C) throughput vs goodput-efficiency scatter, (D) overhead bars, (E) byte entropy by phase, (F) normalised heatmap.
- `run_<id>_handshake.pdf` — handshake duration / packet count / byte fraction across protocols.
- `run_<id>_compare_table.md` — one row per protocol; quick-glance ranking by any column.

### Part 3 outputs

- `background-blending` prints the **confident-blend fraction** (Test C) — the share of TYPHOON flows the open-world classifier labels as a concrete background class with high confidence. Higher = less distinguishable.
- `background-detectability` reports per-test scores (Tests A, B, D, E, F above). Each test answers a distinct ML setup; treat them as complementary not redundant.
- `background-distplot` overlays the actual TYPHOON size/IAT distributions on each background class — visual check of where TYPHOON differs.

## Settings overrides

Every TYPHOON protocol constant (handshake length, decoy rates, fake header bounds, …) can be overridden via environment variables on the TYPHOON containers — these are passed straight through to the Rust crate's `SettingsBuilder`. Useful to A/B-test parameter changes against the same corpus.
