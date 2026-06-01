# TYPHOON Evaluation

A Docker-based harness that captures TYPHOON traffic alongside other protocols and common UDP traffic classes, and answers the central question: **can a passive observer distinguish TYPHOON's wire-level characteristics — packet sizes, inter-arrival times, byte entropy, handshake structure — from the rest of the mix?**

For the protocol itself, see [PROTOCOL.md](../PROTOCOL.md).
For the empirical references behind the UDP traffic mix used in Part 3 (citations, share tables), see [docs/TRAFFIC_CAPTURE_REFERENCE.md](docs/TRAFFIC_CAPTURE_REFERENCE.md).

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
│   ├── background/        # Part 3
│   └── ml/                # ML utilities (re-used by Part 3)
├── docs/                  # methodology references
└── results/               # generated pcaps, plots, ML artefacts (gitignored)
```

## Experiments

Three independent parts; each answers one question.

### Part 1 — Self-comparison

*Is TYPHOON's traffic profile stable and reproducible?* Runs TYPHOON N times under identical or varying conditions and overlays size + IAT distributions. Tight envelopes under identical config = stable; clearly separated envelopes across scenarios = TYPHOON adapts to workload.

### Part 2 — Operational comparison

*Where does TYPHOON sit on throughput / overhead / handshake-cost relative to 15 other UDP/TCP secure-transport protocols?* Captures each protocol once under the same Docker network and emits direct operational metrics. **No classifiers** — a closed-world classifier across these 16 protocols would score near 100 % because each protocol has a distinct wire footprint by design, which says nothing about Part 3's question.

Protocols compared: `raw_udp`, `raw_tcp`, `tls`, `wireguard`, `quic`, `obfs4` (×3 IAT modes), `amneziawg`, `hysteria2`, `shadowsocks`, `tor`, `vless_reality`, `openvpn`, `wireguard_daita`, `typhoon`.

### Part 3 — Background-blending

*Can a passive observer pick TYPHOON out of a realistic UDP traffic mix?* Runs TYPHOON alongside a randomised subset of 8 generators producing common UDP traffic classes (QUIC d/l + u/l, DNS, RTP voice/video, gaming, WireGuard idle, control plane) plus one open-set `unknown` class held out from training. Five ML setups, each modelling a different threat model:

| Test | Threat model | TYPHOON wins when… |
| --- | --- | --- |
| **A** Pair-binary | Observer suspects TYPHOON-as-X and trains a binary classifier on real X vs TYPHOON-as-X | AUC near 0.5 |
| **B** Closed-world | Observer has labels for every class incl. TYPHOON | TYPHOON recall low (often confused with a real class) |
| **C** Open-world threshold | Observer has labels for background only and flags low-confidence flows | TPR @ 1 % FPR low |
| **D** Open-set binary | Observer has labels for TYPHOON + a *subset* of background classes; unseen classes + `unknown` held out at test time | high FPR on unseen background and `unknown` |
| **E** One-class TYPHOON | Observer has only TYPHOON labels (e.g. from a leaked client) | high FPR on `unknown` |

## Requirements

- **Docker** (or rootful Podman — rootless cannot grant `NET_ADMIN` to the observer).
- **Python 3.11+** with [Poetry](https://python-poetry.org/).
- Optional ML extras: `torch` (CNN models), `xgboost`, `umap-learn` — installed via the `ml` Poetry group.

## Installation

```shell
cd evaluation
poetry install --with ml      # Python deps
poetry poe build              # build the 15 comparison-protocol images (once)
poetry poe background-build   # build the 9 background generator images (once, only for Part 3)
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
poe background-blending       # confident-blend fraction (primary metric)
poe background-openworld      # Tests A–E open-world scores
poe background-distplot       # per-pair size/IAT distribution overlays
```

### Pipeline

```shell
poe evaluate                  # capture → analyze → Part 1 + 2 plots → ML → report.md
poe clean                     # delete results/captures and results/logs
```

## Reading the results

Outputs land under `results/`:

```text
results/
├── captures/run_<timestamp>/
│   ├── <protocol>.pcap            # raw capture (handshake + data)
│   ├── stats.json                 # per-pcap metrics — see below
│   ├── metadata.json              # transfer_bytes, scenario, timing
│   └── logs/<protocol>/           # client + server + observer container logs
├── self_compare/, traffic_compare/, use_case_compare/  # Part 1 PNGs
├── plots/                         # Part 2 PNGs + comparison table
├── flow_plots/                    # Part 1 per-flow packet-structure SVGs
├── background/run_*/              # Part 3 per-run pcaps and metadata
└── ml/                            # feature matrices, model weights
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

### Part 1 plots

- `self_compare/default_self_compare.png` — overlaid size + IAT CDFs across N runs of identical config. Look for tight bands.
- `traffic_compare/default_traffic_compare.png` — same CDFs per scenario. Look for clearly separated bands.
- `use_case_compare/use_case_compare.png` — per-PROTOCOL.md-use-case profiles side by side.
- `flow_plots/<example>.png` — stacked-bar of every wire packet showing fake-header / tailor / body composition. Useful to verify per-flow knobs.

### Part 2 plots

- `<run>_proto_compare.png` — six panels: (A) size CDF, (B) IAT CDF, (C) throughput vs goodput-efficiency scatter, (D) overhead bars, (E) byte entropy by phase, (F) normalised heatmap.
- `<run>_handshake.png` — handshake duration / packet count / byte fraction across protocols.
- `<run>_compare_table.md` — one row per protocol; quick-glance ranking by any column.

### Part 3 outputs

- `background-blending` prints the **confident-blend fraction** — the share of TYPHOON flows the open-world classifier labels as a concrete background class with high confidence. Higher = less distinguishable.
- `background-openworld` reports per-test scores (Tests A–E above). Each test answers a distinct ML setup; treat them as complementary not redundant.
- `background-distplot` overlays the actual TYPHOON size/IAT distributions on each background class — visual check of where TYPHOON differs.

## Settings overrides

Every TYPHOON protocol constant (handshake length, decoy rates, fake header bounds, …) can be overridden via environment variables on the TYPHOON containers — these are passed straight through to the Rust crate's `SettingsBuilder`. Useful to A/B-test parameter changes against the same corpus.
