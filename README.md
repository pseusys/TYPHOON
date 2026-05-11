# TYPHOON

> Transfer Your Packets Hidden Over Observed Networks

There are lots of data transferring protocols out there.
Developers have made significant progress in protecting user data with various cryptographic algorithms, making encryption difficult to break.
Still, it's possible to try, and some progress is also being made, e.g., in breaking asymmetric ciphers.

This project tries to make another step in encryption: making a protocol so obfuscated that it's hard to identify and verify it in the first place.
Indeed, if an attacker doesn't know _what_ protocol they're looking at, it makes breaking it significantly harder.

For the full protocol specification, architecture, cryptographic details, and proposed implementation, see [PROTOCOL.md](PROTOCOL.md).

For how TYPHOON compares against 15 other protocols, what traffic data is collected and how, and how ML classifiers attempt to fingerprint it, see [evaluation/EVALUATION.md](evaluation/EVALUATION.md).

## Code and tests

The repository contains [example TYPHOON protocol implementation](./typhoon/) in `rust`.
It is designed to be fast, modern and efficient.

The crate defines the following features:

- `fast_software`: use `fast` [asymmetric cryptographic mode](PROTOCOL.md#cryptography) with `software` [symmetric cryptographic mode](PROTOCOL.md#cryptography).
- `fast_hardware`: use `fast` [asymmetric cryptographic mode](PROTOCOL.md#cryptography) with `hardware` [symmetric cryptographic mode](PROTOCOL.md#cryptography).
- `full_software`: use `full` [asymmetric cryptographic mode](PROTOCOL.md#cryptography) with `software` [symmetric cryptographic mode](PROTOCOL.md#cryptography).
- `full_hardware`: use `full` [asymmetric cryptographic mode](PROTOCOL.md#cryptography) with `hardware` [symmetric cryptographic mode](PROTOCOL.md#cryptography).
- `server`: include TYPHOON server implementation.
- `client`: include TYPHOON client implementation.
- `debug`: include [debug diagnostic tools](PROTOCOL.md#debug-mode) (`DebugMode`, `DebugResult`, `run_debug`, `DebugServerConnectionHandler`); requires `client` and `server`.
- `capture`: emit per-packet JSONL records to the `typhoon::capture` log target at `TRACE` level; enable at runtime with `RUST_LOG=typhoon::capture=trace`.
- `tokio`: use [tokio](https://tokio.rs/) async runtime.
- `async-std`: use [async-std](https://async.rs/) async runtime.

The default features are: `fast_software`, `server`, `client`, `tokio`.

## Development

All commands should be run from inside the `./typhoon` directory.

### Feature sets

The default feature configuration used for development and testing: `fast_software`, `server`, `client`, `tokio`.

Optional features:

- `debug` — enables `DebugMode`, `run_debug`, and `DebugServerConnectionHandler` (requires `client` + `server`).
- `clap` — enables the `typhoon-gen-key` CLI binary argument parser.

### Build

```shell
# Default features (fast_software + tokio)
cargo build

# Full hardware + async-std
cargo build --no-default-features --features "full_hardware,server,client,async-std"

# With debug tooling
cargo build --features debug

# Release build
cargo build --release
```

### Test

```shell
# Default features
cargo test -- --nocapture

# Full hardware + async-std (network tests require tokio; use tokio even with async-std runtime here)
cargo test --no-default-features --features "full_hardware,server,client,tokio" -- --nocapture
```

### Format and lint

```shell
# Format
cargo fmt

# Check formatting without modifying files
cargo fmt --check

# Lint
cargo clippy
cargo clippy --no-default-features --features "full_hardware,server,client,async-std"
```

### Benchmarks

Criterion benchmarks measure pipelined echo throughput: 20 concurrent 1400 B messages round-tripped
under realistic traffic obfuscation (`FlowConfig::random`), matching the `heavy_traffic` example.

```shell
# Run all benchmarks (default features)
cargo bench --bench roundtrip

# Re-use a pre-generated key pair to skip expensive McEliece keygen on each run
TYPHOON_TEST_SERVER_KEY_FAST=server.key cargo bench --bench roundtrip
```

CI runs benchmarks on every push to `main` and on pull requests that touch `typhoon/**`.
Results are stored as a workflow artifact (`bench-results`) on each run.
The CI also generates per-example flamegraph SVGs and per-flow packet structure diagrams
(stored as `flamegraphs` and `flow-diagrams` artifacts respectively, retained for 5 days).

### Flow capture

The `capture` feature emits per-packet JSONL records (component sizes, direction, flow address)
to the `typhoon::capture` log target at `TRACE` level.  The `evaluation/` tool can turn these
into stacked-bar SVG diagrams:

```shell
# Run an example, capture traffic, generate diagrams
cd evaluation
poe plot --example heavy_traffic --out-dir out/

# Or generate from an existing log file
RUST_LOG=typhoon::capture=trace cargo run --features capture --example hello_world 2>trace.log
poe plot --log trace.log --out-dir out/
```

### Coverage

```shell
# Requires cargo-llvm-cov: cargo install cargo-llvm-cov
cargo llvm-cov --features "fast_software,server,client,tokio,debug"
cargo llvm-cov --no-default-features --features "full_hardware,server,client,tokio,debug"
```

### Examples

All examples start an in-process server and client and require no external setup.

```shell
# Basic request–response round trip
cargo run --example hello_world

# Multiple server flow managers
cargo run --example multi_flow

# Multiple simultaneous clients
cargo run --example multi_client

# Long-running session with repeated health-check cycles
cargo run --example long_session

# Sustained high-throughput traffic across multiple flows (~5 min)
cargo run --example heavy_traffic

# Debug probe (reachability, RTT, throughput) — requires the debug feature
cargo run --example debug_probe --features debug
```

### Binaries

#### `typhoon-gen-key`

Generates a server key pair and optionally a client certificate. Requires the `server` and `clap` features.

```shell
cargo build --bin typhoon-gen-key --features "server,clap"

# Generate server key pair only
./target/debug/typhoon-gen-key server.key

# Generate server key pair and a client certificate with one embedded address
./target/debug/typhoon-gen-key server.key --cert client.cert --addr 127.0.0.1:19999

# Multiple addresses
./target/debug/typhoon-gen-key server.key --cert client.cert --addr 203.0.113.1:19999 --addr 203.0.113.2:19999

# Override a protocol constant
./target/debug/typhoon-gen-key server.key --set TYPHOON_MAX_RETRIES=5
```

#### `typhoon-debug`

Runs diagnostic probes against a live TYPHOON server. Requires the `debug` feature (which implies `client` and `server`).

```shell
cargo build --bin typhoon-debug --features debug

# Run all phases (reachability, RTT, throughput)
./target/debug/typhoon-debug client.cert

# Run a single phase
./target/debug/typhoon-debug client.cert reachability
./target/debug/typhoon-debug client.cert rtt
./target/debug/typhoon-debug client.cert throughput
```

### Settings overrides

All `TYPHOON_*` protocol constants can be overridden at runtime through environment variables:

```shell
TYPHOON_MAX_RETRIES=5 TYPHOON_TIMEOUT_DEFAULT=10000 cargo run --example hello_world
```

They can also be set programmatically via `SettingsBuilder`:

```rust
let settings = Arc::new(
    SettingsBuilder::<DefaultExecutor>::new()
        .set(&keys::MAX_RETRIES, 5)
        .set(&keys::TIMEOUT_DEFAULT, 10_000)
        .build()
        .expect("valid settings"),
);
```

### Design choices

- **Runtime agnostic**: async primitives are abstracted behind `AsyncExecutor` and the wrappers in `utils/sync.rs`; switching between `tokio` and `async-std` requires only a feature flag.
- **Zero-copy by design**: payload bytes travel as views over pooled `ByteBuffer`s from allocation to the UDP socket; copies are introduced only at system boundaries (user API and OS socket calls).
- **Lock-free hot paths**: per-packet paths use `CachedMap` snapshots (wait-free reads) and `AtomicBitSet` for active-flow tracking; `Mutex`/`RwLock` is confined to session lifecycle operations (handshake, teardown).

## Evaluation

The `evaluation/` directory contains a Docker-based traffic capture and analysis harness, organised into three independent parts:

1. **TYPHOON self-comparison** — measure run-to-run and scenario-to-scenario variability of TYPHOON's own traffic profile.
2. **Operational comparison** — capture all 16 protocols (TYPHOON + 15 comparators) under a controlled Docker network and compare their throughput, overhead, goodput efficiency, byte entropy, burstiness, and handshake characteristics. _Operational metrics, not detectability._
3. **Background-blending evaluation** — generate a corpus of natural UDP traffic (QUIC HTTPS, DNS, RTP voice/video, gaming, control plane), run TYPHOON alongside, and measure how often a passive classifier mistakes TYPHOON for benign background traffic.

See [evaluation/EVALUATION.md](evaluation/EVALUATION.md) for a complete explanation of each part. The empirical grounding for the Part 3 background composition is in evaluation/docs/TRAFFIC_CAPTURE_REFERENCE.md §7.

### Requirements

- **Docker** (or rootful Podman) — required to run the multi-container capture stacks; rootless Podman cannot grant `NET_ADMIN` to the observer container.
- **Python 3.11+** with [Poetry](https://python-poetry.org/)
- Built Docker images for all 16 protocol stacks (see setup below)

Optional, for the ML utilities (re-used in Part 3):

- `scikit-learn` — installed with the `ml` dependency group (default)
- `torch` (PyTorch) — for 1D-CNN sequence and header-byte models
- `xgboost` — for XGBoost gradient boosting
- `umap-learn` — for UMAP 2D dimensionality reduction

### Setup

```shell
cd evaluation

# Install Python dependencies (core + ML group)
poetry install --with ml

# Build all 16 protocol Docker images (required once, before first capture)
poetry poe build
```

### Poetry commands

All commands run from the `evaluation/` directory.

#### Shared (capture, parse, orchestrate)

| Command | What it does |
| --- | --- |
| `poe build` | Build all 16 protocol Docker images. Required once before any captures. |
| `poe capture --all` | Capture traffic from all 16 protocols (default: bulk transfer, 10 MB). |
| `poe capture --all --chaos` | Same, with network chaos (latency + jitter via Pumba). |
| `poe capture --protocol typhoon` | Capture a single protocol. |
| `poe capture --all --scenario interactive` | Capture with a specific scenario. Scenarios apply meaningfully to TYPHOON (Part 1); for the cross-protocol operational comparison (Part 2), `bulk` is the right default. |
| `poe analyze` | Parse all pcap files from the latest run and write `stats.json`. |
| `poe analyze --run 20260501_120000` | Analyze a specific run by timestamp. |
| `poe lint` | Lint Python sources with ruff. |
| `poe clean` | Delete all captured pcap files and logs. |

#### Part 1 — TYPHOON self-comparison

| Command | What it does |
| --- | --- |
| `poe self-compare` | Run TYPHOON N times under identical config; overlay size and IAT distributions across runs. |
| `poe traffic-compare` | Run TYPHOON across the four payload×wait scenario combinations; compare profiles. |
| `poe use-case-compare` | Run TYPHOON once per PROTOCOL.md use case (throughput / interactive / transparent / security). |
| `poe plot` | Per-flow stacked-bar diagrams from the TYPHOON crate's `capture` log target. |

#### Part 2 — Operational comparison vs other protocols

| Command | What it does |
| --- | --- |
| `poe proto-compare` | Generate operational comparison plots and the markdown table from the latest run. |
| `poe proto-flow-plot` | Per-packet timeline grid from the latest run's pcap captures (auxiliary). |

Outputs land in `results/plots/`:

- `<run>_proto_compare.png` — six-panel operational figure (size CDF, IAT CDF, throughput-vs-efficiency scatter, overhead bars, byte-entropy phases, normalised metric heatmap)
- `<run>_handshake.png` — handshake duration / packet count / byte fraction
- `<run>_compare_table.md` — markdown comparison table

#### Part 3 — Background-blending evaluation

| Command | What it does |
| --- | --- |
| `poe background-build` | Build all 8 generator Docker images (DNS, gaming, RTP voice/video, QUIC d/l, QUIC u/l, control plane, WG idle). |
| `poe background-corpus` | Run the randomised corpus (default 20 runs) — each run picks a random TYPHOON profile, a random subset of generators, and random network chaos. |
| `poe background-blending` | Compute primary metric: fraction of TYPHOON flows confidently classified as one of the natural background classes. |
| `poe background-openworld` | Compute open-world metrics: one-class SVM novelty rate + TPR @ 0.1 % FPR. |

Outputs land in `results/background/run_*/` — one directory per corpus run with the captured pcap and metadata.

#### ML utilities (used by Part 3, callable standalone)

| Command | What it does |
| --- | --- |
| `poe ml-features` | Extract ML feature matrix (`features.npz`) from `stats.json`. |
| `poe ml-classify` | RF / SVM / GB / XGBoost on scalar features. |
| `poe ml-cluster` | k-Means / DBSCAN clustering + PCA/UMAP visualisation. |
| `poe ml-sequence` | MLP + 1D-CNN on first-100 packet size and IAT sequences. |
| `poe ml-bytes` | RF + 1D-CNN on IP+UDP header bytes. |

These were retained from the legacy framing for re-use as components inside Part 3's open-world detector. They are **not** part of the default operational comparison.

#### Pipeline orchestrator

| Command | What it does |
| --- | --- |
| `poe evaluate` | Run captures, analysis, Part 1 + Part 2 plots, ML, and report generation. |

### Quick start

```shell
cd evaluation

# 1. Build images (once)
poetry poe build

# 2a. Operational comparison only (Part 2)
poetry poe capture --all
poetry poe analyze
poetry poe proto-compare

# 2b. TYPHOON self-comparison (Part 1)
poetry poe self-compare
poetry poe traffic-compare
poetry poe use-case-compare

# 2c. Full pipeline (Parts 1 + 2 + ML utilities + report)
poetry poe evaluate --classification-runs 3 --chaos
```

Outputs under `results/`:

- `captures/run_*/` — pcaps + `stats.json` + container logs
- `plots/` — Part 2 operational figures and comparison table
- `self_compare/`, `traffic_compare/`, `use_case_compare/` — Part 1 figures
- `ml/` — feature matrices, model weights, ML diagrams
- `report.md` — pipeline summary report
