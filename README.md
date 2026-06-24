# TYPHOON

> Transfer Your Packets Hidden Over Observed Networks

There are lots of data transferring protocols out there.
Developers have made significant progress in protecting user data with various cryptographic algorithms, making encryption difficult to break.
Still, it's possible to try, and some progress is also being made, e.g., in breaking asymmetric ciphers.

This project tries to make another step in encryption: making a protocol so obfuscated that it's hard to identify and verify it in the first place.
Indeed, if an attacker doesn't know _what_ protocol they're looking at, it makes breaking it significantly harder.

For the full protocol specification, architecture, cryptographic details, and proposed implementation, see [PROTOCOL.md](PROTOCOL.md).

For how TYPHOON compares against 15 other protocols, what traffic data is collected and how, and how ML classifiers attempt to fingerprint it, see [evaluation/README.md](evaluation/README.md).

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
- `tokio`: use [tokio](https://tokio.rs/) async runtime. The multi-threaded flavor is required (`#[tokio::main]` or `Builder::new_multi_thread()`); single-threaded `current_thread` is rejected at `Listener::build()` / `ClientSocket::build()` time.
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

# Multiple simultaneous clients dispatched through a single ClientPool
cargo run --example client_pool

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

- **Runtime agnostic**: async primitives are abstracted behind `AsyncExecutor` and the wrappers in `utils/sync.rs`; switching between `tokio` (multi-threaded flavor) and `async-std` requires only a feature flag.
- **Zero-copy by design**: payload bytes travel as views over pooled `ByteBuffer`s from allocation to the UDP socket; copies are introduced only at system boundaries (user API and OS socket calls).
- **Lock-free hot paths**: per-packet paths use `CachedMap` snapshots (wait-free reads) and `AtomicBitSet` for active-flow tracking; `Mutex`/`RwLock` is confined to session lifecycle operations (handshake, teardown).

### Deployment

TYPHOON's wire packet rate is amplified by its decoy stream relative to a "raw" UDP service.
On a server using Linux's default UDP socket buffer (`net.core.rmem_default = net.core.rmem_max = 208 KB`), a bursty arrival pattern under loss/jitter (e.g. mobile-handoff, transient ISP shaping) can overrun the kernel receive buffer before TYPHOON's userspace receive loop drains it, dropping incoming packets before the protocol's authentication path sees them.

**Bump the host-level UDP buffer sysctls on any production server**, the same way the WireGuard / OpenVPN / strongSwan deployment guides recommend:

| `sysctl` name | required value |
| --- | --- |
| `net.core.rmem_max` | 16777216 |
| `net.core.rmem_default` | 4194304 |
| `net.core.wmem_max` | 16777216 |
| `net.core.wmem_default` | 4194304 |

These are the same values the standard UDP-VPN guides recommend.
At default sizes, both TYPHOON _and_ other UDP-native services (WireGuard, OpenVPN, raw UDP) under-deliver on heavily loaded paths; with these set, the kernel keeps up with the highest decoy rate the protocol's reference providers emit.

## Evaluation

The [`evaluation/`](evaluation/) directory contains a Docker-based traffic capture and analysis harness, organised into three independent parts:

1. **TYPHOON self-comparison** — measure run-to-run and scenario-to-scenario variability of TYPHOON's own traffic profile.
2. **Operational comparison** — capture all 16 protocols (TYPHOON + 15 comparators) under a controlled Docker network and compare throughput, overhead, goodput efficiency, byte entropy, burstiness, and handshake metrics. _Operational, not detectability._
3. **Background-blending evaluation** — generate a corpus of natural UDP traffic (QUIC HTTPS, DNS, RTP voice/video, gaming, control plane), run TYPHOON alongside, and measure how often a passive classifier mistakes TYPHOON for benign traffic.

See [evaluation/README.md](evaluation/README.md) for requirements, install steps, CLI reference, and instructions for reading the results.
