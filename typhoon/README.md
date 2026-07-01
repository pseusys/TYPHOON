# TYPHOON

> Transfer Your Packets Hidden Over Observed Networks

An obfuscated UDP transport protocol designed to be statistically indistinguishable from generic network traffic.
Every wire packet is made up of an optional fake body, an optional fake header, an encrypted payload, and an encrypted trailer; a flow-layer decoy stream injects pure-random packets to mask timing and volume patterns even when no real data is in flight.

Unlike most UDP-based VPN protocols (WireGuard, OpenVPN, QUIC), a TYPHOON session is not pinned to a single UDP 4-tuple.
Each side splits into a session manager (state, encryption) and one or more flow managers, each owning its own UDP socket — a client can spread one session's traffic across several server "proxy" addresses/ports, and a server flow manager can be reused across many client sessions.
Real packets are routed across whichever flows are configured, and each flow runs its own independent decoy stream, so the session's wire footprint is not a single fixed flow's worth of traffic.

This crate is the reference Rust implementation of the protocol.
The full specification (wire format, cryptography, threat model) lives in [PROTOCOL.md](https://github.com/pseusys/TYPHOON/blob/main/PROTOCOL.md); the project-level [README](https://github.com/pseusys/TYPHOON/blob/main/README.md) covers the evaluation harness and protocol comparison against 15 other transports.

Published on crates.io as `typhoon-protocol`:

```toml
[dependencies]
typhoon-protocol = { version = "0.1" }
```

The library itself is imported as `typhoon`:

```rust
use typhoon::socket::{ClientSocketBuilder, ServerBuilder};
```

## Performance and overhead

Numbers below are from the protocol paper's evaluation chapters (criterion benchmarks on a single workstation, `fast_software` build, and a 16-protocol Docker comparison harness); see the paper in [`typhoon-protocol-paper`](https://github.com/pseusys/TYPHOON/tree/main/typhoon-protocol-paper) for full methodology.

- **Handshake**: server-side Classic McEliece decapsulation dominates at 5.7 ms, two orders of magnitude above client-side encapsulation (19 µs) or a plain ECDH exchange (42 µs baseline); the full client handshake over UDP loopback completes in 10 ms.
- **Bulk transfer**: under sustained load the protocol is I/O-bound — the UDP socket send call is the widest cost band in flame-graph profiling, ahead of symmetric crypto and the protocol state machine itself.
- **Wire overhead floor**: every payload-bearing packet carries a fixed minimum of cryptographic and structural overhead before any user data:

  | Packet class | Floor | Made up of |
  | --- | --- | --- |
  | Data-bearing | 144 B | identity (16 B) + trailer encryption (72 B) + payload AEAD (56 B) |
  | Decoy / health-check | 88 B | identity (16 B) + trailer encryption (72 B) |

- **Comparative overhead**: in a 10 MiB client → server transfer measured alongside 15 other UDP/TCP encrypted transports, TYPHOON's overhead ratio (extra bytes over payload) was 12.1% — above plain WireGuard/OpenVPN (~5%) but below other traffic-shaping protocols measured in the same harness (obfs4 32.5%, WireGuard+DAITA 29.5%, Tor 37.9%), reflecting the cost of its randomized padding and decoy traffic.
  Mean packet size was 1313±31 B at maximum payload entropy (8.00 bits/byte).
- **Passive classification**: in open-set tests against a mixed corpus of natural UDP traffic (DNS, RTP, gaming, QUIC, control-plane, etc.), a classifier tuned to flag 95% of TYPHOON flows also misclassified about 1 in 8 unrelated background flows in the test corpus. See [Blocking TYPHOON](#blocking-typhoon) below for what that does and doesn't imply.

## Blocking TYPHOON

- **Whitelisting known protocols works.** TYPHOON mimics generic, no-protocol-in-particular UDP behavior instead of impersonating a specific known one, so it doesn't resemble DNS, QUIC, RTP, or any other catalogued protocol closely enough to pass as one. A policy that allows only catalogued UDP protocols and drops everything else reliably drops TYPHOON too.
- **A known address is always blockable.** TYPHOON hides protocol identity, not endpoint existence; once a server's address is identified by any means, blocking it works regardless of how the traffic looks.
- **Active probing gets no distinguishing answer.** Unidentifiable packets are dropped silently by default (`NoopProbeHandler`); a custom `ActiveProbeHandler` can be supplied to mimic another protocol's response instead.
- **Passive classification of the unclassified remainder has a real, non-zero cost.** Within the residual bucket of otherwise-uncatalogued UDP traffic, a classifier tuned to catch most TYPHOON flows still misclassifies some unrelated ones — see the [evaluation harness](https://github.com/pseusys/TYPHOON/tree/main/evaluation) for methodology and numbers.
- **The user's own traffic shape isn't hidden by default.** Inter-arrival timing and length distribution of user data pass through unmodified; add padding/pacing at the application layer if that matters for a given deployment.

## Features

| Flag | Description |
| --- | --- |
| `fast_software` | XChaCha20-Poly1305 for everything (default) |
| `fast_hardware` | AES-GCM-256 for everything |
| `full_software` | X25519 for trailer + XChaCha20-Poly1305 for session |
| `full_hardware` | X25519 for trailer + AES-GCM-256 for session |
| `server` | Server-side listener and session management |
| `client` | Client-side socket and session management |
| `debug` | Debug probe tools (`DebugMode`, `run_debug`, `DebugServerConnectionHandler`); requires `client` + `server` |
| `capture` | Per-packet trace logging to the `typhoon::capture` log target at `TRACE` level |
| `tokio` | Tokio async runtime (multi-threaded flavor required) |
| `async-std` | async-std runtime |

Default features: `fast_software`, `server`, `client`, `tokio`.

Build/test commands, examples, and CI details live in the
[project README](https://github.com/pseusys/TYPHOON/blob/main/README.md#code-and-tests).

## Settings overrides

All `TYPHOON_*` protocol constants ([full list](https://github.com/pseusys/TYPHOON/blob/main/typhoon/src/settings/statics.rs))
can be overridden at runtime through environment variables:

```shell
TYPHOON_MAX_RETRIES=5 TYPHOON_TIMEOUT_DEFAULT=10000 cargo run --example hello_world
```

or programmatically via `SettingsBuilder`:

```rust
let settings = Arc::new(
    SettingsBuilder::<DefaultExecutor>::new()
        .set(&keys::MAX_RETRIES, 5)
        .set(&keys::TIMEOUT_DEFAULT, 10_000)
        .build()
        .expect("valid settings"),
);
```

## Design choices

- **One session, many flows**: a `ClientSocket`/`Listener` can fan a single session out across multiple flow managers — each with its own UDP port and, optionally, its own IP address — selected per-packet rather than pinned for the session's lifetime. Most UDP VPN protocols bind a session to one fixed 4-tuple; spreading traffic (and each flow's independent decoy stream) across several makes the per-session footprint inherently harder to characterize as a single flow. See [Architecture](https://github.com/pseusys/TYPHOON/blob/main/PROTOCOL.md#architecture) for the full diagram.
- **Runtime agnostic**: async primitives are abstracted behind `AsyncExecutor` and the wrappers in `utils/sync.rs`; switching between `tokio` (multi-threaded flavor) and `async-std` is a feature flag, not a code change.
- **Zero-copy by design**: payload bytes travel as views over pooled `ByteBuffer`s from allocation to the UDP socket; copies are introduced only at system boundaries (user API and OS socket calls).
- **Lock-free hot paths**: per-packet paths use `CachedMap` snapshots (wait-free reads) and `AtomicBitSet` for active-flow tracking; `Mutex`/`RwLock` is confined to session lifecycle operations (handshake, teardown).

## Deployment

TYPHOON's wire packet rate is amplified by its decoy stream relative to a "raw" UDP service.
On a server using Linux's default UDP socket buffer, a bursty arrival pattern under loss/jitter can overrun the kernel receive buffer before TYPHOON's userspace receive loop drains it.
**Bump the host-level UDP buffer sysctls on any production server**, the same way WireGuard / OpenVPN / strongSwan deployment guides recommend:

| `sysctl` name | required value |
| --- | --- |
| `net.core.rmem_max` | 16777216 |
| `net.core.rmem_default` | 4194304 |
| `net.core.wmem_max` | 16777216 |
| `net.core.wmem_default` | 4194304 |

## Reference implementation

The full design rationale lives in [PROTOCOL.md § Proposed implementation](https://github.com/pseusys/TYPHOON/blob/main/PROTOCOL.md#proposed-implementation); this is a summary of how this crate structures it.

**Moving parts.** Each side splits into a session manager (handshake, encryption, data) and one or more flow managers (decoy injection, traffic obfuscation, trailer-only decryption):

- **Listener** (server, one per process): tracks global state, spawns/recycles per-user session managers, issues client certificates.
- **Client pool** (server, optional, one per process): wraps a `Listener`, owns every `ClientHandle` in a map keyed by identity, and exposes a single identity-tagged `receive`/`send` pair instead of one handle per connection.
- **Session controller** (one per session): encrypts user data with the session key, appends the encrypted trailer, and hands the packet to a flow.
- **Health check provider** (one per session): drives handshake/keepalive timers and injects health-check packets.
- **Flow controller** (one per flow): owns a UDP socket, prepends the fake header/body, and writes the packet to the wire.
- **Decoy provider** (one per flow): observes the real packet stream and injects decoy packets per one of the five communication-mode profiles (heavy / noisy / sparse / smooth / random).
- **Active probe handler** (one per flow): receives packets that failed identification (undersized, decryption/verification failure) and can emit a raw response to mimic another protocol.

**Exportable submodules** (the public API surface — everything else is internal):

- [`socket`](https://github.com/pseusys/TYPHOON/blob/main/typhoon/src/socket) — entry points: `ClientSocketBuilder` → `ClientSocket`; `ServerBuilder` → `Listener` → `ClientHandle`, or `ServerBuilder` → `ClientPool` for the multiplexed entrypoint.
- [`flow`](https://github.com/pseusys/TYPHOON/blob/main/typhoon/src/flow) — `ClientFlowManager` / `ServerFlowManager`, the `DecoyProvider` / `ActiveProbeHandler` traits and their built-in implementations.
- [`certificate`](https://github.com/pseusys/TYPHOON/blob/main/typhoon/src/certificate) — server key pair / client certificate generation, persistence, and the binary file format.
- [`settings`](https://github.com/pseusys/TYPHOON/blob/main/typhoon/src/settings) — `SettingsBuilder`, the `TYPHOON_*` constant keys, and environment-variable override resolution.
- [`bytes`](https://github.com/pseusys/TYPHOON/blob/main/typhoon/src/bytes) — `DynamicByteBuffer` / `BytePool` (pooled, zero-copy buffers with prefix/suffix capacity for fake headers and trailers), plus `FixedByteBuffer<N>` and `StaticByteBuffer`.
- [`defaults`](https://github.com/pseusys/TYPHOON/blob/main/typhoon/src/defaults) — default constant values and type aliases.
- [`debug`](https://github.com/pseusys/TYPHOON/blob/main/typhoon/src/debug) *(feature `debug`)* — reachability, round-trip-time, and throughput probes against a live server.

Cryptography (`crypto`), session lifecycle (`session`), the wire trailer (`trailer`), and the lock-free cache primitives (`cache`) are deliberately kept internal (`pub(crate)`/private) — they are implementation details of the modules above, not a stable API surface.

**Open items.** Tracked at length in [PROTOCOL.md § Future work](https://github.com/pseusys/TYPHOON/blob/main/PROTOCOL.md#future-work):

- Multi-hop relays — chain a server and client together so an intermediate hop forwards traffic without decrypting payloads.
- Time-bounded address tracking — keep a small TTL'd set of recent source addresses per client instead of single-address rebinding.
- Path degrading — weighted path selection based on observed per-flow health.
- Isolated flow managers — allow flow managers to run in separate processes/machines from the listener.
- Periodic fake header/body mode rotation — already supported per-flow via `FlowConfig`'s rotation interval; broader rollout/tuning is open.
- UDP datagram batching via `sendmmsg(2)` — implemented on the client send path; server-side cross-client batching is not yet implemented.
- Per-deployment randomisation seed — perturb decoy/fake-body parameter distributions per deployment to resist cross-deployment classifier transfer.
