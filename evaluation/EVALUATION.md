# TYPHOON Evaluation Framework

> A guide to how the TYPHOON evaluation harness works, what it measures, and why — written for readers who have never seen the codebase before.

---

## Table of Contents

1. [The thesis and three evaluation parts](#1--the-thesis-and-three-evaluation-parts)
2. [Part 1 — TYPHOON self-comparison](#2--part-1--typhoon-self-comparison)
3. [Part 2 — Operational comparison vs other protocols](#3--part-2--operational-comparison-vs-other-protocols)
4. [Part 3 — Background-blending evaluation](#4--part-3--background-blending-evaluation)
5. [Shared infrastructure](#5--shared-infrastructure)
6. [Per-pcap metrics reference](#6--per-pcap-metrics-reference)
7. [Directory layout](#7--directory-layout)
8. [What was considered but not done](#8--what-was-considered-but-not-done)
9. [References](#9--references)

---

## 1 — The thesis and three evaluation parts

### The thesis

TYPHOON is an encrypted UDP tunnel designed to be *unidentifiable* — not just unreadable. Standard encryption (TLS, WireGuard, etc.) protects content but still exposes structural metadata: packet sizes, timing patterns, direction asymmetry, and handshake signatures. A passive observer who cannot decrypt the traffic can still fingerprint its origin protocol from these patterns alone. This is the threat model of censors (the Great Firewall of China, ISP-level DPI) and network adversaries described in [PROTOCOL.md](../PROTOCOL.md).

The right question for an obfuscation protocol is therefore not "can a classifier tell TYPHOON apart from WireGuard?" — the answer is trivially yes, because TYPHOON and WireGuard are both clearly tunnel protocols and a classifier that sees only those two classes will pick the right one. **The right question is "can a classifier tell TYPHOON apart from natural, benign UDP traffic on the public internet?"** — that is, can it pick TYPHOON out of a haystack of QUIC HTTPS, DNS, RTP video calls, gaming traffic, and so on?

The evaluation is split into three parts that ask three distinct questions:

| Part | Question | Method |
| --- | --- | --- |
| **1. Self-comparison** | Is TYPHOON's traffic profile *stable and reproducible*? | Run TYPHOON N times under identical and varying conditions; measure run-to-run variance. |
| **2. Operational comparison** | Where does TYPHOON sit on the *throughput / overhead / handshake-cost* axes among existing tunneling protocols? | Capture the 16 protocols once each in a controlled Docker network; compare operational metrics directly. **No ML classifiers — that would be the wrong question here.** |
| **3. Background-blending evaluation** | Can a passive observer pick TYPHOON out of a *natural UDP traffic mix*? | Build a corpus that mirrors the real composition of public-internet UDP traffic (QUIC, DNS, RTP voice/video, gaming, control plane); run TYPHOON alongside; train an open-world classifier on the background only and measure how often TYPHOON is mistaken for benign traffic. |

Earlier versions of this harness conflated these three questions and measured them all with one closed-world classifier. That misframed the central thesis. The current structure separates them so each part answers exactly one well-posed question.

### What changed from the legacy framing

Previous versions treated the 16-protocol comparison as a "detectability competition". The current framing:

- Keeps the 16-protocol comparison but reframes it as **operational**, not detectability.
- Moves the detectability question to **Part 3** with a *natural background corpus* rather than a tunnel-vs-tunnel classifier.
- Keeps the existing ML modules (`ml_classify`, `ml_cluster`, `ml_sequence`, `ml_bytes`) intact for **reuse** in Part 3 — they were not deleted, just moved out of Part 2.

---

## 2 — Part 1 — TYPHOON self-comparison

Lives in [src/typhoon_eval/self/](src/typhoon_eval/self/).

### Part 1 — Question

How stable is TYPHOON's traffic profile? Two sub-questions:

1. *Run-to-run variability under identical configuration*: if you run the same TYPHOON workload twice, do the size CDFs and IAT distributions match? A well-designed obfuscation protocol should have stable profiles within a configuration but *unpredictable* profiles across distinct flows (the `FlowConfig::random` machinery in the TYPHOON crate).
2. *Profile shifts under different scenarios*: if you switch from bulk upload to interactive or streaming workloads, how does the profile change? This shows what the protocol's surface looks like under different real-world usage patterns.

### Modules

| Module | Purpose | Output |
| --- | --- | --- |
| `self/self_compare.py` | Run TYPHOON N times under identical config; overlay size CDFs and IAT CDFs across runs. | `results/self_compare/default_self_compare.png` |
| `self/traffic_compare.py` | Run TYPHOON with the four payload×wait scenario combinations; compare profiles. | `results/traffic_compare/default_traffic_compare.png` |
| `self/use_case_compare.py` | Run TYPHOON once per use case from PROTOCOL.md (throughput / interactive / transparent / security); compare profiles. | `results/use_case_compare/use_case_compare.png` |
| `self/flow_plot.py` | TYPHOON-specific: generate per-flow stacked-bar diagrams from the crate's `capture` log target showing per-packet wire composition. | `results/flow_plots/<example>.png` |

### Part 1 — Commands

```bash
poe self-compare         # run TYPHOON N times, compare runs
poe traffic-compare      # 4 scenario combinations
poe use-case-compare     # PROTOCOL.md use cases
poe plot                 # per-flow packet-structure diagrams
```

### What good looks like

For *self-compare*: tight envelopes around each metric across N runs (low variance under identical config). For *traffic-compare* and *use-case-compare*: clearly separated profiles per scenario (TYPHOON adapts to workload).

---

## 3 — Part 2 — Operational comparison vs other protocols

Lives in [src/typhoon_eval/protocols_op/](src/typhoon_eval/protocols_op/).

### Part 2 — Question

Where does TYPHOON sit on the operational axes — *throughput, overhead, goodput efficiency, byte entropy, handshake cost* — relative to existing tunneling and VPN protocols? This is a deployment-decision question, not a detectability question.

This is **deliberately not** an ML-classifier comparison. A 16-protocol closed-world classifier of tunnel-vs-tunnel will always achieve near-100 % accuracy because the protocols *are* different — they have different overhead, different padding strategies, different handshakes by design. That accuracy number does not say anything about whether TYPHOON blends into background traffic; it says only that TYPHOON is not byte-identical to WireGuard, which is uninteresting.

### The 16 comparison protocols

| Protocol | Transport | Role |
| --- | --- | --- |
| `raw_udp` | UDP | Unencrypted baseline |
| `raw_tcp` | TCP | Unencrypted baseline |
| `tls` | TCP | Standard encrypted transport |
| `wireguard` | UDP | Widely-deployed VPN |
| `quic` | UDP | Modern multiplexed transport |
| `obfs4` | TCP | Tor pluggable transport (default) |
| `obfs4_iat` | TCP | OBFS4 with IAT obfuscation mode 1 |
| `obfs4_iat2` | TCP | OBFS4 with IAT obfuscation mode 2 |
| `amneziawg` | UDP | WireGuard with header obfuscation |
| `hysteria2` | UDP | BBR/Brutal-based UDP tunnel |
| `shadowsocks` | TCP/UDP | Lightweight obfuscated proxy |
| `tor` | TCP | Onion-routing anonymity network |
| `vless_reality` | TCP | TLS-mimicking anti-censorship proxy |
| `openvpn` | UDP | Classic VPN |
| `wireguard_daita` | UDP | WireGuard with DAITA traffic shaping |
| `typhoon` | UDP | This project |

### Outputs (`poe proto-compare`)

Three artefacts per capture run:

- **`<run>_proto_compare.png`** — six-panel operational comparison:
  - A — packet-size CDF
  - B — inter-arrival-time CDF
  - C — throughput vs. goodput-efficiency scatter
  - D — protocol-overhead bar chart
  - E — byte entropy by phase (all / handshake / data)
  - F — operational metric heatmap (throughput, goodput eff., data entropy, burstiness, HS duration, HS byte fraction)
- **`<run>_handshake.png`** — three-panel handshake metrics: duration, packet count, byte fraction.
- **`<run>_compare_table.md`** — markdown comparison table (one row per protocol, columns for throughput / overhead / goodput / entropy / burstiness / handshake metrics / direction asymmetry).

### What this part does **not** do

- No JS-divergence matrix (was a detectability proxy in the legacy version).
- No first-N-packet "fingerprint barcodes" (detectability proxy).
- No tunnel-vs-tunnel classifier accuracy numbers.

These were dropped because they answer the wrong question — see Part 3 for the right one.

### Part 2 — Commands

```bash
poe capture --all          # capture all 16 protocols in one bulk run
poe analyze                # per-pcap metrics → stats.json
poe proto-compare          # plots + table for the latest run
poe proto-flow-plot        # per-packet timeline grid (auxiliary)
```

---

## 4 — Part 3 — Background-blending evaluation

Status: **planned, not yet implemented**. This section describes the design.

Will live in `evaluation/background/` (Docker build contexts for natural-UDP traffic generators) and `src/typhoon_eval/background/` (eval-host orchestration and ML).

### Part 3 — Question

If a passive observer sees a stream of UDP traffic from a real residential or campus uplink — dominated by QUIC HTTPS, DNS, RTP voice/video, gaming, and a long tail of control-plane protocols — can it reliably pick TYPHOON flows out of that mix?

The right metric is **not** "TYPHOON-vs-tunnels classifier accuracy" but **"fraction of TYPHOON flows confidently classified as one of the natural background classes"**. Higher is better for TYPHOON; ideal is 100 %.

### The background corpus

The composition is grounded in real-world UDP traffic measurements catalogued in [docs/TRAFFIC_CAPTURE_REFERENCE.md §7](docs/TRAFFIC_CAPTURE_REFERENCE.md#7-real-world-udp-traffic-composition). Eight natural classes:

| Class | Generator | Real-world share | Per-packet signature |
| --- | --- | --- | --- |
| QUIC HTTPS download | aioquic / quiche client + Caddy HTTP/3 | ~70–80 % of UDP bytes | Initial 1200 B, data 1100–1500 B, c2s-sparse |
| QUIC HTTPS upload | same | minor | Inverted asymmetry |
| DNS | dnsperf + unbound | <1 % bytes, ubiquitous flows | 60–500 B, single-shot |
| RTP voice (G.711 / Opus) | sipp + RTP | ~5 % | 200 B every 20 ms, symmetric |
| RTP video (H.264/Opus) | FFmpeg + RTP | meaningful | 1100–1300 B every ~33 ms, symmetric |
| Online gaming | custom Python | small, ubiquitous | 40 B s2c / 60–300 B c2s, IAT 16–50 ms |
| WireGuard idle | existing WG container | <1 % | 60 B keepalive every 25 s |
| Control plane (NTP / mDNS / STUN) | scapy | trace | <100 B, single-shot |

### Run plan

Each "background run" picks a randomised subset of generators (≥ 3 active simultaneously), randomises their parameters (object sizes, IATs, codec settings, query rates), captures for 90–180 s, and runs **TYPHOON in parallel** with one randomly chosen scenario from Part 1. Repeat 20–25 times under varying chaos conditions (latency 0–100 ms, jitter 0–20 ms, loss 0–2 %).

### ML evaluation (open-world, not closed-world)

Three metrics:

| Metric | Trained on | Tested on | Direction |
| --- | --- | --- | --- |
| Confident-blend fraction | Background only (8 classes) | TYPHOON flows | Higher = better for TYPHOON |
| One-class-SVM novelty rate | Background only (1 class: "normal UDP") | TYPHOON flows | Lower = better for TYPHOON |
| TPR @ 0.1 % FPR | Background + TYPHOON binary | Held-out flows | Lower = better for TYPHOON. WF-literature standard from [TRAFFIC_CAPTURE_REFERENCE.md §5.6](docs/TRAFFIC_CAPTURE_REFERENCE.md#56-evaluation-metrics). |

### Code layout (planned)

```text
evaluation/background/                      # Docker build contexts for generators
├── quic_download/, dns/, rtp_voice/, …
└── compose/docker-compose.yml

src/typhoon_eval/background/                # eval-host code
├── corpus.py                                # orchestrates N parallel generators + TYPHOON
├── ml_open_world.py                         # confidence-based blending detector
└── ml_blending.py                           # primary metric (confident-blend fraction)
```

The `src/typhoon_eval/ml/` modules (RF / SVM / GB / 1D-CNN / clustering) are kept and will be re-used as components inside Part 3's open-world detector.

---

## 5 — Shared infrastructure

Lives in [src/typhoon_eval/shared/](src/typhoon_eval/shared/) and is used by all three parts.

### Network topology (capture)

```text
  ┌─────────────┐       net_left         ┌──────────────┐       net_right        ┌─────────────┐
  │   client    │  172.20.0.10 ─────────▶│   observer   │──────────────────────▶ │   server    │
  │  container  │                        │  172.20.0.2  │                        │  container  │
  └─────────────┘                        │  172.21.0.2  │                        └─────────────┘
                                         └──────────────┘
                                         tcpdump writes
                                         <protocol>.pcap here
```

The observer bridges two Docker networks and runs `tcpdump -i any`. Because it sits between client and server, every packet is seen exactly once regardless of NAT — consistent with passive ISP-level observation [tcpdump/libpcap ref](docs/TRAFFIC_CAPTURE_REFERENCE.md#11-core-capture-toolchain).

### Traffic scenarios

| Scenario | Description | Used by |
| --- | --- | --- |
| `bulk` | Send all data as fast as possible (500-byte chunks) | Parts 1, 2, 3 |
| `interactive` | 50-byte chunks with 100 ms inter-packet delay | Parts 1, 3 |
| `streaming` | 1250-byte chunks with 10 ms delay (~1 Mbps CBR) | Parts 1, 3 |
| `burst` | 3 × (send 1 MB, then sleep 10 s) | Parts 1, 3 |
| `echo` | Server echoes immediately | Part 1 |
| `idle` | Connect, wait 30 s, disconnect | Part 1 |

### Chaos mode

`--chaos` wraps the client with Pumba + tc/netem to introduce latency / jitter (currently — packet loss and bandwidth caps are listed in [TRAFFIC_CAPTURE_REFERENCE.md §3](docs/TRAFFIC_CAPTURE_REFERENCE.md#3-network-emulation-controlled-conditions) but not yet wired through).

### Output structure

```text
results/captures/run_YYYYMMDD_HHMMSS/
├── <protocol>.pcap                # raw packet capture (all parts)
├── <protocol>_chaos.pcap           # under --chaos
├── stats.json                      # per-pcap metrics, see §6
├── metadata.json                   # transfer_bytes, scenario, timing
├── config.json                     # invocation parameters
└── logs/<protocol>/                # client/server/observer container logs
```

### Capture orchestration

`shared/orchestrator.py` runs each protocol sequentially — Docker Compose projects cannot share networks safely in parallel. Per protocol: write env vars to `.env`, `docker compose up`, wait for the client to exit (with timeout), parse delivery percent and timing from logs, tear down. Detailed in `shared/docker_utils.py`.

---

## 6 — Per-pcap metrics reference

For every pcap, `shared/pcap_stats.analyze_pcap()` computes the following. Metrics are computed separately for each direction (`c2s`, `s2c`, `all`). Direction-aware metrics (marked †) appear only in `all`.

### Important measurement note

Packet sizes are recorded as the **transport-layer payload length** (UDP payload, or TCP segment data) — the bytes above the IP+UDP/TCP headers. This excludes a constant 28 B (UDP) or 40+ B (TCP) per-packet overhead that would otherwise leak transport-layer signal into protocol-level statistics. So "packet size 674 B" means 674 B of encrypted protocol payload, not 702 B on the wire.

### Per-direction scalar metrics

| Metric | Description |
| --- | --- |
| `packet_count` | Number of packets observed |
| `byte_count` | Total transport-payload bytes |
| `transmission_time_s` | First → last packet duration |
| `packet_size.{mean,std,min,max,p5,p25,p50,p75,p95,p99,entropy}` | Distribution of transport-payload sizes (entropy normalised to [0, 8]) |
| `iat_ms.{mean,std,p5,p50,p95,p99,entropy}` | Inter-arrival-time distribution in ms |
| `entropy.{all,handshake,data}` | Shannon entropy of payload bytes by phase (bits/byte; encrypted ≈ 8.0) |
| `burstiness` | Coefficient of variation of IATs: `std(IAT) / mean(IAT)` |
| `size_regularity` | `n_distinct_sizes / n_total_packets` |
| `overhead_ratio` | `(transport_payload_bytes − app_data) / app_data` (when `transfer_bytes` is known) |
| `goodput_efficiency` | `app_data / transport_payload_bytes` |

### Direction-aware metrics (in `all` only)

| Metric | Description |
| --- | --- |
| `direction_asymmetry`† | `c2s_bytes / s2c_bytes` |
| `first_n_sizes[100]`† | First 100 direction-signed packet sizes (c2s positive, s2c negative) — kept for ML re-use |
| `first_n_iats[100]`† | First 100 direction-signed IATs (ms) — kept for ML re-use |
| `burst_count`† | Number of contiguous same-direction runs |
| `mean_burst_pkt`† | Mean packets per burst |
| `mean_burst_bytes`† | Mean bytes per burst |

### Handshake metrics (when a sniffer is configured for the protocol)

| Metric | Description |
| --- | --- |
| `hs_duration_s`† | Handshake-window duration |
| `hs_pkt_count`† | Packets in the handshake window |
| `hs_byte_frac`† | Fraction of total bytes in the handshake |

The handshake window is determined by a per-protocol sniffer in `shared/protocols.py`. Sniffers use a packet-count rule (e.g. TYPHOON: first 1 c2s + 2 s2c packets; raw TCP: first 2 c2s + 1 s2c packets for the 3-way handshake) capped at a 200 ms safety net to handle protocols whose s2c side is sparse during bulk upload.

---

## 7 — Directory layout

```text
evaluation/
├── compose/                        # docker-compose YAMLs (16 protocols)
├── protocols/                      # Docker build contexts for the 16 comparison protocols
│   ├── common/                     # shared sender code baked into protocol images
│   └── <protocol>/                 # per-protocol Dockerfile + scripts
├── background/                     # PLANNED — Docker build contexts for natural-UDP generators
├── docs/
│   └── TRAFFIC_CAPTURE_REFERENCE.md
├── results/                        # generated outputs
│   ├── captures/run_*/             # pcaps + stats.json
│   ├── plots/                      # Part 2 outputs
│   ├── self_compare/, traffic_compare/, use_case_compare/  # Part 1 outputs
│   └── ml/                         # ML feature matrices and model weights
├── pyproject.toml                  # poe tasks
└── src/typhoon_eval/
    ├── pipeline.py                 # full-evaluation orchestrator
    ├── shared/                     # capture, parse, orchestrate (used by all parts)
    │   ├── analysis.py
    │   ├── capture_stats.py
    │   ├── docker_utils.py
    │   ├── orchestrator.py
    │   ├── pcap_flow_plot.py
    │   ├── pcap_stats.py
    │   └── protocols.py
    ├── self/                       # PART 1
    │   ├── self_compare.py
    │   ├── traffic_compare.py
    │   ├── use_case_compare.py
    │   └── flow_plot.py
    ├── protocols_op/               # PART 2
    │   └── proto_compare_plots.py
    ├── ml/                         # ML utilities — kept for re-use in PART 3
    │   ├── ml_features.py
    │   ├── ml_classify.py
    │   ├── ml_cluster.py
    │   ├── ml_sequence.py
    │   └── ml_bytes.py
    └── background/                 # PART 3 — eval-host orchestration (PLANNED)
        ├── corpus.py
        ├── ml_open_world.py
        └── ml_blending.py
```

The split between `protocols/` (Docker build contexts) and `src/typhoon_eval/` (eval-host Python) is intentional: code that runs *inside* containers is not on the eval host's import graph. The same pattern applies to the planned `background/` peer dir.

---

## 8 — What was considered but not done

### Part 2 simplifications

The legacy version of `proto_compare_plots.py` had three additional figures:

- An 8-panel **fingerprint figure** with first-N-packet barcodes, JS-divergence matrix, parallel coordinates, and IAT fingerprints.
- A 16 × 16 **inter-protocol JS-divergence heatmap**.
- An ML "competition" mode where TYPHOON-vs-tunnels closed-world classifiers reported 100 % accuracy.

All three were dropped because they answered the wrong question (detectability of TYPHOON among tunnels rather than detectability of TYPHOON among natural UDP traffic). The first-N-packet sequences and direction-signed IAT sequences are still computed by `pcap_stats` and kept in `stats.json` for ML re-use in Part 3.

### Closed-world ML modules

`ml_features.py`, `ml_classify.py`, `ml_cluster.py`, `ml_sequence.py`, `ml_bytes.py` were retained but moved to `src/typhoon_eval/ml/` and removed from the default pipeline. They will be reused as components inside Part 3's open-world detector.

### Real-application traffic generators

Playwright (browser), yt-dlp (DASH/HLS), and FFmpeg+RTP are listed in [TRAFFIC_CAPTURE_REFERENCE.md §2.2](docs/TRAFFIC_CAPTURE_REFERENCE.md#22-realistic-application-layer-simulators) but not yet built into the harness. They are the foundation of Part 3's background corpus.

### Loss / bandwidth-cap chaos conditions

Currently chaos is latency + jitter only. Packet loss, bandwidth caps, and packet reordering are documented in [TRAFFIC_CAPTURE_REFERENCE.md §3](docs/TRAFFIC_CAPTURE_REFERENCE.md#3-network-emulation-controlled-conditions) and supported by tc/netem, but not yet wired through.

### Cross-scenario classifier robustness

Train on bulk, test on interactive — to measure whether classifiers exploit environment-specific artefacts vs. learning real protocol patterns. Will become useful once Part 3 corpus exists.

---

## 9 — References

All methodology references — including the foundation studies cited in this document — are catalogued in [docs/TRAFFIC_CAPTURE_REFERENCE.md](docs/TRAFFIC_CAPTURE_REFERENCE.md). Section 7 of that file describes the **real-world UDP traffic composition** that grounds Part 3's background corpus, with citations to AppLogic Networks (Sandvine), Cloudflare, APNIC Labs, MAWI / WIDE, CESNET-QUIC22, CAIDA, and relevant RFCs (3550 RTP, 6891 EDNS, 8831 WebRTC Data Channels, 9000 QUIC).

Key citations supporting the framing:

- Sirinam et al., "Deep Fingerprinting", CCS 2018 — direction-annotated sequence input
- Hayes & Danezis, "k-fingerprinting", USENIX Sec 2016 — RF baseline
- Tschantz et al., "SoK", IEEE S&P 2016 — four evaluation axes for censorship circumvention (handshake / overhead / distinguishability / timing)
- Juarez et al., "A Critical Evaluation of WF Attacks", CCS 2014 — controlled-evaluation methodology and the open- vs. closed-world distinction that motivates Part 3
- Donenfeld, "WireGuard", NDSS 2017 — handshake structure reference for Part 2
- Langley et al., "QUIC", SIGCOMM 2017 — QUIC packet structure for Part 3 generator
