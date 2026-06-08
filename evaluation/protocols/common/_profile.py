#!/usr/bin/env python3
"""Profile-driven traffic execution for non-TYPHOON evaluation senders.

Reads PROFILE_* env vars (written by the evaluation orchestrator) to drive
the c2s portion of any profile from `shared/profiles.py`.  Non-TYPHOON
protocols cannot drive bidirectional s2c traffic without changes to the
underlying server image, so the s2c portion of any profile is silently
ignored on this side.

Two flavours:
  * `run_profile(send_fn)` — sync, for protocols whose data path is a
    blocking call (TCP `sendall`, SOCKS5 wrapper, raw UDP `send`).
  * `run_profile_async(send_fn)` — async, for protocols whose data path
    is asyncio-based (QUIC).  `send_fn` may be sync or async; if it
    returns an awaitable, the loop awaits it.

Both honour the same `PROFILE_*` knobs (chunk, IAT, bytes, duration,
bursty, INTER_PACKET_DELAY_MS, DELAY_EVERY_N).
"""

from asyncio import sleep as asleep
from collections.abc import Awaitable, Callable
from inspect import isawaitable
from os import environ, urandom
from time import monotonic, sleep
from typing import NamedTuple


class _ProfileConfig(NamedTuple):
    chunk_c2s: int
    iat_c2s_ms: float
    bytes_c2s: int
    duration_s: float
    bursty: bool
    burst_count: int
    burst_idle_s: float
    inter_batch_delay_ms: float
    batch_size: int


def _env_int(key: str, default: int) -> int:
    raw = environ.get(key)
    return int(raw) if raw is not None and raw.strip() else default


def _env_float(key: str, default: float) -> float:
    raw = environ.get(key)
    return float(raw) if raw is not None and raw.strip() else default


def _read_config() -> _ProfileConfig:
    # Batch pacing — pause `inter_batch_delay_ms` every `batch_size` packets.
    # This is the receiver-safe upper bound on send rate regardless of how
    # tight `iat_c2s_ms` is sampled.  Without it, sustained line-rate bursts
    # on a loopback bridge overflow the kernel UDP buffer faster than the
    # receiver can drain (TYPHOON's per-packet AEAD path is the canonical
    # example — see `evaluation/protocols/typhoon/src/bin/eval_client.rs`
    # for the matching Rust-side logic).  Default 40 ms every 10 packets;
    # setting either to 0 disables batch pacing.
    return _ProfileConfig(
        chunk_c2s=max(1, _env_int("PROFILE_CHUNK_C2S", 500)),
        iat_c2s_ms=_env_float("PROFILE_IAT_C2S_MS", 0.0),
        bytes_c2s=_env_int("PROFILE_BYTES_C2S", 10_485_760),
        duration_s=_env_float("PROFILE_DURATION_S", 60.0),
        bursty=_env_int("PROFILE_BURSTY", 0) != 0,
        burst_count=max(1, _env_int("PROFILE_BURST_COUNT", 1)),
        burst_idle_s=_env_float("PROFILE_BURST_IDLE_S", 0.0),
        inter_batch_delay_ms=_env_float("INTER_PACKET_DELAY_MS", 40.0),
        batch_size=max(1, _env_int("DELAY_EVERY_N", 10)),
    )


# Fill the chunk buffer with random bytes once so subsequent slices look like
# compressed/encrypted application data; sending all-zero payloads would let a
# passive observer split flows by trivial byte-entropy alone.
def _build_chunk(chunk_c2s: int) -> bytes:
    return urandom(chunk_c2s)


# ── Sync API ─────────────────────────────────────────────────────────────────


def run_profile(send_fn: Callable[[bytes], None]) -> tuple[int, float]:
    """Execute the c2s portion of the active profile using *send_fn*.

    Returns (bytes_sent, total_sleep_s).
    """
    cfg = _read_config()
    if cfg.bytes_c2s <= 0:
        return 0, 0.0

    start = monotonic()
    deadline = start + cfg.duration_s
    chunk = _build_chunk(cfg.chunk_c2s)
    delay_s = max(0.0, cfg.iat_c2s_ms) / 1000.0
    batch_delay_s = max(0.0, cfg.inter_batch_delay_ms) / 1000.0
    sent = 0
    total_sleep = 0.0

    if cfg.bursty and cfg.burst_count > 1:
        bytes_per_burst = cfg.bytes_c2s // cfg.burst_count
        for i in range(cfg.burst_count):
            target = sent + bytes_per_burst
            sent, total_sleep = _send_until(send_fn, chunk, sent, target, delay_s, deadline, total_sleep, cfg.batch_size, batch_delay_s)
            if sent >= cfg.bytes_c2s or monotonic() >= deadline:
                break
            if i + 1 < cfg.burst_count and cfg.burst_idle_s > 0:
                sleep(cfg.burst_idle_s)
                total_sleep += cfg.burst_idle_s
    else:
        sent, total_sleep = _send_until(send_fn, chunk, sent, cfg.bytes_c2s, delay_s, deadline, total_sleep, cfg.batch_size, batch_delay_s)

    return sent, total_sleep


def _send_until(
    send_fn: Callable[[bytes], None],
    chunk: bytes,
    sent: int,
    target: int,
    delay_s: float,
    deadline: float,
    total_sleep: float,
    batch_size: int,
    batch_delay_s: float,
) -> tuple[int, float]:
    """Drive `send_fn` toward *target* bytes.

    Pacing layers (applied independently):
      * `delay_s`        — per-packet inter-arrival time
                           (`PROFILE_IAT_C2S_MS`).
      * `batch_delay_s`  — extra sleep every `batch_size` packets
                           (`INTER_PACKET_DELAY_MS` / `DELAY_EVERY_N`),
                           the receiver-safe rate cap.
    """
    chunk_size = len(chunk)
    packets_in_batch = 0
    while sent < target and monotonic() < deadline:
        n = min(chunk_size, target - sent)
        send_fn(chunk[:n])
        sent += n
        packets_in_batch += 1
        if delay_s > 0.0:
            sleep(delay_s)
            total_sleep += delay_s
        if batch_delay_s > 0.0 and packets_in_batch >= batch_size:
            sleep(batch_delay_s)
            total_sleep += batch_delay_s
            packets_in_batch = 0
    return sent, total_sleep


# ── Async API ────────────────────────────────────────────────────────────────


async def run_profile_async(
    send_fn: Callable[[bytes], Awaitable[None] | None],
) -> tuple[int, float]:
    """Async version of `run_profile` for asyncio-based senders (QUIC).

    `send_fn` may be sync (returns `None`) or async (returns an awaitable);
    if the call returns an awaitable, the loop awaits it before pacing the
    next packet.  Returns (bytes_sent, total_sleep_s).
    """
    cfg = _read_config()
    if cfg.bytes_c2s <= 0:
        return 0, 0.0

    start = monotonic()
    deadline = start + cfg.duration_s
    chunk = _build_chunk(cfg.chunk_c2s)
    delay_s = max(0.0, cfg.iat_c2s_ms) / 1000.0
    batch_delay_s = max(0.0, cfg.inter_batch_delay_ms) / 1000.0
    sent = 0
    total_sleep = 0.0

    if cfg.bursty and cfg.burst_count > 1:
        bytes_per_burst = cfg.bytes_c2s // cfg.burst_count
        for i in range(cfg.burst_count):
            target = sent + bytes_per_burst
            sent, total_sleep = await _send_until_async(send_fn, chunk, sent, target, delay_s, deadline, total_sleep, cfg.batch_size, batch_delay_s)
            if sent >= cfg.bytes_c2s or monotonic() >= deadline:
                break
            if i + 1 < cfg.burst_count and cfg.burst_idle_s > 0:
                await asleep(cfg.burst_idle_s)
                total_sleep += cfg.burst_idle_s
    else:
        sent, total_sleep = await _send_until_async(send_fn, chunk, sent, cfg.bytes_c2s, delay_s, deadline, total_sleep, cfg.batch_size, batch_delay_s)

    return sent, total_sleep


async def _send_until_async(
    send_fn: Callable[[bytes], Awaitable[None] | None],
    chunk: bytes,
    sent: int,
    target: int,
    delay_s: float,
    deadline: float,
    total_sleep: float,
    batch_size: int,
    batch_delay_s: float,
) -> tuple[int, float]:
    """Async mirror of `_send_until`. See that function for the pacing model."""
    chunk_size = len(chunk)
    packets_in_batch = 0
    while sent < target and monotonic() < deadline:
        n = min(chunk_size, target - sent)
        result = send_fn(chunk[:n])
        if isawaitable(result):
            await result
        sent += n
        packets_in_batch += 1
        if delay_s > 0.0:
            await asleep(delay_s)
            total_sleep += delay_s
        if batch_delay_s > 0.0 and packets_in_batch >= batch_size:
            await asleep(batch_delay_s)
            total_sleep += batch_delay_s
            packets_in_batch = 0
    return sent, total_sleep
