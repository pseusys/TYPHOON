#!/usr/bin/env python3
"""Profile-driven traffic execution for non-TYPHOON evaluation senders.

Reads PROFILE_* env vars (written by the evaluation orchestrator) to drive
the c2s portion of any profile from `shared/profiles.py`.  Non-TYPHOON
protocols cannot drive bidirectional s2c traffic without changes to the
underlying server image, so the s2c portion of any profile is silently
ignored on this side.
"""

from collections.abc import Callable
from os import environ, urandom
from time import monotonic, sleep


def _env_int(key: str, default: int) -> int:
    raw = environ.get(key)
    return int(raw) if raw is not None and raw.strip() else default


def _env_float(key: str, default: float) -> float:
    raw = environ.get(key)
    return float(raw) if raw is not None and raw.strip() else default


def run_profile(send_fn: Callable[[bytes], None]) -> tuple[int, float]:
    """Execute the c2s portion of the active profile using *send_fn*.

    Returns (bytes_sent, total_sleep_s).
    """
    chunk_c2s     = max(1, _env_int("PROFILE_CHUNK_C2S", 500))
    iat_c2s_ms    = _env_float("PROFILE_IAT_C2S_MS", 0.0)
    bytes_c2s     = _env_int("PROFILE_BYTES_C2S", 10_485_760)
    duration_s    = _env_float("PROFILE_DURATION_S", 60.0)
    bursty        = _env_int("PROFILE_BURSTY", 0) != 0
    burst_count   = max(1, _env_int("PROFILE_BURST_COUNT", 1))
    burst_idle_s  = _env_float("PROFILE_BURST_IDLE_S", 0.0)

    if bytes_c2s <= 0:
        return 0, 0.0

    start = monotonic()
    deadline = start + duration_s
    # Fill the chunk buffer with random bytes once so subsequent slices look
    # like compressed/encrypted application data; sending all-zero payloads
    # would let a passive observer split flows by trivial byte-entropy alone.
    chunk = urandom(chunk_c2s)

    sent = 0
    total_sleep = 0.0
    delay_s = max(0.0, iat_c2s_ms) / 1000.0

    if bursty and burst_count > 1:
        bytes_per_burst = bytes_c2s // burst_count
        for i in range(burst_count):
            target = sent + bytes_per_burst
            sent, total_sleep = _send_until(send_fn, chunk, sent, target, delay_s, deadline, total_sleep)
            if sent >= bytes_c2s or monotonic() >= deadline:
                break
            if i + 1 < burst_count and burst_idle_s > 0:
                sleep(burst_idle_s)
                total_sleep += burst_idle_s
    else:
        sent, total_sleep = _send_until(send_fn, chunk, sent, bytes_c2s, delay_s, deadline, total_sleep)

    return sent, total_sleep


def _send_until(
    send_fn: Callable[[bytes], None],
    chunk: bytes,
    sent: int,
    target: int,
    delay_s: float,
    deadline: float,
    total_sleep: float,
) -> tuple[int, float]:
    """Drive `send_fn` toward *target* bytes, respecting *delay_s* IAT and *deadline*."""
    chunk_size = len(chunk)
    while sent < target and monotonic() < deadline:
        n = min(chunk_size, target - sent)
        send_fn(chunk[:n])
        sent += n
        if delay_s > 0.0:
            sleep(delay_s)
            total_sleep += delay_s
    return sent, total_sleep
