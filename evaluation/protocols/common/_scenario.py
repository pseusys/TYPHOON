#!/usr/bin/env python3
"""Shared traffic-scenario execution for TCP and UDP evaluation senders."""

import time
from typing import Callable


def run_scenario(
    scenario: str,
    send_fn: Callable[[bytes], None],
    transfer_bytes: int,
    delay_ms: float = 0.0,
    delay_every: int = 1,
) -> tuple[int, float]:
    """Execute *scenario* using *send_fn*.  Returns (bytes_sent, total_sleep_s)."""
    sent = 0
    total_sleep = 0.0

    if scenario in ("bulk", "echo"):
        chunk_size = 500
        chunk = bytes(chunk_size)
        packets = 0
        while sent < transfer_bytes:
            n = min(chunk_size, transfer_bytes - sent)
            send_fn(chunk[:n])
            sent += n
            packets += 1
            if delay_ms > 0 and packets % delay_every == 0:
                time.sleep(delay_ms / 1000)
                total_sleep += delay_ms / 1000

    elif scenario == "interactive":
        chunk_size = 50
        chunk = bytes(chunk_size)
        while sent < transfer_bytes:
            n = min(chunk_size, transfer_bytes - sent)
            send_fn(chunk[:n])
            sent += n
            time.sleep(0.1)
            total_sleep += 0.1

    elif scenario == "streaming":
        chunk_size = 1250
        chunk = bytes(chunk_size)
        while sent < transfer_bytes:
            n = min(chunk_size, transfer_bytes - sent)
            send_fn(chunk[:n])
            sent += n
            time.sleep(0.01)
            total_sleep += 0.01

    elif scenario == "burst":
        burst_size = max(transfer_bytes // 3, 1)
        chunk_size = 4096
        chunk = bytes(chunk_size)
        for burst_idx in range(3):
            burst_target = min(burst_size, transfer_bytes - sent)
            burst_sent = 0
            while burst_sent < burst_target:
                n = min(chunk_size, burst_target - burst_sent)
                send_fn(chunk[:n])
                burst_sent += n
            sent += burst_sent
            if burst_idx < 2 and sent < transfer_bytes:
                time.sleep(10.0)
                total_sleep += 10.0

    elif scenario == "idle":
        send_fn(b"\x00" * 8)
        sent = 8
        time.sleep(30.0)
        total_sleep += 30.0

    else:
        print(f"unknown scenario {scenario!r}, falling back to bulk", flush=True)
        chunk_size = 500
        chunk = bytes(chunk_size)
        while sent < transfer_bytes:
            n = min(chunk_size, transfer_bytes - sent)
            send_fn(chunk[:n])
            sent += n

    return sent, total_sleep
