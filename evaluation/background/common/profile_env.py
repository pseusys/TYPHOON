#!/usr/bin/env python3
"""Shared profile-env reader for background generator scripts.

Each generator container receives the same `PROFILE_*` env vars as the
TYPHOON containers; this module parses them into a dataclass.
"""

from __future__ import annotations

from dataclasses import dataclass
from os import environ


def _env_int(key: str, default: int) -> int:
    raw = environ.get(key)
    return int(raw) if raw is not None and raw.strip() else default


def _env_float(key: str, default: float) -> float:
    raw = environ.get(key)
    return float(raw) if raw is not None and raw.strip() else default


@dataclass(frozen=True)
class ProfileEnv:
    """Per-run profile parameters delivered via container environment variables."""

    name: str
    chunk_c2s: int
    chunk_s2c: int
    iat_c2s_ms: float
    iat_s2c_ms: float
    bytes_c2s: int
    bytes_s2c: int
    duration_s: float
    bursty: bool
    burst_count: int
    burst_idle_s: float

    @classmethod
    def from_env(cls) -> ProfileEnv:
        return cls(
            name=environ.get("TRAFFIC_PROFILE", "bulk_upload"),
            chunk_c2s=max(1, _env_int("PROFILE_CHUNK_C2S", 500)),
            chunk_s2c=max(1, _env_int("PROFILE_CHUNK_S2C", 0)),
            iat_c2s_ms=max(0.0, _env_float("PROFILE_IAT_C2S_MS", 0.0)),
            iat_s2c_ms=max(0.0, _env_float("PROFILE_IAT_S2C_MS", 0.0)),
            bytes_c2s=_env_int("PROFILE_BYTES_C2S", 10_485_760),
            bytes_s2c=_env_int("PROFILE_BYTES_S2C", 0),
            duration_s=max(1.0, _env_float("PROFILE_DURATION_S", 30.0)),
            bursty=_env_int("PROFILE_BURSTY", 0) != 0,
            burst_count=max(1, _env_int("PROFILE_BURST_COUNT", 1)),
            burst_idle_s=max(0.0, _env_float("PROFILE_BURST_IDLE_S", 0.0)),
        )
