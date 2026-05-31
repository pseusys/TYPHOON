#!/usr/bin/env python3
"""Sparse multi-port UDP control-plane sender.

Sends small UDP packets to the control_plane server on NTP/STUN/mDNS-like
ports at sparse intervals (1–10 s) for the duration of the run.
"""

from __future__ import annotations

from contextlib import suppress
from os import environ, system, urandom
from random import Random, randint
from socket import AF_INET, SOCK_DGRAM, socket, timeout
from sys import exit, path
from time import monotonic, sleep

path.insert(0, "/common")

from profile_env import ProfileEnv

PORTS_AND_QUERY_SIZES = [
    (123, 48),    # NTP-like
    (3478, 60),   # STUN-like
    (5353, 100),  # mDNS-like
]


def _route_setup() -> None:
    gw = environ.get("OBSERVER_GW")
    if not gw:
        return
    system(f"ip route add 172.21.0.0/24 via {gw} 2>/dev/null")  # noqa: S605


def main() -> int:
    profile = ProfileEnv.from_env()
    server_host = environ["SERVER_HOST"]
    seed = int(environ.get("PROFILE_SEED", "0")) or randint(0, 1 << 30)
    rng = Random(seed)

    _route_setup()

    sockets = []
    for port, size in PORTS_AND_QUERY_SIZES:
        s = socket(AF_INET, SOCK_DGRAM)
        s.connect((server_host, port))
        s.settimeout(1.0)
        sockets.append((s, size, port))

    deadline = monotonic() + profile.duration_s
    # Pre-allocated random pool sliced per-packet — avoids zero-payload entropy fingerprint.
    rand_pool = urandom(max(s for _, s in PORTS_AND_QUERY_SIZES))
    sent = 0
    while monotonic() < deadline:
        sock, size, port = rng.choice(sockets)
        with suppress(OSError):
            sock.send(rand_pool[:size])
            sent += 1
            with suppress(OSError, timeout):
                sock.recv(2048)
        sleep(rng.uniform(1.0, 10.0))
    print(f"control-plane client: sent {sent} packets", flush=True)
    return 0


if __name__ == "__main__":
    exit(main())
