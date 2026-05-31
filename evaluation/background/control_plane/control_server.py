#!/usr/bin/env python3
"""Generic UDP echo/responder for the long-tail UDP control-plane class.

Listens on UDP/123 (NTP-like) and UDP/3478 (STUN-like) and echoes any
inbound datagram, padded to a small response size, until duration_s elapses.
"""

from __future__ import annotations

from contextlib import suppress
from os import environ, system, urandom
from socket import AF_INET, SOCK_DGRAM, socket, timeout
from sys import exit, path
from threading import Thread
from time import monotonic, sleep

path.insert(0, "/common")

from profile_env import ProfileEnv

PORTS_AND_RESPONSE_SIZES = [
    (123, 76),    # NTP-like
    (3478, 96),   # STUN-like
    (5353, 200),  # mDNS-like
]


def _route_setup() -> None:
    gw = environ.get("OBSERVER_GW")
    if not gw:
        return
    system(f"ip route add 172.20.0.0/24 via {gw} 2>/dev/null")  # noqa: S605


def _serve(port: int, response_size: int, deadline: float) -> None:
    sock = socket(AF_INET, SOCK_DGRAM)
    sock.bind(("0.0.0.0", port))
    sock.settimeout(0.2)
    response = urandom(response_size)
    while monotonic() < deadline:
        try:
            with suppress(timeout):
                _, peer = sock.recvfrom(2048)
                sock.sendto(response, peer)
        except OSError:
            break


def main() -> int:
    profile = ProfileEnv.from_env()
    _route_setup()
    deadline = monotonic() + profile.duration_s
    for port, size in PORTS_AND_RESPONSE_SIZES:
        Thread(target=_serve, args=(port, size, deadline), daemon=True).start()
    print(f"control-plane server: listening on {[p for p, _ in PORTS_AND_RESPONSE_SIZES]}", flush=True)
    while monotonic() < deadline:
        sleep(0.5)
    return 0


if __name__ == "__main__":
    exit(main())
