#!/usr/bin/env python3
"""Gaming client emulating action-game commands.

Sends 60–300 B variable-size packets c2s every 30–50 ms; receives 40 B tick
updates from the server and discards them.
"""

from __future__ import annotations

from os import environ, system, urandom
from random import Random, randint
from socket import AF_INET, SOCK_DGRAM, socket, timeout
from sys import exit, path
from threading import Thread
from time import monotonic, sleep

path.insert(0, "/common")
from profile_env import ProfileEnv

SERVER_PORT = 27015


def _route_setup() -> None:
    gw = environ.get("OBSERVER_GW")
    if not gw:
        return
    system(f"ip route add 172.21.0.0/24 via {gw} 2>/dev/null")  # noqa: S605


def _recv_loop(sock: socket, deadline: float) -> None:
    sock.settimeout(0.2)
    while monotonic() < deadline:
        try:
            sock.recv(2048)
        except (timeout, OSError):
            continue


def main() -> int:
    profile = ProfileEnv.from_env()
    server_host = environ["SERVER_HOST"]
    seed = int(environ.get("PROFILE_SEED", "0")) or randint(0, 1 << 30)
    rng = Random(seed)

    _route_setup()

    sock = socket(AF_INET, SOCK_DGRAM)
    sock.connect((server_host, SERVER_PORT))

    deadline = monotonic() + profile.duration_s
    Thread(target=_recv_loop, args=(sock, deadline), daemon=True).start()

    iat_min_ms = max(profile.iat_c2s_ms, 30.0)
    iat_max_ms = max(iat_min_ms + 20.0, 50.0)

    # Pre-allocate a max-size random buffer; per-packet slice gives variable
    # length without paying urandom() cost on the hot path.
    rand_pool = urandom(300)
    sent = 0
    while monotonic() < deadline:
        size = rng.randint(60, 300)
        try:
            sock.send(rand_pool[:size])
            sent += 1
        except OSError:
            break
        sleep(rng.uniform(iat_min_ms, iat_max_ms) / 1000.0)
    print(f"gaming client: sent {sent} packets", flush=True)
    return 0


if __name__ == "__main__":
    exit(main())
