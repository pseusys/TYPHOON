#!/usr/bin/env python3
"""Gaming client emulating action-game commands.

Sends 60–300 B variable-size packets c2s every 30–50 ms; receives 40 B tick
updates from the server and discards them.
"""

from __future__ import annotations

import os
import random
import socket
import sys
import threading
import time

sys.path.insert(0, "/common")
from profile_env import ProfileEnv

SERVER_PORT = 27015


def _route_setup() -> None:
    gw = os.environ.get("OBSERVER_GW")
    if not gw:
        return
    os.system(f"ip route add 172.21.0.0/24 via {gw} 2>/dev/null")  # noqa: S605


def _recv_loop(sock: socket.socket, deadline: float) -> None:
    sock.settimeout(0.2)
    while time.monotonic() < deadline:
        try:
            sock.recv(2048)
        except (socket.timeout, OSError):
            continue


def main() -> int:
    profile = ProfileEnv.from_env()
    server_host = os.environ["SERVER_HOST"]
    seed = int(os.environ.get("PROFILE_SEED", "0")) or random.randint(0, 1 << 30)
    rng = random.Random(seed)

    _route_setup()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.connect((server_host, SERVER_PORT))

    deadline = time.monotonic() + profile.duration_s
    threading.Thread(target=_recv_loop, args=(sock, deadline), daemon=True).start()

    iat_min_ms = max(profile.iat_c2s_ms, 30.0)
    iat_max_ms = max(iat_min_ms + 20.0, 50.0)

    # Pre-allocate a max-size random buffer; per-packet slice gives variable
    # length without paying os.urandom() cost on the hot path.
    rand_pool = os.urandom(300)
    sent = 0
    while time.monotonic() < deadline:
        size = rng.randint(60, 300)
        try:
            sock.send(rand_pool[:size])
            sent += 1
        except OSError:
            break
        time.sleep(rng.uniform(iat_min_ms, iat_max_ms) / 1000.0)
    print(f"gaming client: sent {sent} packets", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
