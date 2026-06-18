#!/usr/bin/env python3
"""Gaming server emulating an action-game tick loop.

Emits 40-byte tick updates s2c at 16 ms IAT, receives small client commands
c2s at 30–50 ms IAT.  Runs until PROFILE_DURATION_S elapses.
"""

from __future__ import annotations

from os import environ, system, urandom
from socket import AF_INET, SOCK_DGRAM, socket
from sys import exit, path
from threading import Thread
from time import monotonic, sleep

path.insert(0, "/common")
from profile_env import ProfileEnv

LISTEN_PORT = 27015
TICK_PAYLOAD_SIZE = 40


def _route_setup() -> None:
    gw = environ.get("OBSERVER_GW")
    if not gw:
        return
    system(f"ip route add 172.20.0.0/24 via {gw} 2>/dev/null")  # noqa: S605


def _recv_loop(sock: socket, deadline: float, peer_holder: list[tuple]) -> None:
    sock.settimeout(0.2)
    while monotonic() < deadline:
        try:
            data, peer = sock.recvfrom(2048)
            if not peer_holder:
                peer_holder.append(peer)
        except TimeoutError:
            continue
        except OSError:
            break


def main() -> int:
    profile = ProfileEnv.from_env()
    _route_setup()

    sock = socket(AF_INET, SOCK_DGRAM)
    sock.bind(("0.0.0.0", LISTEN_PORT))
    print(f"gaming server listening on UDP/{LISTEN_PORT}", flush=True)

    deadline = monotonic() + profile.duration_s
    peer_holder: list[tuple] = []
    recv_thread = Thread(target=_recv_loop, args=(sock, deadline, peer_holder), daemon=True)
    recv_thread.start()

    # Wait briefly for the first c2s packet so we know where to send.
    while not peer_holder and monotonic() < deadline:
        sleep(0.05)

    if not peer_holder:
        print("gaming: no client packets received", flush=True)
        return 0

    peer = peer_holder[0]
    iat_s = max(profile.iat_s2c_ms, 16.0) / 1000.0
    payload = urandom(TICK_PAYLOAD_SIZE)
    sent = 0
    while monotonic() < deadline:
        try:
            sock.sendto(payload, peer)
            sent += 1
        except OSError:
            break
        sleep(iat_s)
    print(f"gaming server: sent {sent} ticks", flush=True)
    return 0


if __name__ == "__main__":
    exit(main())
