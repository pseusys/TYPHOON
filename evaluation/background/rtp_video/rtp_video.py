#!/usr/bin/env python3
"""Symmetric RTP video generator (~1100 B at 30 fps frame bursts).

Each frame is 1–20 packets emitted in a tight burst, then a ~33 ms idle gap.
Packet sizes draw from N(1100, 100) clamped to [600, 1200].
"""

from __future__ import annotations

from os import environ, system, urandom
from random import Random, randint
from socket import AF_INET, SOCK_DGRAM, socket
from sys import exit, path
from threading import Thread
from time import monotonic, sleep

path.insert(0, "/common")
from profile_env import ProfileEnv

CLIENT_PORT = 5104
SERVER_PORT = 5106
RTP_HEADER_SIZE = 12
FRAME_INTERVAL_S = 1.0 / 30.0
PACKETS_PER_FRAME_RANGE = (1, 20)
PACKET_SIZE_MEAN = 1100
PACKET_SIZE_STD = 100
PACKET_SIZE_MIN = 600
PACKET_SIZE_MAX = 1200


def _route_setup(role: str) -> None:
    gw = environ.get("OBSERVER_GW")
    if not gw:
        return
    target = "172.21.0.0/24" if role == "client" else "172.20.0.0/24"
    system(f"ip route add {target} via {gw} 2>/dev/null")  # noqa: S605


def _build_rtp(seq: int, ts: int, ssrc: int, payload: bytes, marker: bool) -> bytes:
    flags = (2 << 6)
    payload_type = (0x80 if marker else 0) | 96  # dynamic PT 96 = video
    header = bytes([flags, payload_type, (seq >> 8) & 0xFF, seq & 0xFF])
    header += ts.to_bytes(4, "big") + ssrc.to_bytes(4, "big")
    return header + payload


def _recv_loop(sock: socket, deadline: float) -> None:
    sock.settimeout(0.2)
    while monotonic() < deadline:
        try:
            sock.recv(2048)
        except (TimeoutError, OSError):
            continue


def main() -> int:
    role = environ.get("ROLE", "client").lower()
    profile = ProfileEnv.from_env()
    seed = int(environ.get("PROFILE_SEED", "0")) or randint(0, 1 << 30)
    rng = Random(seed)

    _route_setup(role)

    sock = socket(AF_INET, SOCK_DGRAM)
    if role == "client":
        sock.bind(("0.0.0.0", CLIENT_PORT))
        peer_addr = (environ["SERVER_HOST"], SERVER_PORT)
    else:
        sock.bind(("0.0.0.0", SERVER_PORT))
        peer_addr = (environ.get("CLIENT_HOST", "0.0.0.0"), CLIENT_PORT)

    deadline = monotonic() + profile.duration_s
    Thread(target=_recv_loop, args=(sock, deadline), daemon=True).start()

    ssrc = rng.randint(0, 0xFFFFFFFF)
    seq = rng.randint(0, 0xFFFF)
    ts = rng.randint(0, 0xFFFFFFFF)
    # H.264-encoded NAL units are high-entropy on the wire — pre-allocate a
    # max-size random buffer and slice it per-packet to avoid the cost of
    # generating random bytes on the hot path.
    rand_pool = urandom(PACKET_SIZE_MAX)
    sent = 0
    while monotonic() < deadline:
        n_pkts = rng.randint(*PACKETS_PER_FRAME_RANGE)
        for i in range(n_pkts):
            size = int(rng.gauss(PACKET_SIZE_MEAN, PACKET_SIZE_STD))
            size = max(PACKET_SIZE_MIN, min(size, PACKET_SIZE_MAX))
            payload_size = max(size - RTP_HEADER_SIZE, 1)
            try:
                sock.sendto(_build_rtp(seq, ts, ssrc, rand_pool[:payload_size], marker=(i == n_pkts - 1)), peer_addr)
                sent += 1
            except OSError:
                deadline = 0.0
                break
            seq = (seq + 1) & 0xFFFF
        ts = (ts + 3000) & 0xFFFFFFFF  # 90 kHz clock × 33 ms
        sleep_s = FRAME_INTERVAL_S * rng.uniform(0.85, 1.15)
        sleep(sleep_s)
    print(f"rtp_video {role}: sent {sent} packets", flush=True)
    return 0


if __name__ == "__main__":
    exit(main())
