#!/usr/bin/env python3
"""Symmetric RTP voice generator (~200 B every 20 ms, 50 pps each direction).

Both client and server run this same script.  The role determines the
listening port and the peer port.  After ROLE-specific socket setup, both
sides emit RTP packets at the profile's IAT and consume incoming RTP from
the other side until the duration cap.
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

CLIENT_PORT = 5004
SERVER_PORT = 5006
RTP_HEADER_SIZE = 12
DEFAULT_PAYLOAD_SIZE = 160  # G.711 sample chunk, becomes 172 B with RTP header.


def _route_setup(role: str) -> None:
    gw = os.environ.get("OBSERVER_GW")
    if not gw:
        return
    target = "172.21.0.0/24" if role == "client" else "172.20.0.0/24"
    os.system(f"ip route add {target} via {gw} 2>/dev/null")  # noqa: S605


def _build_rtp(seq: int, ts: int, ssrc: int, payload: bytes) -> bytes:
    flags = (2 << 6)  # version 2, no padding/extension/CSRC
    payload_type = 0  # PCMU / G.711
    header = bytes([flags, payload_type, (seq >> 8) & 0xFF, seq & 0xFF])
    header += ts.to_bytes(4, "big") + ssrc.to_bytes(4, "big")
    return header + payload


def _recv_loop(sock: socket.socket, deadline: float) -> None:
    sock.settimeout(0.2)
    while time.monotonic() < deadline:
        try:
            sock.recv(2048)
        except (socket.timeout, OSError):
            continue


def main() -> int:
    role = os.environ.get("ROLE", "client").lower()
    profile = ProfileEnv.from_env()
    seed = int(os.environ.get("PROFILE_SEED", "0")) or random.randint(0, 1 << 30)
    rng = random.Random(seed)

    _route_setup(role)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    if role == "client":
        sock.bind(("0.0.0.0", CLIENT_PORT))
        peer_addr = (os.environ["SERVER_HOST"], SERVER_PORT)
    else:
        sock.bind(("0.0.0.0", SERVER_PORT))
        peer_addr = (os.environ.get("CLIENT_HOST", "0.0.0.0"), CLIENT_PORT)

    deadline = time.monotonic() + profile.duration_s
    iat_ms = profile.iat_c2s_ms if role == "client" else profile.iat_s2c_ms
    iat_s = max(iat_ms, 20.0) / 1000.0
    payload_size = max(DEFAULT_PAYLOAD_SIZE, profile.chunk_c2s if role == "client" else profile.chunk_s2c) - RTP_HEADER_SIZE
    payload_size = max(payload_size, 1)

    threading.Thread(target=_recv_loop, args=(sock, deadline), daemon=True).start()

    ssrc = rng.randint(0, 0xFFFFFFFF)
    seq = rng.randint(0, 0xFFFF)
    ts = rng.randint(0, 0xFFFFFFFF)
    # Voice payload bytes are constant per call (fixed codec output rate).
    # Encrypted-or-encoded media is high-entropy on the wire, so random fill.
    payload = os.urandom(payload_size)
    sent = 0
    while time.monotonic() < deadline:
        try:
            sock.sendto(_build_rtp(seq, ts, ssrc, payload), peer_addr)
            sent += 1
        except OSError:
            break
        seq = (seq + 1) & 0xFFFF
        ts = (ts + payload_size) & 0xFFFFFFFF
        time.sleep(iat_s)
    print(f"rtp_voice {role}: sent {sent} packets", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
