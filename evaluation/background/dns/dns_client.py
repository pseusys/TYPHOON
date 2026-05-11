#!/usr/bin/env python3
"""DNS query generator for the background corpus.

Sends a stream of random A/AAAA/MX/TXT queries to the server at SERVER_HOST:53,
spaced by the per-direction IATs from the active profile.  Quits after
PROFILE_DURATION_S or PROFILE_BYTES_C2S whichever fires first.
"""

from __future__ import annotations

import os
import random
import socket
import string
import sys
import time

sys.path.insert(0, "/common")
from dnslib import QTYPE, DNSHeader, DNSQuestion, DNSRecord
from profile_env import ProfileEnv

QUERY_TYPES = (QTYPE.A, QTYPE.AAAA, QTYPE.MX, QTYPE.TXT)


def _route_setup() -> None:
    gw = os.environ.get("OBSERVER_GW")
    if not gw:
        return
    os.system(f"ip route add 172.21.0.0/24 via {gw} 2>/dev/null")  # noqa: S605


def _random_name(rng: random.Random) -> str:
    label = "".join(rng.choices(string.ascii_lowercase, k=rng.randint(6, 14)))
    return f"{label}.example.test"


def main() -> int:
    profile = ProfileEnv.from_env()
    server_host = os.environ["SERVER_HOST"]
    seed = int(os.environ.get("PROFILE_SEED", "0")) or random.randint(0, 1 << 30)
    rng = random.Random(seed)

    _route_setup()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.connect((server_host, 53))
    sock.settimeout(2.0)

    delay_s = max(profile.iat_c2s_ms, 1.0) / 1000.0
    deadline = time.monotonic() + profile.duration_s
    sent_bytes = 0
    queries = 0
    while time.monotonic() < deadline and sent_bytes < max(profile.bytes_c2s, 1):
        qtype = rng.choice(QUERY_TYPES)
        name = _random_name(rng)
        q = DNSRecord(DNSHeader(id=rng.randint(0, 0xFFFF), rd=1), q=DNSQuestion(name, qtype))
        wire = q.pack()
        try:
            sock.send(wire)
            sent_bytes += len(wire)
            queries += 1
        except OSError:
            break
        try:
            sock.recv(4096)  # consume response
        except (OSError, socket.timeout):
            pass
        time.sleep(delay_s)
    print(f"dns: sent {queries} queries / {sent_bytes} bytes", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
