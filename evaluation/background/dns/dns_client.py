#!/usr/bin/env python3
"""DNS query generator for the background corpus.

Sends a stream of random A/AAAA/MX/TXT queries to the server at SERVER_HOST:53,
spaced by the per-direction IATs from the active profile.  Quits after
PROFILE_DURATION_S or PROFILE_BYTES_C2S whichever fires first.
"""

from __future__ import annotations

from contextlib import suppress
from os import environ, system
from random import Random, randint
from socket import AF_INET, SOCK_DGRAM, socket, timeout
from string import ascii_lowercase
from sys import exit, path
from time import monotonic, sleep

path.insert(0, "/common")

from dnslib import QTYPE, DNSHeader, DNSQuestion, DNSRecord
from profile_env import ProfileEnv

QUERY_TYPES = (QTYPE.A, QTYPE.AAAA, QTYPE.MX, QTYPE.TXT)


def _route_setup() -> None:
    gw = environ.get("OBSERVER_GW")
    if not gw:
        return
    system(f"ip route add 172.21.0.0/24 via {gw} 2>/dev/null")  # noqa: S605


def _random_name(rng: Random) -> str:
    label = "".join(rng.choices(ascii_lowercase, k=rng.randint(6, 14)))
    return f"{label}.example.test"


def main() -> int:
    profile = ProfileEnv.from_env()
    server_host = environ["SERVER_HOST"]
    seed = int(environ.get("PROFILE_SEED", "0")) or randint(0, 1 << 30)
    rng = Random(seed)

    _route_setup()

    sock = socket(AF_INET, SOCK_DGRAM)
    sock.connect((server_host, 53))
    sock.settimeout(2.0)

    delay_s = max(profile.iat_c2s_ms, 1.0) / 1000.0
    deadline = monotonic() + profile.duration_s
    sent_bytes = 0
    queries = 0
    while monotonic() < deadline and sent_bytes < max(profile.bytes_c2s, 1):
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
        with suppress(OSError, timeout):
            sock.recv(4096)  # consume response
        sleep(delay_s)
    print(f"dns: sent {queries} queries / {sent_bytes} bytes", flush=True)
    return 0


if __name__ == "__main__":
    exit(main())
