#!/usr/bin/env python3
"""Minimal DNS authoritative server for the background corpus.

Listens on UDP/53 and answers any query with a synthetic A or TXT record
sized to the query type (so DNSSEC-style large responses are exercised).
Uses dnslib so no external resolver is required inside the container.
"""

from __future__ import annotations

from os import environ, system
from socket import AF_INET, SOCK_DGRAM, socket
from sys import exit

from dnslib import AAAA, QTYPE, RR, TXT, A, DNSHeader, DNSRecord

LISTEN_PORT = 53
TXT_TOTAL_BYTES = 1100      # produces ~1200 B response (split across <255-byte chunks)
TXT_CHUNK_BYTES = 200       # under the 255-byte per-character-string limit
MAX_DURATION_SAFETY_S = 600


def _route_setup() -> None:
    gw = environ.get("OBSERVER_GW")
    if not gw:
        return
    system(f"ip route add 172.20.0.0/24 via {gw} 2>/dev/null")  # noqa: S605


def _txt_chunks() -> list[str]:
    return ["x" * TXT_CHUNK_BYTES for _ in range(TXT_TOTAL_BYTES // TXT_CHUNK_BYTES)]


def _answer(query: DNSRecord) -> bytes:
    qname = query.q.qname
    qtype = QTYPE[query.q.qtype]
    reply = DNSRecord(DNSHeader(id=query.header.id, qr=1, aa=1, ra=0), q=query.q)
    if qtype == "TXT":
        reply.add_answer(RR(qname, QTYPE.TXT, rdata=TXT(_txt_chunks()), ttl=60))
    elif qtype == "AAAA":
        reply.add_answer(RR(qname, QTYPE.AAAA, rdata=AAAA("::1"), ttl=60))
    else:
        reply.add_answer(RR(qname, QTYPE.A, rdata=A("203.0.113.5"), ttl=60))
    return reply.pack()


def main() -> int:
    _route_setup()
    sock = socket(AF_INET, SOCK_DGRAM)
    sock.bind(("0.0.0.0", LISTEN_PORT))
    sock.settimeout(MAX_DURATION_SAFETY_S)
    print(f"dns server listening on UDP/{LISTEN_PORT}", flush=True)
    while True:
        try:
            data, peer = sock.recvfrom(4096)
        except TimeoutError:
            break
        try:
            query = DNSRecord.parse(data)
            reply = _answer(query)
            sock.sendto(reply, peer)
        except Exception as e:
            print(f"dns: parse error from {peer}: {e}", flush=True)
    return 0


if __name__ == "__main__":
    exit(main())
