#!/usr/bin/env python3
from contextlib import suppress
from os import environ
from socket import AF_INET, SO_REUSEADDR, SOCK_STREAM, SOL_SOCKET, socket
from ssl import PROTOCOL_TLS_SERVER, SSLContext, SSLError, TLSVersion
from struct import unpack
from subprocess import run
from sys import exit

CELL = 514
PORT = 9001  # conventional Tor ORPort
LENGTH_OFFSET = 14


def recv_exact(sock: socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return bytes(buf)
        buf += chunk
    return bytes(buf)


observer_gw = environ.get("OBSERVER_GW")
transfer_bytes = int(environ.get("PROFILE_BYTES_C2S", 104_857_600))
idle_timeout = int(environ.get("IDLE_TIMEOUT_S", 120))

if observer_gw:
    run(
        ["ip", "route", "add", "172.20.0.0/24", "via", observer_gw],
        check=False,
        capture_output=True,
    )

run(
    [
        "openssl",
        "req",
        "-x509",
        "-newkey",
        "rsa:2048",
        "-keyout",
        "/tmp/tor_key.pem",
        "-out",
        "/keys/tor_cert.pem",
        "-days",
        "1",
        "-nodes",
        "-subj",
        "/CN=tor-eval",
    ],
    check=True,
    capture_output=True,
)

ctx = SSLContext(PROTOCOL_TLS_SERVER)
ctx.minimum_version = TLSVersion.TLSv1_3
ctx.load_cert_chain("/keys/tor_cert.pem", "/tmp/tor_key.pem")

raw = socket(AF_INET, SOCK_STREAM)
raw.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
raw.bind(("0.0.0.0", PORT))
raw.listen(1)
print(f"Tor OR simulator listening on :{PORT}", flush=True)

received_data = 0
DATA_PER_CELL = 498  # usable payload bytes per RELAY cell

conn, addr = raw.accept()
try:
    tls = ctx.wrap_socket(conn, server_side=True)
except SSLError as e:
    print(f"TLS handshake failed: {e}", flush=True)
    exit(1)

print(f"TLS connection from {addr}", flush=True)
tls.settimeout(idle_timeout)

with suppress(SSLError, OSError, TimeoutError):
    while received_data < transfer_bytes:
        cell = recv_exact(tls, CELL)
        if len(cell) < CELL:
            break
        (length,) = unpack("!H", cell[LENGTH_OFFSET:LENGTH_OFFSET + 2])
        received_data += min(length, DATA_PER_CELL)

with suppress(OSError):
    tls.close()

pct = received_data / transfer_bytes * 100
print(f"received ~{received_data} bytes in cells ({pct:.1f}%)", flush=True)
exit(0)
