#!/usr/bin/env python3
"""
TLS 1.3 sink — generates a self-signed cert, writes it to /keys/tls_cert.pem
so the client can trust it, then receives PROFILE_BYTES_C2S over TLS.
"""

from contextlib import suppress
from os import environ
from socket import AF_INET, SO_REUSEADDR, SOCK_STREAM, SOL_SOCKET, socket
from ssl import PROTOCOL_TLS_SERVER, SSLContext, SSLError, TLSVersion
from subprocess import run
from sys import exit

observer_gw = environ.get("OBSERVER_GW")
transfer_bytes = int(environ.get("PROFILE_BYTES_C2S", 104_857_600))
idle_timeout = int(environ.get("IDLE_TIMEOUT_S", 120))
port = 9000

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
        "/tmp/tls_key.pem",
        "-out",
        "/keys/tls_cert.pem",
        "-days",
        "1",
        "-nodes",
        "-subj",
        "/CN=tls-eval",
    ],
    check=True,
    capture_output=True,
)

ctx = SSLContext(PROTOCOL_TLS_SERVER)
ctx.minimum_version = TLSVersion.TLSv1_3
ctx.load_cert_chain("/keys/tls_cert.pem", "/tmp/tls_key.pem")

raw = socket(AF_INET, SOCK_STREAM)
raw.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
raw.bind(("0.0.0.0", port))
raw.listen(1)
print(f"TLS sink ready on :{port}", flush=True)

conn, _ = raw.accept()
try:
    tls = ctx.wrap_socket(conn, server_side=True)
except SSLError as e:
    print(f"TLS handshake failed: {e}", flush=True)
    exit(1)

tls.settimeout(idle_timeout)
received = 0
with suppress(SSLError, OSError, TimeoutError):
    while received < transfer_bytes:
        data = tls.recv(65536)
        if not data:
            break
        received += len(data)
with suppress(OSError):
    tls.close()

pct = received / transfer_bytes * 100
print(f"received {received}/{transfer_bytes} bytes ({pct:.1f}%)", flush=True)
exit(0)
