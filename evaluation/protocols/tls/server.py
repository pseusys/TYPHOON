#!/usr/bin/env python3
"""
TLS 1.3 sink — generates a self-signed cert, writes it to /keys/tls_cert.pem
so the client can trust it, then receives TRANSFER_BYTES over TLS.
"""

import os
import socket
import ssl
import subprocess
import sys

observer_gw = os.environ.get("OBSERVER_GW")
transfer_bytes = int(os.environ.get("TRANSFER_BYTES", 104_857_600))
port = 9000

if observer_gw:
    subprocess.run(
        ["ip", "route", "add", "172.20.0.0/24", "via", observer_gw],
        check=False,
        capture_output=True,
    )

subprocess.run(
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

ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.minimum_version = ssl.TLSVersion.TLSv1_3
ctx.load_cert_chain("/keys/tls_cert.pem", "/tmp/tls_key.pem")

raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
raw.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
raw.bind(("0.0.0.0", port))
raw.listen(1)
print(f"TLS sink ready on :{port}", flush=True)

received = 0
while received < transfer_bytes:
    conn, _ = raw.accept()
    try:
        tls = ctx.wrap_socket(conn, server_side=True)
    except ssl.SSLError:
        conn.close()
        continue
    with tls:
        while received < transfer_bytes:
            data = tls.recv(65536)
            if not data:
                break
            received += len(data)

print(f"received {received}/{transfer_bytes} bytes", flush=True)
sys.exit(0 if received >= transfer_bytes else 1)
