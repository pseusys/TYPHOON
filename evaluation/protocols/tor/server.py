#!/usr/bin/env python3
import os
import socket
import ssl
import subprocess
import sys

CELL = 514
PORT = 9001  # conventional Tor ORPort


def recv_exact(sock, n):
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return bytes(buf)
        buf += chunk
    return bytes(buf)


observer_gw = os.environ.get("OBSERVER_GW")
transfer_bytes = int(os.environ.get("TRANSFER_BYTES", 104_857_600))
idle_timeout = int(os.environ.get("IDLE_TIMEOUT_S", 120))

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

ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.minimum_version = ssl.TLSVersion.TLSv1_3
ctx.load_cert_chain("/keys/tor_cert.pem", "/tmp/tor_key.pem")

raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
raw.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
raw.bind(("0.0.0.0", PORT))
raw.listen(1)
print(f"Tor OR simulator listening on :{PORT}", flush=True)

received_data = 0
DATA_PER_CELL = 498  # usable payload bytes per RELAY cell

conn, addr = raw.accept()
try:
    tls = ctx.wrap_socket(conn, server_side=True)
except ssl.SSLError as e:
    print(f"TLS handshake failed: {e}", flush=True)
    sys.exit(1)

print(f"TLS connection from {addr}", flush=True)
tls.settimeout(idle_timeout)
try:
    while received_data < transfer_bytes:
        cell = recv_exact(tls, CELL)
        if len(cell) < CELL:
            break
        received_data += DATA_PER_CELL
except (ssl.SSLError, OSError, TimeoutError):
    pass

finally:
    try:
        tls.close()
    except OSError:
        pass

pct = received_data / transfer_bytes * 100
print(f"received ~{received_data} bytes in cells ({pct:.1f}%)", flush=True)
sys.exit(0)
