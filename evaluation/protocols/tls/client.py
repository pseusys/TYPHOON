#!/usr/bin/env python3
"""
TLS 1.3 sender — waits for /keys/tls_cert.pem from the server, then sends
TRANSFER_BYTES over TLS using that cert as the trusted CA.
"""

import os
import socket
import ssl
import subprocess
import sys
import time

observer_gw = os.environ.get("OBSERVER_GW")
server_host = os.environ["SERVER_HOST"]
transfer_bytes = int(os.environ.get("TRANSFER_BYTES", 104_857_600))
port = 9000
retries = 30
chunk_size = 500
delay_ms = float(os.environ.get("INTER_PACKET_DELAY_MS", 0))
delay_every = int(os.environ.get("DELAY_EVERY_N", 1))

if observer_gw:
    subprocess.run(
        ["ip", "route", "add", "172.21.0.0/24", "via", observer_gw],
        check=False,
        capture_output=True,
    )

# Wait for server cert
for _ in range(retries):
    if os.path.exists("/keys/tls_cert.pem"):
        break
    time.sleep(1)
else:
    print("tls_cert.pem never appeared", flush=True)
    sys.exit(1)

ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
ctx.minimum_version = ssl.TLSVersion.TLSv1_3
ctx.load_verify_locations("/keys/tls_cert.pem")
ctx.check_hostname = False

chunk = bytes(chunk_size)
for _attempt in range(retries):
    try:
        raw = socket.create_connection((server_host, port), timeout=5)
        raw.settimeout(None)
        tls = ctx.wrap_socket(raw, server_hostname="tls-eval")
        sent = 0
        packets = 0
        while sent < transfer_bytes:
            n = min(chunk_size, transfer_bytes - sent)
            tls.sendall(chunk[:n])
            sent += n
            packets += 1
            if delay_ms > 0 and packets % delay_every == 0:
                time.sleep(delay_ms / 1000)
        try:
            raw2 = tls.unwrap()
        except (ssl.SSLError, OSError):
            raw2 = raw
        try:
            raw2.shutdown(socket.SHUT_WR)
            raw2.settimeout(120)
            while raw2.recv(65536):
                pass
        except OSError:
            pass
        finally:
            try:
                raw2.close()
            except OSError:
                pass
        print(f"sent {sent} bytes", flush=True)
        sys.exit(0)
    except (ConnectionRefusedError, OSError, ssl.SSLError):
        time.sleep(1)

sys.exit(1)
