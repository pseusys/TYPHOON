#!/usr/bin/env python3
import os
import socket
import subprocess
import sys
import time

observer_gw = os.environ.get("OBSERVER_GW")
server_host = os.environ["SERVER_HOST"]
transfer_bytes = int(os.environ.get("TRANSFER_BYTES", 104_857_600))
port = 9000
chunk_size = 1400  # stays well under Ethernet MTU

if observer_gw:
    subprocess.run(
        ["ip", "route", "add", "172.21.0.0/24", "via", observer_gw],
        check=False,
        capture_output=True,
    )

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.connect((server_host, port))

# Brief pause so the server socket is definitely bound before first packet.
time.sleep(0.2)

chunk = bytes(chunk_size)
sent = 0
while sent < transfer_bytes:
    n = min(chunk_size, transfer_bytes - sent)
    sock.send(chunk[:n])
    sent += n

sock.send(b"DONE")
print(f"sent {sent} bytes", flush=True)
sys.exit(0)
