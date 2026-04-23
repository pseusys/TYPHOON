#!/usr/bin/env python3
import os
import socket
import sys

transfer_bytes = int(os.environ.get("TRANSFER_BYTES", 104_857_600))
idle_timeout = int(os.environ.get("IDLE_TIMEOUT_S", 10))
port = 9000

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(("0.0.0.0", port))
sock.settimeout(idle_timeout)
print(f"UDP sink ready on :{port}", flush=True)

received = 0
while received < transfer_bytes:
    try:
        data, _ = sock.recvfrom(65536)
    except socket.timeout:
        break
    if data == b"DONE":
        break
    received += len(data)

pct = received / transfer_bytes * 100
print(f"received {received}/{transfer_bytes} bytes ({pct:.1f}%)", flush=True)
sys.exit(0)
