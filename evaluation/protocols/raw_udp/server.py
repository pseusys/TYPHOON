#!/usr/bin/env python3
import os
import socket
import subprocess
import sys

observer_gw = os.environ.get("OBSERVER_GW")
transfer_bytes = int(os.environ.get("TRANSFER_BYTES", 104_857_600))
initial_timeout = int(os.environ.get("INITIAL_TIMEOUT_S", 60))
idle_timeout = int(os.environ.get("IDLE_TIMEOUT_S", 30))
port = 9000

if observer_gw:
    subprocess.run(
        ["ip", "route", "add", "172.20.0.0/24", "via", observer_gw],
        check=False,
        capture_output=True,
    )

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(("0.0.0.0", port))
sock.settimeout(initial_timeout)
print(f"UDP sink ready on :{port}", flush=True)

received = 0
first = True
while received < transfer_bytes:
    try:
        data, _ = sock.recvfrom(65536)
    except socket.timeout:
        break
    if first:
        first = False
        sock.settimeout(idle_timeout)
    if data == b"DONE":
        break
    received += len(data)

pct = received / transfer_bytes * 100
print(f"received {received}/{transfer_bytes} bytes ({pct:.1f}%)", flush=True)
sys.exit(0)
