#!/usr/bin/env python3
import os
import socket
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

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(("0.0.0.0", port))
print(f"UDP sink ready on :{port}", flush=True)

received = 0
while received < transfer_bytes:
    data, _ = sock.recvfrom(65536)
    if data == b"DONE":
        break
    received += len(data)

print(f"received {received}/{transfer_bytes} bytes", flush=True)
sys.exit(0 if received >= transfer_bytes else 1)
