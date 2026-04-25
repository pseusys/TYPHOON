#!/usr/bin/env python3
import os
import signal
import socket
import sys
import time

transfer_bytes = int(os.environ.get("TRANSFER_BYTES", 104_857_600))
initial_timeout = int(os.environ.get("INITIAL_TIMEOUT_S", 60))
idle_timeout = int(os.environ.get("IDLE_TIMEOUT_S", 30))
port = 9000

received = 0


def _sigterm(signum, frame):
    pct = received / transfer_bytes * 100
    print(f"received {received}/{transfer_bytes} bytes ({pct:.1f}%)", flush=True)
    sys.exit(0)


signal.signal(signal.SIGTERM, _sigterm)

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(("0.0.0.0", port))
sock.settimeout(initial_timeout)
print(f"UDP sink ready on :{port}", flush=True)

first_byte_time = None
last_byte_time = None
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
    if first_byte_time is None:
        first_byte_time = time.monotonic()
    received += len(data)
    last_byte_time = time.monotonic()

pct = received / transfer_bytes * 100
print(f"received {received}/{transfer_bytes} bytes ({pct:.1f}%)", flush=True)
if first_byte_time is not None and last_byte_time is not None:
    print(f"recv_time_s={last_byte_time - first_byte_time:.3f}", flush=True)
sys.exit(0)
