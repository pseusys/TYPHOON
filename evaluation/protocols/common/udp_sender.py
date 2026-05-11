#!/usr/bin/env python3
"""
UDP sender — sends the c2s portion of the active TRAFFIC_PROFILE to SERVER_HOST:9000, exits 0.

Env vars:
  SERVER_HOST       destination IP or hostname (required)
  TRAFFIC_PROFILE   profile name (informational)
  PROFILE_CHUNK_C2S, PROFILE_IAT_C2S_MS, PROFILE_BYTES_C2S, PROFILE_DURATION_S,
  PROFILE_BURSTY, PROFILE_BURST_COUNT, PROFILE_BURST_IDLE_S
"""

import os
import signal
import socket
import sys
import time

from _profile import run_profile

server_host = os.environ["SERVER_HOST"]
port = 9000

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.connect((server_host, port))

# Wait 200 ms so the server socket is bound before the first packet arrives.
time.sleep(0.2)

transfer_start = time.monotonic()
sent, total_sleep = run_profile(sock.send)
transfer_time_s = time.monotonic() - transfer_start - total_sleep

sock.send(b"DONE")
signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
time.sleep(0.5)
print(f"sent {sent} bytes", flush=True)
print(f"transfer_time_s={transfer_time_s:.3f}", flush=True)
sys.exit(0)
