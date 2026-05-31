#!/usr/bin/env python3
"""
UDP sender — sends the c2s portion of the active TRAFFIC_PROFILE to SERVER_HOST:9000, exits 0.

Env vars:
  SERVER_HOST       destination IP or hostname (required)
  TRAFFIC_PROFILE   profile name (informational)
  PROFILE_CHUNK_C2S, PROFILE_IAT_C2S_MS, PROFILE_BYTES_C2S, PROFILE_DURATION_S,
  PROFILE_BURSTY, PROFILE_BURST_COUNT, PROFILE_BURST_IDLE_S
"""

from os import environ
from signal import SIGTERM, signal
from socket import AF_INET, SOCK_DGRAM, socket
from sys import exit
from time import monotonic, sleep

from _profile import run_profile

server_host = environ["SERVER_HOST"]
port = 9000

sock = socket(AF_INET, SOCK_DGRAM)
sock.connect((server_host, port))

# Wait 200 ms so the server socket is bound before the first packet arrives.
sleep(0.2)

transfer_start = monotonic()
sent, total_sleep = run_profile(sock.send)
transfer_time_s = monotonic() - transfer_start - total_sleep

sock.send(b"DONE")
signal(SIGTERM, lambda *_: exit(0))
sleep(0.5)
print(f"sent {sent} bytes", flush=True)
print(f"transfer_time_s={transfer_time_s:.3f}", flush=True)
exit(0)
