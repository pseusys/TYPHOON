#!/usr/bin/env python3
"""
UDP sender — sends a traffic scenario to SERVER_HOST:9000, exits 0.

Env vars:
  SERVER_HOST       destination IP or hostname (required)
  TRANSFER_BYTES    bytes to send (default 100 MB)
  TRAFFIC_SCENARIO  bulk|interactive|streaming|burst|idle|echo (default: bulk)
"""

import os
import signal
import socket
import sys
import time

from _scenario import run_scenario

server_host = os.environ["SERVER_HOST"]
transfer_bytes = int(os.environ.get("TRANSFER_BYTES", 104_857_600))
scenario = os.environ.get("TRAFFIC_SCENARIO", "bulk").lower()
delay_ms = float(os.environ.get("INTER_PACKET_DELAY_MS", 0))
delay_every = int(os.environ.get("DELAY_EVERY_N", 1))
port = 9000

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.connect((server_host, port))

# Wait 200 ms so the server socket is bound before the first packet arrives.
time.sleep(0.2)

transfer_start = time.monotonic()
sent, total_sleep = run_scenario(scenario, sock.send, transfer_bytes, delay_ms, delay_every)
transfer_time_s = time.monotonic() - transfer_start - total_sleep

sock.send(b"DONE")
signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
time.sleep(0.5)
print(f"sent {sent} bytes", flush=True)
print(f"transfer_time_s={transfer_time_s:.3f}", flush=True)
sys.exit(0)
