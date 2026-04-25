#!/usr/bin/env python3
"""
TCP sender — connects to SERVER_HOST:LISTEN_PORT, sends TRANSFER_BYTES, exits 0.

Env vars:
  SERVER_HOST     destination IP or hostname (required)
  OBSERVER_GW     gateway IP for the route add
  FORWARD_SUBNET  subnet to route (default 172.21.0.0/24)
  TRANSFER_BYTES  bytes to send (default 100 MB)
  LISTEN_PORT     destination port (default 9000)
  CONNECT_RETRIES times to retry on connection refused (default 30)
"""

import os
import socket
import subprocess
import sys
import time

observer_gw = os.environ.get("OBSERVER_GW")
forward_subnet = os.environ.get("FORWARD_SUBNET", "172.21.0.0/24")
server_host = os.environ["SERVER_HOST"]
port = int(os.environ.get("LISTEN_PORT", 9000))
transfer_bytes = int(os.environ.get("TRANSFER_BYTES", 104_857_600))
retries = int(os.environ.get("CONNECT_RETRIES", 30))
chunk_size = 500
delay_ms = float(os.environ.get("INTER_PACKET_DELAY_MS", 0))
delay_every = int(os.environ.get("DELAY_EVERY_N", 1))

if observer_gw:
    subprocess.run(["ip", "route", "add", forward_subnet, "via", observer_gw], check=False, capture_output=True)

chunk = bytes(chunk_size)
for attempt in range(retries):
    try:
        with socket.create_connection((server_host, port), timeout=5) as s:
            s.settimeout(None)
            sent = 0
            packets = 0
            total_sleep = 0.0
            transfer_start = time.monotonic()
            while sent < transfer_bytes:
                n = min(chunk_size, transfer_bytes - sent)
                s.sendall(chunk[:n])
                sent += n
                packets += 1
                if delay_ms > 0 and packets % delay_every == 0:
                    time.sleep(delay_ms / 1000)
                    total_sleep += delay_ms / 1000
            transfer_time_s = time.monotonic() - transfer_start - total_sleep
            try:
                s.shutdown(socket.SHUT_WR)
                s.settimeout(120)
                while s.recv(65536):
                    pass
            except OSError:
                pass
        print(f"sent {sent} bytes", flush=True)
        print(f"transfer_time_s={transfer_time_s:.3f}", flush=True)
        sys.exit(0)
    except (ConnectionRefusedError, OSError):
        if attempt < retries - 1:
            time.sleep(1)

print("failed to connect after retries", flush=True)
sys.exit(1)
