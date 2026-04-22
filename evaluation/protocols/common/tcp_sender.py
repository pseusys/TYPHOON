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

if observer_gw:
    subprocess.run(["ip", "route", "add", forward_subnet, "via", observer_gw], check=False, capture_output=True)

chunk = bytes(65536)
for attempt in range(retries):
    try:
        with socket.create_connection((server_host, port), timeout=5) as s:
            sent = 0
            while sent < transfer_bytes:
                n = min(len(chunk), transfer_bytes - sent)
                s.sendall(chunk[:n])
                sent += n
        print(f"sent {sent} bytes", flush=True)
        sys.exit(0)
    except (ConnectionRefusedError, OSError):
        if attempt < retries - 1:
            time.sleep(1)

print("failed to connect after retries", flush=True)
sys.exit(1)
