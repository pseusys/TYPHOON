#!/usr/bin/env python3
"""
TCP sender — connects to SERVER_HOST:LISTEN_PORT, runs the c2s portion of the
active TRAFFIC_PROFILE, exits 0.

Env vars:
  SERVER_HOST       destination IP or hostname (required)
  OBSERVER_GW       gateway IP for the route add
  FORWARD_SUBNET    subnet to route (default 172.21.0.0/24)
  LISTEN_PORT       destination port (default 9000)
  CONNECT_RETRIES   times to retry on connection refused (default 30)
  TRAFFIC_PROFILE   profile name (informational)
  PROFILE_CHUNK_C2S, PROFILE_IAT_C2S_MS, PROFILE_BYTES_C2S, PROFILE_DURATION_S,
  PROFILE_BURSTY, PROFILE_BURST_COUNT, PROFILE_BURST_IDLE_S
"""

from os import environ
from socket import SHUT_WR, create_connection
from subprocess import run
from sys import exit
from time import monotonic, sleep

from _profile import run_profile

observer_gw = environ.get("OBSERVER_GW")
forward_subnet = environ.get("FORWARD_SUBNET", "172.21.0.0/24")
server_host = environ["SERVER_HOST"]
port = int(environ.get("LISTEN_PORT", 9000))
retries = int(environ.get("CONNECT_RETRIES", 30))

if observer_gw:
    run(["ip", "route", "add", forward_subnet, "via", observer_gw], check=False, capture_output=True)

for attempt in range(retries):
    try:
        with create_connection((server_host, port), timeout=5) as s:
            s.settimeout(None)
            transfer_start = monotonic()
            sent, total_sleep = run_profile(s.sendall)
            transfer_time_s = monotonic() - transfer_start - total_sleep
            try:
                s.shutdown(SHUT_WR)
                s.settimeout(120)
                while s.recv(65536):
                    pass
            except OSError:
                pass

        print(f"sent {sent} bytes", flush=True)
        print(f"transfer_time_s={transfer_time_s:.3f}", flush=True)
        exit(0)
    except (ConnectionRefusedError, OSError):
        if attempt < retries - 1:
            sleep(1)

print("failed to connect after retries", flush=True)
exit(1)
