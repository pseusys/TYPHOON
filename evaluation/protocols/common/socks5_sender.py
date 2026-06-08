#!/usr/bin/env python3
"""
SOCKS5 sender — connects to SERVER_HOST through a local SOCKS5 proxy, runs the
c2s portion of the active TRAFFIC_PROFILE, exits 0.

For standard proxies (Shadowsocks, Tor, VLESS): no auth.
For obfs4proxy PT SOCKS5: set SOCKS5_USERNAME to the PT arg string, e.g.
    cert=<base64>;iat-mode=0

Env vars:
  SERVER_HOST      final destination IP (required)
  SERVER_PORT      final destination port (default 9000)
  OBSERVER_GW      gateway for route add
  FORWARD_SUBNET   subnet to route (default 172.21.0.0/24)
  SOCKS5_HOST      proxy host (default 127.0.0.1)
  SOCKS5_PORT      proxy port  (default 1080)
  SOCKS5_USERNAME  PT args for obfs4 auth; omit for standard SOCKS5
  CONNECT_RETRIES  attempts before giving up (default 30)
  TRAFFIC_PROFILE  profile name (informational)
  PROFILE_CHUNK_C2S, PROFILE_IAT_C2S_MS, PROFILE_BYTES_C2S, PROFILE_DURATION_S,
  PROFILE_BURSTY, PROFILE_BURST_COUNT, PROFILE_BURST_IDLE_S
"""

from os import environ
from socket import SHUT_WR
from subprocess import run
from sys import exit
from time import monotonic, sleep

from socks import SOCKS5, socksocket  # PySocks

from _profile import run_profile

observer_gw = environ.get("OBSERVER_GW")
forward_subnet = environ.get("FORWARD_SUBNET", "172.21.0.0/24")
server_host = environ["SERVER_HOST"]
server_port = int(environ.get("SERVER_PORT", 9000))
socks5_host = environ.get("SOCKS5_HOST", "127.0.0.1")
socks5_port = int(environ.get("SOCKS5_PORT", 1080))
socks5_user = environ.get("SOCKS5_USERNAME")
retries = int(environ.get("CONNECT_RETRIES", 30))

if observer_gw:
    run(["ip", "route", "add", forward_subnet, "via", observer_gw], check=False, capture_output=True)

for attempt in range(retries):
    try:
        s = socksocket()
        if socks5_user:
            s.set_proxy(SOCKS5, socks5_host, socks5_port, username=socks5_user, password="\x00")
        else:
            s.set_proxy(SOCKS5, socks5_host, socks5_port)
        s.settimeout(10)
        s.connect((server_host, server_port))
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
        s.close()
        print(f"sent {sent} bytes via SOCKS5", flush=True)
        print(f"transfer_time_s={transfer_time_s:.3f}", flush=True)
        exit(0)
    except Exception as exc:
        print(f"attempt {attempt + 1}/{retries}: {exc}", flush=True)
        if attempt < retries - 1:
            sleep(2)

print("failed to send via SOCKS5", flush=True)
exit(1)
