#!/usr/bin/env python3
"""
SOCKS5 sender — connects to SERVER_HOST through a local SOCKS5 proxy, sends
PROFILE_BYTES_C2S, exits 0.

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
  PROFILE_BYTES_C2S   bytes to send (default 100 MB)
  CONNECT_RETRIES  attempts before giving up (default 30)
"""

from os import environ
from socket import SHUT_WR
from subprocess import run
from sys import exit
from time import monotonic, sleep

from socks import SOCKS5, socksocket  # PySocks

observer_gw = environ.get("OBSERVER_GW")
forward_subnet = environ.get("FORWARD_SUBNET", "172.21.0.0/24")
server_host = environ["SERVER_HOST"]
server_port = int(environ.get("SERVER_PORT", 9000))
socks5_host = environ.get("SOCKS5_HOST", "127.0.0.1")
socks5_port = int(environ.get("SOCKS5_PORT", 1080))
socks5_user = environ.get("SOCKS5_USERNAME")
transfer_bytes = int(environ.get("PROFILE_BYTES_C2S", 104_857_600))
retries = int(environ.get("CONNECT_RETRIES", 30))
chunk_size = 500
delay_ms = float(environ.get("INTER_PACKET_DELAY_MS", 0))
delay_every = int(environ.get("DELAY_EVERY_N", 1))

if observer_gw:
    run(["ip", "route", "add", forward_subnet, "via", observer_gw], check=False, capture_output=True)

chunk = bytes(chunk_size)
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
        sent = 0
        packets = 0
        total_sleep = 0.0
        transfer_start = monotonic()
        while sent < transfer_bytes:
            n = min(chunk_size, transfer_bytes - sent)
            s.sendall(chunk[:n])
            sent += n
            packets += 1
            if delay_ms > 0 and packets % delay_every == 0:
                sleep(delay_ms / 1000)
                total_sleep += delay_ms / 1000
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
