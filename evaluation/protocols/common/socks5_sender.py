#!/usr/bin/env python3
"""
SOCKS5 sender — connects to SERVER_HOST through a local SOCKS5 proxy, sends
TRANSFER_BYTES, exits 0.

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
  TRANSFER_BYTES   bytes to send (default 100 MB)
  CONNECT_RETRIES  attempts before giving up (default 30)
"""

import os
import socket
import subprocess
import sys
import time

import socks  # PySocks

observer_gw = os.environ.get("OBSERVER_GW")
forward_subnet = os.environ.get("FORWARD_SUBNET", "172.21.0.0/24")
server_host = os.environ["SERVER_HOST"]
server_port = int(os.environ.get("SERVER_PORT", 9000))
socks5_host = os.environ.get("SOCKS5_HOST", "127.0.0.1")
socks5_port = int(os.environ.get("SOCKS5_PORT", 1080))
socks5_user = os.environ.get("SOCKS5_USERNAME")
transfer_bytes = int(os.environ.get("TRANSFER_BYTES", 104_857_600))
retries = int(os.environ.get("CONNECT_RETRIES", 30))

if observer_gw:
    subprocess.run(["ip", "route", "add", forward_subnet, "via", observer_gw], check=False, capture_output=True)

chunk = bytes(65536)
for attempt in range(retries):
    try:
        s = socks.socksocket()
        if socks5_user:
            s.set_proxy(socks.SOCKS5, socks5_host, socks5_port, username=socks5_user, password="\x00")
        else:
            s.set_proxy(socks.SOCKS5, socks5_host, socks5_port)
        s.settimeout(10)
        s.connect((server_host, server_port))
        s.settimeout(None)
        sent = 0
        while sent < transfer_bytes:
            n = min(len(chunk), transfer_bytes - sent)
            s.sendall(chunk[:n])
            sent += n
        try:
            s.shutdown(socket.SHUT_WR)
            s.settimeout(120)
            while s.recv(65536):
                pass
        except OSError:
            pass
        s.close()
        print(f"sent {sent} bytes via SOCKS5", flush=True)
        sys.exit(0)
    except Exception as exc:
        print(f"attempt {attempt + 1}/{retries}: {exc}", flush=True)
        if attempt < retries - 1:
            time.sleep(2)

print("failed to send via SOCKS5", flush=True)
sys.exit(1)
