#!/usr/bin/env python3
"""
TCP sink — accepts one connection, receives TRANSFER_BYTES, exits 0.

Env vars:
  OBSERVER_GW     gateway IP to route the opposite /24 subnet through
  RETURN_SUBNET   subnet to add a route to (default 172.20.0.0/24)
  TRANSFER_BYTES  bytes to receive before exiting (default 100 MB)
  LISTEN_PORT     TCP port to bind (default 9000)
"""

import os
import socket
import subprocess
import sys

observer_gw = os.environ.get("OBSERVER_GW")
return_subnet = os.environ.get("RETURN_SUBNET", "172.20.0.0/24")
transfer_bytes = int(os.environ.get("TRANSFER_BYTES", 104_857_600))
port = int(os.environ.get("LISTEN_PORT", 9000))

if observer_gw:
    subprocess.run(["ip", "route", "add", return_subnet, "via", observer_gw], check=False, capture_output=True)

srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("0.0.0.0", port))
srv.listen(1)
print(f"TCP sink ready on :{port}", flush=True)

received = 0
while received < transfer_bytes:
    conn, addr = srv.accept()
    with conn:
        while received < transfer_bytes:
            data = conn.recv(65536)
            if not data:
                break
            received += len(data)

print(f"received {received}/{transfer_bytes} bytes", flush=True)
sys.exit(0 if received >= transfer_bytes else 1)
