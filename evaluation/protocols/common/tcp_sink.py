#!/usr/bin/env python3
"""
TCP sink — accepts one connection, receives PROFILE_BYTES_C2S, exits 0.

Env vars:
  OBSERVER_GW     gateway IP to route the opposite /24 subnet through
  RETURN_SUBNET   subnet to add a route to (default 172.20.0.0/24)
  PROFILE_BYTES_C2S  bytes to receive before exiting (default 100 MB)
  LISTEN_PORT     TCP port to bind (default 9000)
"""

from contextlib import suppress
from os import environ
from signal import SIGTERM, signal
from socket import AF_INET, SO_REUSEADDR, SOCK_STREAM, SOL_SOCKET, socket
from subprocess import run
from sys import exit
from time import monotonic
from typing import NoReturn

observer_gw = environ.get("OBSERVER_GW")
return_subnet = environ.get("RETURN_SUBNET", "172.20.0.0/24")
transfer_bytes = int(environ.get("PROFILE_BYTES_C2S", 104_857_600))
port = int(environ.get("LISTEN_PORT", 9000))

if observer_gw:
    run(["ip", "route", "add", return_subnet, "via", observer_gw], check=False, capture_output=True)

idle_timeout = int(environ.get("IDLE_TIMEOUT_S", 120))

received = 0


def _sigterm(signum, frame) -> NoReturn:
    pct = received / transfer_bytes * 100
    print(f"received {received}/{transfer_bytes} bytes ({pct:.1f}%)", flush=True)
    exit(0)


signal(SIGTERM, _sigterm)

srv = socket(AF_INET, SOCK_STREAM)
srv.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
srv.bind(("0.0.0.0", port))
srv.listen(1)
print(f"TCP sink ready on :{port}", flush=True)

conn, _ = srv.accept()
conn.settimeout(idle_timeout)

first_byte_time = None
last_byte_time = None
with suppress(TimeoutError, OSError):
    while received < transfer_bytes:
        data = conn.recv(65536)
        if not data:
            break
        if first_byte_time is None:
            first_byte_time = monotonic()
        received += len(data)
        last_byte_time = monotonic()
with suppress(OSError):
    conn.close()

pct = received / transfer_bytes * 100
print(f"received {received}/{transfer_bytes} bytes ({pct:.1f}%)", flush=True)
if first_byte_time is not None and last_byte_time is not None:
    print(f"recv_time_s={last_byte_time - first_byte_time:.3f}", flush=True)
exit(0)
