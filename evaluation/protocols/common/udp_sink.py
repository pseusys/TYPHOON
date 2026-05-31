#!/usr/bin/env python3
from os import environ
from signal import SIGTERM, signal
from socket import AF_INET, SOCK_DGRAM, socket
from sys import exit
from time import monotonic
from typing import NoReturn

transfer_bytes = int(environ.get("PROFILE_BYTES_C2S", 104_857_600))
initial_timeout = int(environ.get("INITIAL_TIMEOUT_S", 60))
idle_timeout = int(environ.get("IDLE_TIMEOUT_S", 30))
port = 9000

received = 0


def _sigterm(signum, frame) -> NoReturn:
    pct = received / transfer_bytes * 100
    print(f"received {received}/{transfer_bytes} bytes ({pct:.1f}%)", flush=True)
    exit(0)


signal(SIGTERM, _sigterm)

sock = socket(AF_INET, SOCK_DGRAM)
sock.bind(("0.0.0.0", port))
sock.settimeout(initial_timeout)
print(f"UDP sink ready on :{port}", flush=True)

first_byte_time = None
last_byte_time = None
first = True
while received < transfer_bytes:
    try:
        data, _ = sock.recvfrom(65536)
    except TimeoutError:
        break
    if first:
        first = False
        sock.settimeout(idle_timeout)
    if data == b"DONE":
        break
    if first_byte_time is None:
        first_byte_time = monotonic()
    received += len(data)
    last_byte_time = monotonic()

pct = received / transfer_bytes * 100
print(f"received {received}/{transfer_bytes} bytes ({pct:.1f}%)", flush=True)
if first_byte_time is not None and last_byte_time is not None:
    print(f"recv_time_s={last_byte_time - first_byte_time:.3f}", flush=True)
exit(0)
