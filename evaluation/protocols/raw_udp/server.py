#!/usr/bin/env python3
from os import environ
from socket import AF_INET, SOCK_DGRAM, socket
from subprocess import run
from sys import exit

observer_gw = environ.get("OBSERVER_GW")
transfer_bytes = int(environ.get("PROFILE_BYTES_C2S", 104_857_600))
initial_timeout = int(environ.get("INITIAL_TIMEOUT_S", 60))
idle_timeout = int(environ.get("IDLE_TIMEOUT_S", 30))
port = 9000

if observer_gw:
    run(
        ["ip", "route", "add", "172.20.0.0/24", "via", observer_gw],
        check=False,
        capture_output=True,
    )

sock = socket(AF_INET, SOCK_DGRAM)
sock.bind(("0.0.0.0", port))
sock.settimeout(initial_timeout)
print(f"UDP sink ready on :{port}", flush=True)

received = 0
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
    received += len(data)

pct = received / transfer_bytes * 100
print(f"received {received}/{transfer_bytes} bytes ({pct:.1f}%)", flush=True)
exit(0)
