#!/usr/bin/env python3
from os import environ
from socket import AF_INET, SOCK_DGRAM, socket
from subprocess import run
from sys import exit
from time import monotonic, sleep

observer_gw = environ.get("OBSERVER_GW")
server_host = environ["SERVER_HOST"]
transfer_bytes = int(environ.get("PROFILE_BYTES_C2S", 104_857_600))
port = 9000
chunk_size = 500  # small payload so padding protocols show distinct wire-size distributions

delay_ms = float(environ.get("INTER_PACKET_DELAY_MS", 0))
delay_every = int(environ.get("DELAY_EVERY_N", 1))

if observer_gw:
    run(
        ["ip", "route", "add", "172.21.0.0/24", "via", observer_gw],
        check=False,
        capture_output=True,
    )

sock = socket(AF_INET, SOCK_DGRAM)
sock.connect((server_host, port))

# Brief pause so the server socket is definitely bound before first packet.
sleep(0.2)

chunk = bytes(chunk_size)
sent = 0
packets = 0
total_sleep = 0.0
transfer_start = monotonic()
while sent < transfer_bytes:
    n = min(chunk_size, transfer_bytes - sent)
    sock.send(chunk[:n])
    sent += n
    packets += 1
    if delay_ms > 0 and packets % delay_every == 0:
        sleep(delay_ms / 1000)
        total_sleep += delay_ms / 1000
transfer_time_s = monotonic() - transfer_start - total_sleep

print(f"sent {sent} bytes", flush=True)
print(f"transfer_time_s={transfer_time_s:.3f}", flush=True)

sock.send(b"DONE")
exit(0)
