#!/usr/bin/env python3
import os
import signal
import socket
import sys
import time

server_host = os.environ["SERVER_HOST"]
transfer_bytes = int(os.environ.get("TRANSFER_BYTES", 104_857_600))
port = 9000
chunk_size = 500  # small payload so padding protocols show distinct wire-size distributions

delay_ms = float(os.environ.get("INTER_PACKET_DELAY_MS", 0))
delay_every = int(os.environ.get("DELAY_EVERY_N", 1))

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.connect((server_host, port))

# Brief pause so the server socket is definitely bound before first packet.
time.sleep(0.2)

chunk = bytes(chunk_size)
sent = 0
packets = 0
while sent < transfer_bytes:
    n = min(chunk_size, transfer_bytes - sent)
    sock.send(chunk[:n])
    sent += n
    packets += 1
    if delay_ms > 0 and packets % delay_every == 0:
        time.sleep(delay_ms / 1000)

sock.send(b"DONE")
signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
time.sleep(0.5)  # let the VPN daemon flush the last packet before the container exits
print(f"sent {sent} bytes", flush=True)
sys.exit(0)
