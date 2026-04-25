#!/usr/bin/env python3
import os
import socket
import ssl
import struct
import subprocess
import sys
import time

CELL = 514
DATA_PER_CELL = 498  # usable bytes per RELAY cell
PORT = 9001


def make_relay_cell(data: bytes) -> bytes:
    """Build a 514-byte Tor link-protocol-v4 RELAY cell."""
    # header: circid(4) + CMD_RELAY(1) = 5 bytes
    header = struct.pack("!IB", 1, 3)
    # relay body: relay_cmd(1) + recognized(2) + stream_id(2) + digest(4) + length(2) + data(498) = 509
    body = (
        b"\x02"      # relay_cmd = RELAY_DATA
        + b"\x00\x00"  # recognized
        + b"\x00\x01"  # stream_id
        + os.urandom(4)  # digest (random for realism)
        + struct.pack("!H", len(data))  # length
        + data.ljust(DATA_PER_CELL, b"\x00")
    )
    return header + body  # 5 + 509 = 514


observer_gw = os.environ.get("OBSERVER_GW")
server_host = os.environ["SERVER_HOST"]
transfer_bytes = int(os.environ.get("TRANSFER_BYTES", 104_857_600))
retries = 30
delay_ms = float(os.environ.get("INTER_PACKET_DELAY_MS", 0))
delay_every = int(os.environ.get("DELAY_EVERY_N", 1))

if observer_gw:
    subprocess.run(
        ["ip", "route", "add", "172.21.0.0/24", "via", observer_gw],
        check=False,
        capture_output=True,
    )

for _ in range(retries):
    if os.path.exists("/keys/tor_cert.pem"):
        break
    time.sleep(1)
else:
    print("tor_cert.pem never appeared", flush=True)
    sys.exit(1)

ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
ctx.minimum_version = ssl.TLSVersion.TLSv1_3
ctx.load_verify_locations("/keys/tor_cert.pem")
ctx.check_hostname = False

for attempt in range(retries):
    try:
        raw = socket.create_connection((server_host, PORT), timeout=5)
        raw.settimeout(None)
        tls = ctx.wrap_socket(raw, server_hostname="tor-eval")
        sent_data = 0
        cells = 0
        chunk = bytes(DATA_PER_CELL)
        while sent_data < transfer_bytes:
            n = min(DATA_PER_CELL, transfer_bytes - sent_data)
            cell = make_relay_cell(chunk[:n])
            tls.sendall(cell)
            sent_data += n
            cells += 1
            if delay_ms > 0 and cells % delay_every == 0:
                time.sleep(delay_ms / 1000)
        try:
            raw2 = tls.unwrap()
        except (ssl.SSLError, OSError):
            raw2 = raw
        try:
            raw2.shutdown(socket.SHUT_WR)
            raw2.settimeout(120)
            while raw2.recv(65536):
                pass
        except OSError:
            pass
        finally:
            try:
                raw2.close()
            except OSError:
                pass
        print(f"sent {sent_data} data bytes in cells", flush=True)
        sys.exit(0)
    except (ConnectionRefusedError, OSError, ssl.SSLError) as exc:
        print(f"attempt {attempt + 1}: {exc}", flush=True)
        time.sleep(1)

sys.exit(1)
