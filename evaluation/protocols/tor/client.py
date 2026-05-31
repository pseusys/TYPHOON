#!/usr/bin/env python3
from contextlib import suppress
from os import environ, path, urandom
from socket import SHUT_WR, create_connection
from ssl import PROTOCOL_TLS_CLIENT, SSLContext, SSLError, TLSVersion
from struct import pack
from subprocess import run
from sys import exit
from time import sleep

CELL = 514
DATA_PER_CELL = 498  # usable bytes per RELAY cell
PORT = 9001


def make_relay_cell(data: bytes) -> bytes:
    """Build a 514-byte Tor link-protocol-v4 RELAY cell."""
    # header: circid(4) + CMD_RELAY(1) = 5 bytes
    header = pack("!IB", 1, 3)
    # relay body: relay_cmd(1) + recognized(2) + stream_id(2) + digest(4) + length(2) + data(498) = 509
    body = (
        b"\x02"      # relay_cmd = RELAY_DATA
        + b"\x00\x00"  # recognized
        + b"\x00\x01"  # stream_id
        + urandom(4)  # digest (random for realism)
        + pack("!H", len(data))  # length
        + data.ljust(DATA_PER_CELL, b"\x00")
    )
    return header + body  # 5 + 509 = 514


observer_gw = environ.get("OBSERVER_GW")
server_host = environ["SERVER_HOST"]
transfer_bytes = int(environ.get("PROFILE_BYTES_C2S", 104_857_600))
retries = 30
delay_ms = float(environ.get("INTER_PACKET_DELAY_MS", 0))
delay_every = int(environ.get("DELAY_EVERY_N", 1))

if observer_gw:
    run(
        ["ip", "route", "add", "172.21.0.0/24", "via", observer_gw],
        check=False,
        capture_output=True,
    )

for _ in range(retries):
    if path.exists("/keys/tor_cert.pem"):
        break
    sleep(1)
else:
    print("tor_cert.pem never appeared", flush=True)
    exit(1)

ctx = SSLContext(PROTOCOL_TLS_CLIENT)
ctx.minimum_version = TLSVersion.TLSv1_3
ctx.load_verify_locations("/keys/tor_cert.pem")
ctx.check_hostname = False

for attempt in range(retries):
    try:
        raw = create_connection((server_host, PORT), timeout=5)
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
                sleep(delay_ms / 1000)
        try:
            raw2 = tls.unwrap()
        except (SSLError, OSError):
            raw2 = raw
        with suppress(OSError):
            raw2.shutdown(SHUT_WR)
            raw2.settimeout(120)
            while raw2.recv(65536):
                pass
        with suppress(OSError):
            raw2.close()
        print(f"sent {sent_data} data bytes in cells", flush=True)
        exit(0)
    except (ConnectionRefusedError, OSError, SSLError) as exc:
        print(f"attempt {attempt + 1}: {exc}", flush=True)
        sleep(1)

exit(1)
