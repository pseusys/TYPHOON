#!/usr/bin/env python3
"""
Tor link-protocol-v4 sender — wraps the c2s portion of the active
TRAFFIC_PROFILE in 514-byte RELAY cells over TLS.

Each chunk produced by `_profile.run_profile` is split into one or more
DATA_PER_CELL-byte segments and emitted as RELAY cells, so PROFILE_CHUNK_C2S
controls the application data unit while the wire continues to use Tor's
fixed 514-byte cell size.
"""

from contextlib import suppress
from os import environ, path, urandom
from socket import SHUT_WR, create_connection
from ssl import PROTOCOL_TLS_CLIENT, SSLContext, SSLError, TLSVersion
from struct import pack
from subprocess import run
from sys import exit
from time import monotonic, sleep

from _profile import run_profile

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
retries = 30

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

        def send_in_cells(data: bytes) -> None:
            """Split *data* into ≤DATA_PER_CELL chunks and emit RELAY cells."""
            offset = 0
            while offset < len(data):
                n = min(DATA_PER_CELL, len(data) - offset)
                tls.sendall(make_relay_cell(data[offset:offset + n]))
                offset += n

        transfer_start = monotonic()
        sent, total_sleep = run_profile(send_in_cells)
        transfer_time_s = monotonic() - transfer_start - total_sleep

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
        print(f"sent {sent} data bytes in cells", flush=True)
        print(f"transfer_time_s={transfer_time_s:.3f}", flush=True)
        exit(0)
    except (ConnectionRefusedError, OSError, SSLError) as exc:
        print(f"attempt {attempt + 1}: {exc}", flush=True)
        sleep(1)

exit(1)
