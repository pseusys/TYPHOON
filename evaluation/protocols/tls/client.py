#!/usr/bin/env python3
"""
TLS 1.3 sender — waits for /keys/tls_cert.pem from the server, then runs the
c2s portion of the active TRAFFIC_PROFILE over TLS using that cert as the
trusted CA.
"""

from contextlib import suppress
from os import environ, path
from socket import SHUT_WR, create_connection
from ssl import PROTOCOL_TLS_CLIENT, SSLContext, SSLError, TLSVersion
from subprocess import run
from sys import exit
from time import monotonic, sleep

from _profile import run_profile

observer_gw = environ.get("OBSERVER_GW")
server_host = environ["SERVER_HOST"]
port = 9000
retries = 30

if observer_gw:
    run(
        ["ip", "route", "add", "172.21.0.0/24", "via", observer_gw],
        check=False,
        capture_output=True,
    )

# Wait for server cert
for _ in range(retries):
    if path.exists("/keys/tls_cert.pem"):
        break
    sleep(1)
else:
    print("tls_cert.pem never appeared", flush=True)
    exit(1)

ctx = SSLContext(PROTOCOL_TLS_CLIENT)
ctx.minimum_version = TLSVersion.TLSv1_3
ctx.load_verify_locations("/keys/tls_cert.pem")
ctx.check_hostname = False

for _attempt in range(retries):
    try:
        raw = create_connection((server_host, port), timeout=5)
        raw.settimeout(None)
        tls = ctx.wrap_socket(raw, server_hostname="tls-eval")
        transfer_start = monotonic()
        sent, total_sleep = run_profile(tls.sendall)
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
        print(f"sent {sent} bytes", flush=True)
        print(f"transfer_time_s={transfer_time_s:.3f}", flush=True)
        exit(0)
    except (ConnectionRefusedError, OSError, SSLError):
        sleep(1)

exit(1)
