#!/usr/bin/env python3
from asyncio import TimeoutError, run, sleep, wait_for
from os import environ, path
from ssl import CERT_NONE
from subprocess import run as subprocess_run
from sys import exit
from time import sleep as time_sleep
from traceback import print_exc

from aioquic.asyncio import connect
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.quic.configuration import QuicConfiguration

observer_gw = environ.get("OBSERVER_GW")
server_host = environ["SERVER_HOST"]
transfer_bytes = int(environ.get("PROFILE_BYTES_C2S", 104_857_600))
PORT = 9000
CHUNK = 500
delay_ms = float(environ.get("INTER_PACKET_DELAY_MS", 0))
delay_every = int(environ.get("DELAY_EVERY_N", 1))
wait_timeout = int(environ.get("QUIC_WAIT_TIMEOUT_S", 240))

if observer_gw:
    subprocess_run(
        ["ip", "route", "add", "172.21.0.0/24", "via", observer_gw],
        check=False,
        capture_output=True,
    )

for _ in range(30):
    if path.exists("/keys/quic_cert.pem"):
        break
    time_sleep(1)
else:
    print("quic_cert.pem never appeared", flush=True)
    exit(1)


async def main() -> None:
    config = QuicConfiguration(is_client=True, alpn_protocols=["eval"])
    config.verify_mode = CERT_NONE
    config.server_name = "quic-eval"
    config.idle_timeout = 300.0
    config.max_stream_data = 128 * 1024 * 1024
    config.max_data = 256 * 1024 * 1024
    config.congestion_control_algorithm = "cubic"

    print("Connecting...", flush=True)
    sent_bytes = 0
    async with connect(
        server_host,
        PORT,
        configuration=config,
        create_protocol=QuicConnectionProtocol,
    ) as proto:
        print("Connected, sending data...", flush=True)
        stream_id = proto._quic.get_next_available_stream_id()
        chunk = bytes(CHUNK)
        packets = 0
        while sent_bytes < transfer_bytes:
            n = min(CHUNK, transfer_bytes - sent_bytes)
            end = (sent_bytes + n) >= transfer_bytes
            proto._quic.send_stream_data(stream_id, chunk[:n], end_stream=end)
            sent_bytes += n
            packets += 1
            if end or packets % delay_every == 0:
                proto.transmit()
            if delay_ms > 0 and packets % delay_every == 0:
                await sleep(delay_ms / 1000)
        print(f"All {sent_bytes} bytes enqueued, waiting for server close...", flush=True)
        try:
            await wait_for(proto.wait_closed(), timeout=wait_timeout)
        except TimeoutError:
            print(f"wait_closed timed out after {wait_timeout}s", flush=True)

    print(f"sent {sent_bytes} bytes via QUIC", flush=True)


try:
    run(main())
except Exception:
    print_exc()
    exit(1)
exit(0)
