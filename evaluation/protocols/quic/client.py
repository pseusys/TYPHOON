#!/usr/bin/env python3
"""
QUIC sender — runs the c2s portion of the active TRAFFIC_PROFILE over a single
QUIC stream.  Uses `_profile.run_profile_async` so PROFILE_DURATION_S, batch
pacing, and IAT pacing are honoured uniformly with the other senders without
blocking the aioquic event loop on a sync `time.sleep`.
"""

from asyncio import TimeoutError, run, wait_for
from os import environ, path
from ssl import CERT_NONE
from subprocess import run as subprocess_run
from sys import exit
from time import monotonic, sleep
from traceback import print_exc

from _profile import run_profile_async
from aioquic.asyncio import connect
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.quic.configuration import QuicConfiguration

observer_gw = environ.get("OBSERVER_GW")
server_host = environ["SERVER_HOST"]
PORT = 9000
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
    sleep(1)
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
    async with connect(
        server_host,
        PORT,
        configuration=config,
        create_protocol=QuicConnectionProtocol,
    ) as proto:
        print("Connected, sending data...", flush=True)
        stream_id = proto._quic.get_next_available_stream_id()

        def send_chunk(data: bytes) -> None:
            """Enqueue *data* on the eval stream and trigger transmission."""
            proto._quic.send_stream_data(stream_id, data, end_stream=False)
            proto.transmit()

        transfer_start = monotonic()
        sent_bytes, total_sleep = await run_profile_async(send_chunk)
        transfer_time_s = monotonic() - transfer_start - total_sleep

        # Close the stream cleanly; aioquic requires a final send to flip FIN.
        proto._quic.send_stream_data(stream_id, b"", end_stream=True)
        proto.transmit()

        print(f"All {sent_bytes} bytes enqueued, waiting for server close...", flush=True)
        try:
            await wait_for(proto.wait_closed(), timeout=wait_timeout)
        except TimeoutError:
            print(f"wait_closed timed out after {wait_timeout}s", flush=True)

    print(f"sent {sent_bytes} bytes via QUIC", flush=True)
    print(f"transfer_time_s={transfer_time_s:.3f}", flush=True)


try:
    run(main())
except Exception:
    print_exc()
    exit(1)
exit(0)
