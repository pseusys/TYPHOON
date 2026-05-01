#!/usr/bin/env python3
import asyncio
import os
import ssl
import subprocess
import sys
import time
import traceback

from aioquic.asyncio import connect
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.quic.configuration import QuicConfiguration

observer_gw = os.environ.get("OBSERVER_GW")
server_host = os.environ["SERVER_HOST"]
transfer_bytes = int(os.environ.get("TRANSFER_BYTES", 104_857_600))
PORT = 9000
CHUNK = 500
delay_ms = float(os.environ.get("INTER_PACKET_DELAY_MS", 0))
delay_every = int(os.environ.get("DELAY_EVERY_N", 1))
wait_timeout = int(os.environ.get("QUIC_WAIT_TIMEOUT_S", 240))

if observer_gw:
    subprocess.run(
        ["ip", "route", "add", "172.21.0.0/24", "via", observer_gw],
        check=False,
        capture_output=True,
    )

for _ in range(30):
    if os.path.exists("/keys/quic_cert.pem"):
        break
    time.sleep(1)
else:
    print("quic_cert.pem never appeared", flush=True)
    sys.exit(1)


async def main() -> None:
    config = QuicConfiguration(is_client=True, alpn_protocols=["eval"])
    config.verify_mode = ssl.CERT_NONE
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
                await asyncio.sleep(delay_ms / 1000)
        print(f"All {sent_bytes} bytes enqueued, waiting for server close...", flush=True)
        try:
            await asyncio.wait_for(proto.wait_closed(), timeout=wait_timeout)
        except asyncio.TimeoutError:
            print(f"wait_closed timed out after {wait_timeout}s", flush=True)

    print(f"sent {sent_bytes} bytes via QUIC", flush=True)


try:
    asyncio.run(main())
except Exception:
    traceback.print_exc()
    sys.exit(1)
sys.exit(0)
