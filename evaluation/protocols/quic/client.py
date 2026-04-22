#!/usr/bin/env python3
import asyncio
import os
import ssl
import subprocess
import sys
import time

from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection

observer_gw = os.environ.get("OBSERVER_GW")
server_host = os.environ["SERVER_HOST"]
transfer_bytes = int(os.environ.get("TRANSFER_BYTES", 104_857_600))
PORT = 9000
CHUNK = 65536

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
    config.server_name = server_host

    loop = asyncio.get_running_loop()
    _, proto = await loop.create_datagram_endpoint(
        lambda: QuicConnectionProtocol(QuicConnection(configuration=config)),
        local_addr=("0.0.0.0", 0),
    )

    sent_bytes = 0
    try:
        proto.connect((server_host, PORT))
        await asyncio.wait_for(proto.wait_connected(), timeout=30)

        stream_id = proto._quic.get_next_available_stream_id()
        chunk = bytes(CHUNK)
        while sent_bytes < transfer_bytes:
            n = min(CHUNK, transfer_bytes - sent_bytes)
            end = (sent_bytes + n) >= transfer_bytes
            proto._quic.send_stream_data(stream_id, chunk[:n], end_stream=end)
            proto.transmit()
            sent_bytes += n
            await asyncio.sleep(0)
        await asyncio.sleep(1)
    finally:
        proto.close()
        await proto.wait_closed()

    print(f"sent {sent_bytes} bytes via QUIC", flush=True)


asyncio.run(main())
sys.exit(0)
