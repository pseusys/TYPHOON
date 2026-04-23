#!/usr/bin/env python3
import asyncio
import os
import subprocess
import sys

from aioquic.asyncio import serve
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import ConnectionTerminated, QuicEvent, StreamDataReceived

transfer_bytes = int(os.environ.get("TRANSFER_BYTES", 104_857_600))
PORT = 9000

subprocess.run(
    [
        "openssl",
        "req",
        "-x509",
        "-newkey",
        "rsa:2048",
        "-keyout",
        "/tmp/quic_key.pem",
        "-out",
        "/keys/quic_cert.pem",
        "-days",
        "1",
        "-nodes",
        "-subj",
        "/CN=quic-eval",
    ],
    check=True,
    capture_output=True,
)


class SinkProtocol(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._received = 0
        self._done = asyncio.Event()

    def quic_event_received(self, event: QuicEvent) -> None:
        if isinstance(event, StreamDataReceived):
            self._received += len(event.data)
            if event.end_stream or self._received >= transfer_bytes:
                self._done.set()
        elif isinstance(event, ConnectionTerminated):
            self._done.set()

    async def wait_done(self) -> None:
        await self._done.wait()
        pct = self._received / transfer_bytes * 100
        print(f"received {self._received}/{transfer_bytes} bytes ({pct:.1f}%)", flush=True)


async def main() -> None:
    config = QuicConfiguration(is_client=False, alpn_protocols=["eval"])
    config.load_cert_chain("/keys/quic_cert.pem", "/tmp/quic_key.pem")

    protocols: list[SinkProtocol] = []

    def factory(*args, **kwargs) -> SinkProtocol:
        p = SinkProtocol(*args, **kwargs)
        protocols.append(p)
        return p

    print(f"QUIC sink ready on :{PORT}", flush=True)
    server = await serve("0.0.0.0", PORT, configuration=config, create_protocol=factory)

    while not protocols:
        await asyncio.sleep(0.1)
    await protocols[0].wait_done()
    server.close()


asyncio.run(main())
sys.exit(0)
