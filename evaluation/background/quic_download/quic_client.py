#!/usr/bin/env python3
"""HTTP/3 client repeatedly downloading objects from the QUIC d/l server.

Issues GETs in a loop until PROFILE_DURATION_S is exhausted.  Each GET
fetches one object of size matching `bytes_s2c / OBJECT_COUNT`.
"""

from __future__ import annotations

import asyncio
import os
import ssl
import sys
import time

from aioquic.asyncio.client import connect
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.h3.connection import H3_ALPN, H3Connection
from aioquic.h3.events import DataReceived, H3Event, HeadersReceived
from aioquic.quic.configuration import QuicConfiguration

sys.path.insert(0, "/common")
from profile_env import ProfileEnv

SERVER_PORT = 443
OBJECT_COUNT = 4


def _route_setup() -> None:
    gw = os.environ.get("OBSERVER_GW")
    if not gw:
        return
    os.system(f"ip route add 172.21.0.0/24 via {gw} 2>/dev/null")  # noqa: S605


class HttpClientProtocol(QuicConnectionProtocol):
    """Issue one GET, signal the body-completion future when stream ends."""

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._h3 = H3Connection(self._quic)
        self._completed: asyncio.Future[int] = asyncio.get_event_loop().create_future()
        self._bytes_in = 0

    async def get(self, host: str, path: str = "/") -> int:
        stream_id = self._quic.get_next_available_stream_id()
        self._h3.send_headers(
            stream_id=stream_id,
            headers=[
                (b":method", b"GET"),
                (b":scheme", b"https"),
                (b":authority", host.encode()),
                (b":path", path.encode()),
            ],
            end_stream=True,
        )
        self.transmit()
        return await self._completed

    def quic_event_received(self, event) -> None:
        for h3_event in self._h3.handle_event(event):
            self._handle_h3_event(h3_event)

    def _handle_h3_event(self, event: H3Event) -> None:
        if isinstance(event, DataReceived):
            self._bytes_in += len(event.data)
            if event.stream_ended and not self._completed.done():
                self._completed.set_result(self._bytes_in)
        elif isinstance(event, HeadersReceived) and event.stream_ended:
            if not self._completed.done():
                self._completed.set_result(self._bytes_in)


async def main_async() -> None:
    profile = ProfileEnv.from_env()
    _route_setup()
    server_host = os.environ["SERVER_HOST"]

    config = QuicConfiguration(is_client=True, alpn_protocols=H3_ALPN)
    config.verify_mode = ssl.CERT_NONE

    deadline = time.monotonic() + profile.duration_s
    fetched = 0
    while time.monotonic() < deadline:
        try:
            async with connect(
                server_host, SERVER_PORT, configuration=config, create_protocol=HttpClientProtocol
            ) as client:
                client = client  # type: HttpClientProtocol
                got = await asyncio.wait_for(client.get(server_host), timeout=max(deadline - time.monotonic(), 1.0))
                fetched += got
        except (asyncio.TimeoutError, ConnectionError, OSError) as e:
            print(f"quic-d/l client: connection error {e}", flush=True)
            await asyncio.sleep(0.5)
        except Exception as e:
            print(f"quic-d/l client: error {e}", flush=True)
            await asyncio.sleep(0.5)
    print(f"quic-d/l client: total fetched {fetched} bytes", flush=True)


if __name__ == "__main__":
    asyncio.run(main_async())
