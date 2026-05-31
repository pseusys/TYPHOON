#!/usr/bin/env python3
"""HTTP/3 server (aioquic) accepting POSTs and acknowledging with a tiny body.

Listens on UDP/443 and answers any POST with a 200 OK + 16-byte ack body,
draining the request body silently.  Used by the QUIC upload generator.
"""

from __future__ import annotations

from asyncio import run, sleep
from os import environ, system
from sys import path

from aioquic.asyncio import serve
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.h3.connection import H3_ALPN, H3Connection
from aioquic.h3.events import DataReceived, H3Event, HeadersReceived
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import QuicEvent

path.insert(0, "/common")
from profile_env import ProfileEnv

LISTEN_PORT = 443
ACK_BODY = b"OK" * 8  # 16 B


def _route_setup() -> None:
    gw = environ.get("OBSERVER_GW")
    if not gw:
        return
    system(f"ip route add 172.20.0.0/24 via {gw} 2>/dev/null")  # noqa: S605


class HttpServerProtocol(QuicConnectionProtocol):
    """One H3 connection draining POST bodies and acknowledging."""

    def __init__(self, *args: object, **kwargs: object) -> None:
        super().__init__(*args, **kwargs)
        self._h3: H3Connection | None = None

    def quic_event_received(self, event: QuicEvent) -> None:
        if self._h3 is None:
            self._h3 = H3Connection(self._quic)
        for h3_event in self._h3.handle_event(event):
            self._handle_h3_event(h3_event)

    def _handle_h3_event(self, event: H3Event) -> None:
        if isinstance(event, HeadersReceived) and event.stream_ended or isinstance(event, DataReceived) and event.stream_ended:
            self._reply(event.stream_id)

    def _reply(self, stream_id: int) -> None:
        self._h3.send_headers(
            stream_id=stream_id,
            headers=[
                (b":status", b"200"),
                (b"content-type", b"application/octet-stream"),
                (b"content-length", str(len(ACK_BODY)).encode()),
            ],
        )
        self._h3.send_data(stream_id=stream_id, data=ACK_BODY, end_stream=True)


async def main_async() -> None:
    profile = ProfileEnv.from_env()
    _route_setup()
    cert_path = environ.get("CERT_PATH", "/keys/quic.pem")
    key_path = environ.get("KEY_PATH", "/keys/quic.key")
    config = QuicConfiguration(is_client=False, alpn_protocols=H3_ALPN)
    config.load_cert_chain(cert_path, key_path)

    print(f"quic-u/l server: listening on UDP/{LISTEN_PORT}", flush=True)
    await serve(host="0.0.0.0", port=LISTEN_PORT, configuration=config, create_protocol=HttpServerProtocol)
    await sleep(profile.duration_s + 5.0)


if __name__ == "__main__":
    run(main_async())
