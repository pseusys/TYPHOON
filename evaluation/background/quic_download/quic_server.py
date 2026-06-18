#!/usr/bin/env python3
"""HTTP/3 server (aioquic) serving a configurable-size random object.

Listens on UDP/443 and answers any GET with a payload of `OBJECT_SIZE_BYTES`
random bytes.  Used by the QUIC download generator.
"""

from __future__ import annotations

from asyncio import run, sleep
from os import environ, system, urandom
from sys import path

from aioquic.asyncio import serve
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.h3.connection import H3_ALPN, H3Connection
from aioquic.h3.events import H3Event, HeadersReceived
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import QuicEvent

path.insert(0, "/common")
from profile_env import ProfileEnv

LISTEN_PORT = 443


def _route_setup() -> None:
    gw = environ.get("OBSERVER_GW")
    if not gw:
        return
    system(f"ip route add 172.20.0.0/24 via {gw} 2>/dev/null")  # noqa: S605


class HttpServerProtocol(QuicConnectionProtocol):
    """One H3 connection answering any request with a fixed-size random body."""

    def __init__(self, *args: object, object_size: int, **kwargs: object) -> None:
        super().__init__(*args, **kwargs)
        self._h3: H3Connection | None = None
        self._object_size = object_size

    def quic_event_received(self, event: QuicEvent) -> None:
        if self._h3 is None:
            self._h3 = H3Connection(self._quic)
        for h3_event in self._h3.handle_event(event):
            self._handle_h3_event(h3_event)

    def _handle_h3_event(self, event: H3Event) -> None:
        if not isinstance(event, HeadersReceived):
            return
        body = urandom(self._object_size)
        self._h3.send_headers(
            stream_id=event.stream_id,
            headers=[
                (b":status", b"200"),
                (b"content-type", b"application/octet-stream"),
                (b"content-length", str(self._object_size).encode()),
            ],
        )
        self._h3.send_data(stream_id=event.stream_id, data=body, end_stream=True)


async def main_async() -> None:
    profile = ProfileEnv.from_env()
    _route_setup()
    object_size = max(profile.bytes_s2c, 1024)
    cert_path = environ.get("CERT_PATH", "/keys/quic.pem")
    key_path = environ.get("KEY_PATH", "/keys/quic.key")
    config = QuicConfiguration(is_client=False, alpn_protocols=H3_ALPN)
    config.load_cert_chain(cert_path, key_path)

    print(f"quic-d/l server: listening on UDP/{LISTEN_PORT}, object_size={object_size}", flush=True)

    def _factory(*args: object, **kwargs: object) -> HttpServerProtocol:
        return HttpServerProtocol(*args, object_size=object_size, **kwargs)

    await serve(host="0.0.0.0", port=LISTEN_PORT, configuration=config, create_protocol=_factory)
    await sleep(profile.duration_s + 5.0)


if __name__ == "__main__":
    run(main_async())
