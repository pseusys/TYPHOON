from dataclasses import dataclass, field
from typing import Callable


# Packet record type: (timestamp_s, ip_size_bytes, app_payload_bytes).
PacketRecord = tuple[float, int, bytes]

# Handshake sniffer: given all packets sorted by time, returns the handshake
# end timestamp (seconds).  Return None to fall back to the global window.
HandshakeSniffer = Callable[[list[PacketRecord]], float | None]


def _window_sniffer(seconds: float) -> HandshakeSniffer:
    """Sniffer that marks handshake end as `first_ts + seconds`."""
    return lambda pkts: (pkts[0][0] + seconds) if pkts else None


@dataclass(frozen=True)
class Protocol:
    name: str
    description: str
    transport: str  # "udp" | "tcp" | "tcp/udp"
    client_image: str
    server_image: str
    # Per-protocol handshake detector.  Excluded from equality/hash so Protocol
    # remains usable as a dict key even though callables aren't hashable.
    handshake_sniffer: HandshakeSniffer | None = field(default=None, hash=False, compare=False)


def _img(slug: str, role: str) -> str:
    return f"typhoon-eval-{slug}-{role}"


ALL: list[Protocol] = [
    Protocol("raw_udp",  "Raw UDP",         "udp",     _img("raw-udp",        "client"), _img("raw-udp",        "server"), _window_sniffer(0.2)),
    Protocol("raw_tcp",  "Raw TCP",         "tcp",     _img("raw-tcp",        "client"), _img("raw-tcp",        "server"), _window_sniffer(0.2)),
    Protocol("tls",      "TLS 1.3",         "tcp",     _img("tls",            "client"), _img("tls",            "server"), _window_sniffer(0.5)),
    Protocol("wireguard","WireGuard",        "udp",     _img("wireguard",      "client"), _img("wireguard",      "server"), _window_sniffer(1.0)),
    Protocol("quic",     "QUIC",             "udp",     _img("quic",           "client"), _img("quic",           "server"), _window_sniffer(1.0)),
    Protocol("obfs4",    "OBFS4",            "tcp",     _img("obfs4",          "client"), _img("obfs4",          "server"), _window_sniffer(2.0)),
    Protocol("obfs4_iat","OBFS4 (IAT=1)",   "tcp",     _img("obfs4",          "client"), _img("obfs4",          "server"), _window_sniffer(2.0)),
    Protocol("obfs4_iat2","OBFS4 (IAT=2)",  "tcp",     _img("obfs4",          "client"), _img("obfs4",          "server"), _window_sniffer(2.0)),
    Protocol("amneziawg","AmneziaWG",        "udp",     _img("amneziawg",      "client"), _img("amneziawg",      "server"), _window_sniffer(1.0)),
    Protocol("hysteria2","Hysteria2+Brutal", "udp",     _img("hysteria2",      "client"), _img("hysteria2",      "server"), _window_sniffer(1.0)),
    Protocol("shadowsocks","Shadowsocks",    "tcp/udp", _img("shadowsocks",    "client"), _img("shadowsocks",    "server"), _window_sniffer(0.5)),
    Protocol("tor",      "Tor",              "tcp",     _img("tor",            "client"), _img("tor",            "server"), _window_sniffer(15.0)),
    Protocol("vless_reality","VLESS REALITY","tcp",     _img("vless-reality",  "client"), _img("vless-reality",  "server"), _window_sniffer(1.0)),
    Protocol("openvpn",  "OpenVPN",          "udp",     _img("openvpn",        "client"), _img("openvpn",        "server"), _window_sniffer(5.0)),
    Protocol("wireguard_daita","WireGuard+DAITA","udp", _img("wireguard-daita","client"), _img("wireguard-daita","server"), _window_sniffer(1.0)),
    Protocol("typhoon",  "TYPHOON",          "udp",     _img("typhoon",        "client"), _img("typhoon",        "server"), _window_sniffer(5.0)),
]

BY_NAME: dict[str, Protocol] = {p.name: p for p in ALL}
