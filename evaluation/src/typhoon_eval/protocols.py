from dataclasses import dataclass


@dataclass(frozen=True)
class Protocol:
    name: str
    description: str
    transport: str       # "udp" | "tcp" | "tcp/udp"
    client_image: str
    server_image: str


def _img(slug: str, role: str) -> str:
    return f"typhoon-eval-{slug}-{role}"


ALL: list[Protocol] = [
    Protocol("raw_udp",       "Raw UDP",          "udp",     _img("raw-udp",       "client"), _img("raw-udp",       "server")),
    Protocol("raw_tcp",       "Raw TCP",          "tcp",     _img("raw-tcp",       "client"), _img("raw-tcp",       "server")),
    Protocol("tls",           "TLS 1.3",          "tcp",     _img("tls",           "client"), _img("tls",           "server")),
    Protocol("wireguard",     "WireGuard",        "udp",     _img("wireguard",     "client"), _img("wireguard",     "server")),
    Protocol("quic",          "QUIC",             "udp",     _img("quic",          "client"), _img("quic",          "server")),
    Protocol("obfs4",         "OBFS4",            "tcp",     _img("obfs4",         "client"), _img("obfs4",         "server")),
    Protocol("obfs4_iat",     "OBFS4 (IAT=1)",    "tcp",     _img("obfs4",         "client"), _img("obfs4",         "server")),
    Protocol("obfs4_iat2",    "OBFS4 (IAT=2)",    "tcp",     _img("obfs4",         "client"), _img("obfs4",         "server")),
    Protocol("amneziawg",     "AmneziaWG",        "udp",     _img("amneziawg",     "client"), _img("amneziawg",     "server")),
    Protocol("hysteria2",     "Hysteria2+Brutal", "udp",     _img("hysteria2",     "client"), _img("hysteria2",     "server")),
    Protocol("shadowsocks",   "Shadowsocks",      "tcp/udp", _img("shadowsocks",   "client"), _img("shadowsocks",   "server")),
    Protocol("tor",           "Tor",              "tcp",     _img("tor",           "client"), _img("tor",           "server")),
    Protocol("vless_reality", "VLESS REALITY",    "tcp",     _img("vless-reality", "client"), _img("vless-reality", "server")),
    Protocol("openvpn",         "OpenVPN",          "udp",     _img("openvpn",         "client"), _img("openvpn",         "server")),
    Protocol("wireguard_daita", "WireGuard+DAITA",  "udp",     _img("wireguard-daita", "client"), _img("wireguard-daita", "server")),
    Protocol("typhoon",         "TYPHOON",          "udp",     _img("typhoon",         "client"), _img("typhoon",         "server")),
]

BY_NAME: dict[str, Protocol] = {p.name: p for p in ALL}
