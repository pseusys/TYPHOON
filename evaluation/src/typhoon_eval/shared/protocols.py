from collections.abc import Callable
from dataclasses import dataclass, field

# Packet record type: (timestamp_s, transport_payload_size_bytes, app_payload_bytes).
# The size field excludes IP+UDP/TCP headers, isolating protocol-level signal
# from transport-layer overhead.
PacketRecord = tuple[float, int, bytes]

# Handshake sniffer: given the c2s and s2c packet lists (each sorted by time),
# returns the handshake end timestamp (seconds).  Return None to fall back to
# the global window.
HandshakeSniffer = Callable[[list[PacketRecord], list[PacketRecord]], float | None]

# Epsilon added to the boundary timestamp so packets emitted simultaneously
# (e.g. fragments of a single handshake message) all fall on the handshake side.
_BOUNDARY_EPSILON_S = 0.001


def _packet_count_sniffer(c2s_n: int, s2c_n: int, time_cap_s: float = 0.2) -> HandshakeSniffer:
    """Mark handshake end as `min(packet_boundary, first_ts + time_cap_s)`.

    `packet_boundary = max(c2s_n-th c2s ts, s2c_n-th s2c ts) + 1ms`.  N=0 in
    either direction skips that constraint (useful for protocols with no
    handshake response from one side).

    The time cap is a safety net for protocols where one direction is sparse:
    if the N-th packet in that direction never arrives in time (or arrives
    deep in the data phase), the cap prevents the handshake window from
    swallowing data packets.  200 ms is generous even for 4-RTT handshakes
    over 50 ms RTT links.
    """
    def sniff(c2s: list[PacketRecord], s2c: list[PacketRecord]) -> float | None:
        if not c2s and not s2c:
            return None
        first_ts = min(
            c2s[0][0] if c2s else float("inf"),
            s2c[0][0] if s2c else float("inf"),
        )
        ts_c = c2s[min(c2s_n, len(c2s)) - 1][0] if c2s and c2s_n > 0 else None
        ts_s = s2c[min(s2c_n, len(s2c)) - 1][0] if s2c and s2c_n > 0 else None
        candidates = [t for t in (ts_c, ts_s) if t is not None]
        if not candidates:
            return first_ts + time_cap_s
        packet_boundary = max(candidates) + _BOUNDARY_EPSILON_S
        return min(packet_boundary, first_ts + time_cap_s)
    return sniff


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


# Per-protocol sniffers based on known wire-level handshake structure.
# Counts are minimum c2s/s2c packets that the handshake exchange produces
# on the wire (after fragmentation, before any application data).  The 200 ms
# time cap is a safety net for any case where the s2c side is sparse and the
# N-th s2c packet would otherwise fall deep into the data phase.
_SN_RAW_UDP   = _packet_count_sniffer(c2s_n=1, s2c_n=0)  # no handshake; bound at first packet
_SN_RAW_TCP   = _packet_count_sniffer(c2s_n=2, s2c_n=1)  # SYN, SYN-ACK, ACK
_SN_TLS       = _packet_count_sniffer(c2s_n=3, s2c_n=2)  # TCP 3-way + TLS 1.3 1-RTT (CH, SH+...+Fin, Fin)
_SN_WIREGUARD = _packet_count_sniffer(c2s_n=1, s2c_n=1)  # Init, Response
_SN_QUIC      = _packet_count_sniffer(c2s_n=2, s2c_n=2)  # Initial(c), Initial+Handshake(s), Handshake(c)
_SN_OBFS4     = _packet_count_sniffer(c2s_n=3, s2c_n=2)  # TCP 3-way + obfs4 NTOR (1c+1s)
_SN_HYSTERIA2 = _packet_count_sniffer(c2s_n=2, s2c_n=2)  # QUIC-based
_SN_SHADOWSOCKS = _packet_count_sniffer(c2s_n=2, s2c_n=1)  # TCP 3-way; AEAD framing has no handshake
_SN_TOR       = _packet_count_sniffer(c2s_n=5, s2c_n=5)  # circuit construction is multi-hop; rough bound
_SN_VLESS     = _packet_count_sniffer(c2s_n=3, s2c_n=2)  # TLS-mimicking; same as TLS
_SN_OPENVPN   = _packet_count_sniffer(c2s_n=4, s2c_n=3)  # TLS-over-OpenVPN; longer than raw TLS
_SN_TYPHOON   = _packet_count_sniffer(c2s_n=1, s2c_n=2)  # 1 init + post-quantum response (2 fragments observed)


ALL: list[Protocol] = [
    Protocol("raw_udp",  "Raw UDP",         "udp",     _img("raw-udp",        "client"), _img("raw-udp",        "server"), _SN_RAW_UDP),
    Protocol("raw_tcp",  "Raw TCP",         "tcp",     _img("raw-tcp",        "client"), _img("raw-tcp",        "server"), _SN_RAW_TCP),
    Protocol("tls",      "TLS 1.3",         "tcp",     _img("tls",            "client"), _img("tls",            "server"), _SN_TLS),
    Protocol("wireguard","WireGuard",        "udp",     _img("wireguard",      "client"), _img("wireguard",      "server"), _SN_WIREGUARD),
    Protocol("quic",     "QUIC",             "udp",     _img("quic",           "client"), _img("quic",           "server"), _SN_QUIC),
    Protocol("obfs4",    "OBFS4",            "tcp",     _img("obfs4",          "client"), _img("obfs4",          "server"), _SN_OBFS4),
    Protocol("obfs4_iat","OBFS4 (IAT=1)",   "tcp",     _img("obfs4",          "client"), _img("obfs4",          "server"), _SN_OBFS4),
    Protocol("obfs4_iat2","OBFS4 (IAT=2)",  "tcp",     _img("obfs4",          "client"), _img("obfs4",          "server"), _SN_OBFS4),
    Protocol("amneziawg","AmneziaWG",        "udp",     _img("amneziawg",      "client"), _img("amneziawg",      "server"), _SN_WIREGUARD),
    Protocol("hysteria2","Hysteria2+Brutal", "udp",     _img("hysteria2",      "client"), _img("hysteria2",      "server"), _SN_HYSTERIA2),
    Protocol("shadowsocks","Shadowsocks",    "tcp",     _img("shadowsocks",    "client"), _img("shadowsocks",    "server"), _SN_SHADOWSOCKS),
    Protocol("tor",      "Tor",              "tcp",     _img("tor",            "client"), _img("tor",            "server"), _SN_TOR),
    Protocol("vless_reality","VLESS REALITY","tcp",     _img("vless-reality",  "client"), _img("vless-reality",  "server"), _SN_VLESS),
    Protocol("openvpn",  "OpenVPN",          "udp",     _img("openvpn",        "client"), _img("openvpn",        "server"), _SN_OPENVPN),
    Protocol("wireguard_daita","WireGuard+DAITA","udp", _img("wireguard-daita","client"), _img("wireguard-daita","server"), _SN_WIREGUARD),
    Protocol("typhoon",  "TYPHOON",          "udp",     _img("typhoon",        "client"), _img("typhoon",        "server"), _SN_TYPHOON),
]

BY_NAME: dict[str, Protocol] = {p.name: p for p in ALL}
