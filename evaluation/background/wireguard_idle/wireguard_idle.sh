#!/bin/sh
# WireGuard idle: bring the tunnel up, keep it idle for PROFILE_DURATION_S.
# Both sides run the same script with ROLE=client|server.
set -eu

ROLE="${ROLE:?ROLE must be set to client or server}"
SERVER_HOST="${SERVER_HOST:-172.21.0.17}"
DURATION_S="${PROFILE_DURATION_S:-60}"
LISTEN_PORT="${LISTEN_PORT:-51820}"
KEEPALIVE_S="${WG_KEEPALIVE_S:-25}"
OBSERVER_GW="${OBSERVER_GW:-}"

if [[ -n "${OBSERVER_GW}" ]]; then
    if [[ "${ROLE}" = "client" ]]; then
        ip route del 172.21.0.0/24 2>/dev/null || true
        ip route add 172.21.0.0/24 via "${OBSERVER_GW}" \
            || echo "wireguard_idle: WARNING: client route add failed"
    else
        ip route del 172.20.0.0/24 2>/dev/null || true
        ip route add 172.20.0.0/24 via "${OBSERVER_GW}" \
            || echo "wireguard_idle: WARNING: server route add failed"
    fi
fi

mkdir -p /etc/wireguard
SERVER_PRIVKEY=$(wg genkey)
SERVER_PUBKEY=$(echo "${SERVER_PRIVKEY}"  | wg pubkey)
CLIENT_PRIVKEY=$(wg genkey)
CLIENT_PUBKEY=$(echo "${CLIENT_PRIVKEY}"  | wg pubkey)

# Both sides have access to the same /shared volume via docker compose.
SHARED_DIR="${SHARED_DIR:-/shared}"
mkdir -p "${SHARED_DIR}"

if [[ "${ROLE}" = "server" ]]; then
    echo "${SERVER_PUBKEY}"  > "${SHARED_DIR}/server.pub"
    echo "${SERVER_PRIVKEY}" > "${SHARED_DIR}/server.key"
    while [[ ! -f "${SHARED_DIR}/client.pub" ]]; do sleep 0.5; done
    PEER_PUBKEY=$(cat "${SHARED_DIR}/client.pub")
    cat > /etc/wireguard/wg0.conf <<EOF
[Interface]
Address = 10.10.0.1/24
ListenPort = ${LISTEN_PORT}
PrivateKey = ${SERVER_PRIVKEY}
[Peer]
PublicKey = ${PEER_PUBKEY}
AllowedIPs = 10.10.0.2/32
EOF
else
    echo "${CLIENT_PUBKEY}"  > "${SHARED_DIR}/client.pub"
    while [[ ! -f "${SHARED_DIR}/server.pub" ]]; do sleep 0.5; done
    PEER_PUBKEY=$(cat "${SHARED_DIR}/server.pub")
    cat > /etc/wireguard/wg0.conf <<EOF
[Interface]
Address = 10.10.0.2/24
PrivateKey = ${CLIENT_PRIVKEY}
[Peer]
PublicKey = ${PEER_PUBKEY}
Endpoint = ${SERVER_HOST}:${LISTEN_PORT}
AllowedIPs = 10.10.0.1/32
PersistentKeepalive = ${KEEPALIVE_S}
EOF
fi

wg-quick up wg0
echo "wireguard_idle: ${ROLE} up, idling for ${DURATION_S} s"

if [[ "${ROLE}" = "client" ]]; then
    echo "wireguard_idle: client kicking handshake via ping 10.10.0.1"
    echo "wireguard_idle: wg show wg0 BEFORE ping:"
    wg show wg0 2>&1 || true
    for i in 1 2 3 4 5; do
        if ping -c 1 -W 2 10.10.0.1; then
            echo "wireguard_idle: ping succeeded on attempt ${i}"
            break
        else
            echo "wireguard_idle: ping attempt ${i} failed"
        fi
        sleep 1
    done
    echo "wireguard_idle: wg show wg0 AFTER ping:"
    wg show wg0 2>&1 || true
fi

sleep "${DURATION_S}"
wg-quick down wg0 || true
