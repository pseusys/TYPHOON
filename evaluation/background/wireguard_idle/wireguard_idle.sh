#!/bin/sh
# WireGuard idle: bring the tunnel up, keep it idle for PROFILE_DURATION_S.
# Both sides run the same script with ROLE=client|server.
set -eu

ROLE="${ROLE:?ROLE must be set to client or server}"
SERVER_HOST="${SERVER_HOST:-172.21.0.17}"
DURATION_S="${PROFILE_DURATION_S:-60}"
LISTEN_PORT="${LISTEN_PORT:-51820}"
KEEPALIVE_S="${WG_KEEPALIVE_S:-25}"

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
sleep "${DURATION_S}"
wg-quick down wg0 || true
