#!/bin/sh
set -e

# Route must exist before the WireGuard handshake so UDP reaches 172.21.0.10:51820
if [ -n "${OBSERVER_GW}" ]; then
    ip route del 172.21.0.0/24 2>/dev/null || true
    ip route add 172.21.0.0/24 via "${OBSERVER_GW}" \
        || echo "[wg-client] WARNING: route add failed"
fi

until [ -f /keys/wg_server.pub ]; do sleep 0.5; done

wg genkey | tee /keys/wg_client.key | wg pubkey > /keys/wg_client.pub
chmod 600 /keys/wg_client.key

ip link add wg0 type wireguard
ip addr add 10.100.0.2/24 dev wg0
wg set wg0 \
    private-key /keys/wg_client.key \
    peer "$(cat /keys/wg_server.pub)" \
        allowed-ips 10.100.0.1/32 \
        endpoint 172.21.0.10:51820 \
        persistent-keepalive 5
ip link set wg0 up

for i in $(seq 1 30); do
    HS=$(wg show wg0 latest-handshakes 2>/dev/null | awk '{print $2}')
    if [ -n "${HS}" ] && [ "${HS}" != "0" ]; then break; fi
    sleep 1
done

SERVER_HOST=10.100.0.1 SERVER_PORT=9000 OBSERVER_GW="" exec python3 /app/client.py
