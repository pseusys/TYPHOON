#!/bin/bash
set -euo pipefail

wg genkey | tee /keys/wg_server.key | wg pubkey > /keys/wg_server.pub
chmod 600 /keys/wg_server.key

# Create interface before peer is known so the healthcheck can verify wg0 exists
ip link add wg0 type wireguard
ip addr add 10.100.0.1/24 dev wg0
wg set wg0 private-key /keys/wg_server.key listen-port 51820
ip link set wg0 up

TRANSFER_BYTES="${TRANSFER_BYTES:-104857600}" \
OBSERVER_GW="" \
python3 /app/server.py &
SINK_PID=$!

(
    until [[ -f /keys/wg_client.pub ]]; do sleep 0.5; done
    wg set wg0 peer "$(<  /keys/wg_client.pub)" allowed-ips 10.100.0.2/32
) &

wait "${SINK_PID}"
