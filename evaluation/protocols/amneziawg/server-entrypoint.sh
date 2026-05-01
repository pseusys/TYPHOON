#!/bin/bash
set -euo pipefail

# AmneziaWG obfuscation parameters — must match client exactly.
# H1-H4 replace WireGuard's fixed type bytes (1/2/3/4) to remove the fixed-header fingerprint.
# Jc/Jmin/Jmax inject random junk packets at handshake time.
AWG_JC=4; AWG_JMIN=40; AWG_JMAX=70
AWG_S1=0; AWG_S2=0
AWG_H1=6; AWG_H2=7; AWG_H3=8; AWG_H4=9

awg genkey | tee /keys/awg_server.key | awg pubkey > /keys/awg_server.pub
chmod 600 /keys/awg_server.key

amneziawg-go awg0
ip addr add 10.100.0.1/24 dev awg0

awg set awg0 \
    private-key /keys/awg_server.key \
    listen-port 51820 \
    jc "${AWG_JC}" jmin "${AWG_JMIN}" jmax "${AWG_JMAX}" \
    s1 "${AWG_S1}" s2 "${AWG_S2}" \
    h1 "${AWG_H1}" h2 "${AWG_H2}" h3 "${AWG_H3}" h4 "${AWG_H4}"

ip link set awg0 up

TRANSFER_BYTES="${TRANSFER_BYTES:-104857600}" \
OBSERVER_GW="" \
python3 /app/server.py &
SINK_PID=$!

trap 'kill -TERM "${SINK_PID}" 2>/dev/null; wait "${SINK_PID}"; exit' SIGTERM SIGINT

(
    until [[ -f /keys/awg_client.pub ]]; do sleep 0.5; done
    awg set awg0 peer "$(<  /keys/awg_client.pub)" allowed-ips 10.100.0.2/32
) &

wait "${SINK_PID}"
