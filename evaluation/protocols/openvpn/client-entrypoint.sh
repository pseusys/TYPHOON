#!/bin/bash
set -euo pipefail
OBSERVER_GW="${OBSERVER_GW:-}"

if [[ -n "${OBSERVER_GW}" ]]; then
    ip route del 172.21.0.0/24 2>/dev/null || true
    ip route add 172.21.0.0/24 via "${OBSERVER_GW}" || true
fi

until [[ -f /keys/ovpn_pki_ready ]]; do sleep 0.5; done

cat > /tmp/client.conf << 'EOF'
client
dev tun
proto udp
remote 172.21.0.10 1194
ca   /keys/ovpn_ca.crt
cert /keys/ovpn_client.crt
key  /keys/ovpn_client.key
data-ciphers AES-256-GCM
auth SHA256
persist-key
persist-tun
resolv-retry infinite
nobind
verb 1
EOF

openvpn --config /tmp/client.conf &
OVP_PID=$!

# Wait for VPN tunnel to assign an IP on tun0
for i in {1..30}; do
    if ip addr show tun0 2>/dev/null | grep -q "10\.200\.0\."; then break; fi
    sleep 1
done

# Connect through the VPN tunnel, not the direct path
SERVER_HOST=10.200.0.1 \
SERVER_PORT=9000 \
OBSERVER_GW="" \
python3 /app/client.py

kill "${OVP_PID}" 2>/dev/null || true
