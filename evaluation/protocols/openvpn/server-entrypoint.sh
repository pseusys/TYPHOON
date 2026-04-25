#!/bin/bash
set -euo pipefail
OBSERVER_GW="${OBSERVER_GW:-}"

ip route add 172.20.0.0/24 via "${OBSERVER_GW}" || true

# Generate CA
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
    -keyout /keys/ovpn_ca.key -out /keys/ovpn_ca.crt \
    -days 365 -nodes -subj "/CN=typhoon-eval-ca"

# Generate server cert
openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
    -keyout /keys/ovpn_server.key -out /tmp/server.csr \
    -nodes -subj "/CN=typhoon-eval-server"
openssl x509 -req -in /tmp/server.csr \
    -CA /keys/ovpn_ca.crt -CAkey /keys/ovpn_ca.key -CAcreateserial \
    -out /keys/ovpn_server.crt -days 365

# Generate client cert (server holds the CA, so it issues the client cert too)
openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
    -keyout /keys/ovpn_client.key -out /tmp/client.csr \
    -nodes -subj "/CN=typhoon-eval-client"
openssl x509 -req -in /tmp/client.csr \
    -CA /keys/ovpn_ca.crt -CAkey /keys/ovpn_ca.key -CAcreateserial \
    -out /keys/ovpn_client.crt -days 365

chmod 600 /keys/ovpn_server.key /keys/ovpn_client.key

# Signal client that PKI is ready
touch /keys/ovpn_pki_ready

cat > /tmp/server.conf << 'EOF'
dev tun
proto udp
port 1194
server 10.200.0.0 255.255.255.0
ca   /keys/ovpn_ca.crt
cert /keys/ovpn_server.crt
key  /keys/ovpn_server.key
dh none
ecdh-curve prime256v1
data-ciphers AES-256-GCM
auth SHA256
keepalive 10 120
persist-key
persist-tun
verb 1
EOF

TRANSFER_BYTES="${TRANSFER_BYTES:-104857600}" \
OBSERVER_GW="" \
python3 /app/server.py &
SINK_PID=$!

openvpn --config /tmp/server.conf &
OVP_PID=$!

trap 'kill -TERM "${SINK_PID}" 2>/dev/null; wait "${SINK_PID}"; kill "${OVP_PID}" 2>/dev/null; exit' SIGTERM SIGINT

wait "${SINK_PID}"
kill "${OVP_PID}" 2>/dev/null || true
