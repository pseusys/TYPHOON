#!/bin/sh
set -e

ip route add 172.20.0.0/24 via "$OBSERVER_GW" || true

# Generate server keypair using wg (keys in hex for UAPI format)
wg genkey > /keys/wg_server_b64.key
chmod 600 /keys/wg_server_b64.key
wg pubkey < /keys/wg_server_b64.key > /keys/wg_server_b64.pub

# Convert base64 key to hex for UAPI protocol
python3 -c "
import base64, binascii, sys
b64 = open('/keys/wg_server_b64.key').read().strip()
print(binascii.hexlify(base64.b64decode(b64)).decode())
" > /keys/wg_server.key

python3 -c "
import base64, binascii, sys
b64 = open('/keys/wg_server_b64.pub').read().strip()
print(binascii.hexlify(base64.b64decode(b64)).decode())
" > /keys/wg_server.pub

# Start tcp_sink
TRANSFER_BYTES="${TRANSFER_BYTES:-104857600}" \
OBSERVER_GW="" \
python3 /app/server.py &
SINK_PID=$!

# Wait for client public key (written as base64 by client)
until [ -f /keys/wg_client_b64.pub ]; do sleep 0.5; done

python3 -c "
import base64, binascii
b64 = open('/keys/wg_client_b64.pub').read().strip()
print(binascii.hexlify(base64.b64decode(b64)).decode())
" > /keys/wg_client.pub

CLIENT_HEX=$(cat /keys/wg_client.pub)
SERVER_KEY_HEX=$(cat /keys/wg_server.key)

# Write UAPI config for wg-daita
cat > /tmp/wg.conf << EOF
private_key=${SERVER_KEY_HEX}
listen_port=51820
public_key=${CLIENT_HEX}
allowed_ip=10.100.0.2/32
EOF

# Start wg-daita: creates wg0 TUN, configures device, enables DAITA on client peer
WG_IFNAME=wg0 \
WG_CONFIG=/tmp/wg.conf \
WG_READY_FILE=/keys/wg_daita_ready \
DAITA_PEER_HEX="${CLIENT_HEX}" \
DAITA_MACHINES_FILE=/etc/daita/machines.txt \
wg-daita &
WG_PID=$!

until [ -f /keys/wg_daita_ready ]; do sleep 0.2; done

ip addr add 10.100.0.1/24 dev wg0
ip link set wg0 up

wait $SINK_PID
kill "$WG_PID" 2>/dev/null || true
