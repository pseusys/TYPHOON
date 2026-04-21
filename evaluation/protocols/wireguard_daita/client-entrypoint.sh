#!/bin/sh
set -e

if [ -n "$OBSERVER_GW" ]; then
    ip route del 172.21.0.0/24 2>/dev/null || true
    ip route add 172.21.0.0/24 via "$OBSERVER_GW" || true
fi

# Wait for server public key (base64)
until [ -f /keys/wg_server_b64.pub ]; do sleep 0.5; done

# Convert server base64 pubkey to hex
python3 -c "
import base64, binascii
b64 = open('/keys/wg_server_b64.pub').read().strip()
print(binascii.hexlify(base64.b64decode(b64)).decode())
" > /keys/wg_server.pub

SERVER_HEX=$(cat /keys/wg_server.pub)

# Generate client keypair
wg genkey > /keys/wg_client_b64.key
chmod 600 /keys/wg_client_b64.key
wg pubkey < /keys/wg_client_b64.key > /keys/wg_client_b64.pub

python3 -c "
import base64, binascii
b64 = open('/keys/wg_client_b64.key').read().strip()
print(binascii.hexlify(base64.b64decode(b64)).decode())
" > /keys/wg_client.key

CLIENT_KEY_HEX=$(cat /keys/wg_client.key)

# Write UAPI config with server peer
cat > /tmp/wg.conf << EOF
private_key=${CLIENT_KEY_HEX}
public_key=${SERVER_HEX}
endpoint=172.21.0.10:51820
allowed_ip=10.100.0.1/32
persistent_keepalive_interval=5
EOF

# Start wg-daita with DAITA enabled on server peer
WG_IFNAME=wg0 \
WG_CONFIG=/tmp/wg.conf \
WG_READY_FILE=/keys/wg_daita_client_ready \
DAITA_PEER_HEX="${SERVER_HEX}" \
DAITA_MACHINES_FILE=/etc/daita/machines.txt \
wg-daita &
WG_PID=$!

until [ -f /keys/wg_daita_client_ready ]; do sleep 0.2; done

ip addr add 10.100.0.2/24 dev wg0
ip link set wg0 up

# Wait for handshake
for i in $(seq 1 30); do
    HS=$(wg show wg0 latest-handshakes 2>/dev/null | awk '{print $2}')
    if [ -n "$HS" ] && [ "$HS" != "0" ]; then break; fi
    sleep 1
done

SERVER_HOST=10.100.0.1 SERVER_PORT=9000 OBSERVER_GW="" exec python3 /app/client.py
