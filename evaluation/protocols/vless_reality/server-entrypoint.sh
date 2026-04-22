#!/bin/sh
set -e

ip route add 172.20.0.0/24 via "${OBSERVER_GW}" || true

# xray x25519 v26+ format: "Password (PublicKey): <key>" — match /PublicKey/ not /PublicKey:/
KEYS=$(xray x25519)
PRIVATE_KEY=$(echo "${KEYS}" | awk '/^PrivateKey:/ {print $2}')
PUBLIC_KEY=$(echo  "${KEYS}" | awk '/PublicKey/   {print $NF}')
SHORT_ID=$(openssl rand -hex 8)
UUID="a1b2c3d4-e5f6-7890-abcd-ef1234567890"

echo "${PUBLIC_KEY}" > /keys/vless_public_key
echo "${SHORT_ID}"   > /keys/vless_short_id
echo "${UUID}"       > /keys/vless_uuid

# REALITY requires a decoy backend; unauthenticated connections are forwarded here
openssl req -x509 -newkey rsa:2048 \
    -keyout /tmp/decoy_key.pem -out /tmp/decoy_cert.pem \
    -days 1 -nodes -subj "/CN=localhost" 2>/dev/null
openssl s_server -accept 8443 \
    -cert /tmp/decoy_cert.pem -key /tmp/decoy_key.pem \
    -quiet 2>/dev/null &

cat > /etc/xray/config.json <<EOF
{
  "log": {"loglevel": "warning"},
  "inbounds": [{
    "listen": "0.0.0.0",
    "port": 443,
    "protocol": "vless",
    "settings": {
      "clients": [{"id": "${UUID}", "flow": "xtls-rprx-vision"}],
      "decryption": "none"
    },
    "streamSettings": {
      "network": "tcp",
      "security": "reality",
      "realitySettings": {
        "show": false,
        "dest": "localhost:8443",
        "xver": 0,
        "serverNames": ["www.google.com"],
        "privateKey": "${PRIVATE_KEY}",
        "shortIds": ["${SHORT_ID}"]
      }
    }
  }],
  "outbounds": [{"protocol": "freedom"}]
}
EOF

TRANSFER_BYTES="${TRANSFER_BYTES:-104857600}" \
OBSERVER_GW="" \
python3 /app/server.py &
SINK_PID=$!

xray run -config /etc/xray/config.json &
XRAY_PID=$!

wait "${SINK_PID}"
