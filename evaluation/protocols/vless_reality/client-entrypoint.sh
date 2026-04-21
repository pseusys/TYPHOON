#!/bin/sh
set -e

ip route add 172.21.0.0/24 via "$OBSERVER_GW" || true

until [ -f /keys/vless_public_key ] && [ -f /keys/vless_short_id ] && [ -f /keys/vless_uuid ]; do
    sleep 0.5
done

PUBLIC_KEY=$(cat /keys/vless_public_key)
SHORT_ID=$(cat  /keys/vless_short_id)
UUID=$(cat      /keys/vless_uuid)

cat > /etc/xray/config.json <<EOF
{
  "log": {"loglevel": "warning"},
  "inbounds": [{
    "listen": "127.0.0.1",
    "port": 1080,
    "protocol": "socks",
    "settings": {"auth": "noauth", "udp": false}
  }],
  "outbounds": [{
    "protocol": "vless",
    "settings": {
      "vnext": [{
        "address": "${SERVER_HOST:-172.21.0.10}",
        "port": 443,
        "users": [{
          "id": "${UUID}",
          "flow": "xtls-rprx-vision",
          "encryption": "none"
        }]
      }]
    },
    "streamSettings": {
      "network": "tcp",
      "security": "reality",
      "realitySettings": {
        "fingerprint": "chrome",
        "serverName": "www.google.com",
        "password": "${PUBLIC_KEY}",
        "shortId": "${SHORT_ID}",
        "spiderX": "/"
      }
    }
  }]
}
EOF

xray run -config /etc/xray/config.json &
XRAY_PID=$!

for i in $(seq 1 30); do
    ss -tln | grep -q ':1080' && break
    sleep 1
done

SERVER_HOST=127.0.0.1 \
SERVER_PORT=9000 \
OBSERVER_GW="" \
python3 /app/client.py

kill "$XRAY_PID" 2>/dev/null || true
