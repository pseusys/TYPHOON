#!/bin/sh
set -e

ip route add 172.21.0.0/24 via "${OBSERVER_GW}" || true

until [ -f /keys/hysteria_ready ]; do sleep 0.5; done

cat > /tmp/client.yaml << 'EOF'
server: "172.21.0.10:443"
auth: "typhoon-eval-2026"

tls:
  insecure: true

obfs:
  type: salamander
  salamander:
    password: "typhoon-eval-salamander"

socks5:
  listen: "127.0.0.1:1080"
EOF

hysteria client -c /tmp/client.yaml &
CLIENT_PID=$!

for i in $(seq 1 30); do
    ss -tln | grep -q ':1080' && break
    sleep 1
done

# Destination is 127.0.0.1:9000 as seen from the server (proxy connects to itself)
SERVER_HOST=127.0.0.1 \
SERVER_PORT=9000 \
OBSERVER_GW="" \
python3 /app/client.py

kill "${CLIENT_PID}" 2>/dev/null || true
