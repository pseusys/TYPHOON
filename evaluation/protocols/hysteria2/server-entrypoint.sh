#!/bin/sh
set -e

ip route add 172.20.0.0/24 via "${OBSERVER_GW}" || true

# Self-signed TLS cert — client uses insecure mode, no CA needed
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
    -keyout /keys/hysteria_server.key -out /keys/hysteria_server.crt \
    -days 365 -nodes -subj "/CN=hysteria-eval"
chmod 600 /keys/hysteria_server.key

cat > /tmp/server.yaml << 'EOF'
listen: :443

tls:
  cert: /keys/hysteria_server.crt
  key:  /keys/hysteria_server.key

obfs:
  type: salamander
  salamander:
    password: "typhoon-eval-salamander"

auth:
  type: password
  password: "typhoon-eval-2026"
EOF

# tcp_sink receives the data proxied through Hysteria2
TRANSFER_BYTES="${TRANSFER_BYTES:-104857600}" \
OBSERVER_GW="" \
python3 /app/server.py &
SINK_PID=$!

hysteria server -c /tmp/server.yaml &

# Signal healthcheck and client
touch /keys/hysteria_ready

wait "${SINK_PID}"
