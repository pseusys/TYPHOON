#!/bin/bash
set -euo pipefail
OBSERVER_GW="${OBSERVER_GW:-}"

ip route add 172.21.0.0/24 via "${OBSERVER_GW}" || true

ss-local \
    -s "${SERVER_HOST:-172.21.0.10}" -p 8388 \
    -l 1080 \
    -k "typhoon-eval-2026" \
    -m "chacha20-ietf-poly1305" \
    -t 300 &
SSLOCAL_PID=$!

for i in {1..30}; do
    if ss -tln | grep -q ':1080'; then break; fi
    sleep 1
done

SERVER_HOST=127.0.0.1 \
SERVER_PORT=9000 \
OBSERVER_GW="" \
python3 /app/client.py

kill "${SSLOCAL_PID}" 2>/dev/null || true
