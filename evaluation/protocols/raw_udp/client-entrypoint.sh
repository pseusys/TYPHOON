#!/bin/bash
set -euo pipefail
OBSERVER_GW="${OBSERVER_GW:-}"

# Add route to server network through the observer gateway.
# Logged explicitly so any failure is visible in container logs.
if [[ -n "${OBSERVER_GW}" ]]; then
    echo "[client] adding route 172.21.0.0/24 via ${OBSERVER_GW}"
    ip route del 172.21.0.0/24 2>/dev/null || true
    ip route add 172.21.0.0/24 via "${OBSERVER_GW}" \
        || echo "[client] WARNING: route add failed (already exists?)"
fi

exec python3 /app/client.py
