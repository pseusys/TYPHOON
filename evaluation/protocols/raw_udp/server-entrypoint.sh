#!/bin/sh
set -e

# Add return route to client network through the observer gateway.
if [ -n "$OBSERVER_GW" ]; then
    echo "[server] adding route 172.20.0.0/24 via $OBSERVER_GW"
    ip route del 172.20.0.0/24 2>/dev/null || true
    ip route add 172.20.0.0/24 via "$OBSERVER_GW" \
        || echo "[server] WARNING: route add failed (already exists?)"
fi

exec python3 /app/server.py
