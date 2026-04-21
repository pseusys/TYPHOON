#!/bin/sh
set -e

ip route add 172.20.0.0/24 via "$OBSERVER_GW" || true

TRANSFER_BYTES="${TRANSFER_BYTES:-104857600}" \
OBSERVER_GW="" \
LISTEN_PORT=9001 \
python3 /app/server.py &
SINK_PID=$!

mkdir -p /state
export TOR_PT_MANAGED_TRANSPORT_VER="1"
export TOR_PT_STATE_LOCATION="/state"
export TOR_PT_SERVER_TRANSPORTS="obfs4"
export TOR_PT_SERVER_BINDADDR="obfs4-${CERT_HOST:-0.0.0.0}:9000"
export TOR_PT_ORPORT="127.0.0.1:9001"

# PT spec: SMETHOD line on stdout carries the cert args for the client
obfs4proxy -enableLogging -logLevel INFO 2>/tmp/obfs4.log | while IFS= read -r line; do
    echo "[obfs4-server] $line"
    case "$line" in
        SMETHOD\ obfs4\ *)
            ARGS=$(echo "$line" | sed 's/.*ARGS://')
            echo "$ARGS" > /keys/obfs4_args.txt
            ;;
    esac
done &

wait $SINK_PID
