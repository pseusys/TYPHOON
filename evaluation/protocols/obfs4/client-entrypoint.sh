#!/bin/sh
set -e

ip route add 172.21.0.0/24 via "${OBSERVER_GW}" || true

# Wait for server to publish the obfs4 cert / iat-mode args
echo "Waiting for obfs4 args..."
until [ -f /keys/obfs4_args.txt ]; do sleep 0.5; done
OBFS4_ARGS=$(cat /keys/obfs4_args.txt)   # e.g. cert=XXX,iat-mode=0
echo "Got obfs4 args: ${OBFS4_ARGS}"

# Start obfs4proxy client in managed PT mode
mkdir -p /state
export TOR_PT_MANAGED_TRANSPORT_VER="1"
export TOR_PT_STATE_LOCATION="/state"
export TOR_PT_CLIENT_TRANSPORTS="obfs4"

# Capture the SOCKS5 port obfs4proxy allocates
SOCKS5_PORT=""
obfs4proxy -enableLogging -logLevel INFO 2>/dev/null | while IFS= read -r line; do
    echo "[obfs4-client] ${line}"
    case "${line}" in
        CMETHOD\ obfs4\ socks5\ *)
            # CMETHOD obfs4 socks5 127.0.0.1:<port>
            ADDR=$(echo "${line}" | awk '{print $4}')
            SOCKS5_PORT=$(echo "${ADDR}" | cut -d: -f2)
            echo "${SOCKS5_PORT}" > /tmp/socks5_port
            ;;
    esac
done &
PT_PID=$!

# Wait for the SOCKS5 port to appear
for i in $(seq 1 30); do
    [ -f /tmp/socks5_port ] && break
    sleep 1
done
SOCKS5_PORT=$(cat /tmp/socks5_port)
echo "obfs4proxy SOCKS5 on port ${SOCKS5_PORT}"

# goptlib parses PT args with semicolons; SMETHOD ARGS uses commas — convert
SOCKS5_PORT="${SOCKS5_PORT}" \
SOCKS5_USERNAME="$(echo "${OBFS4_ARGS}" | tr ',' ';')" \
SERVER_HOST="${SERVER_HOST:-172.21.0.10}" \
SERVER_PORT=9000 \
OBSERVER_GW="" \
python3 /app/client.py

kill "${PT_PID}" 2>/dev/null || true
