#!/bin/sh
set -eu
CHAOS_DELAY_MS="${CHAOS_DELAY_MS:-100}"
CHAOS_JITTER_MS="${CHAOS_JITTER_MS:-30}"
CHAOS_LOSS_PCT="${CHAOS_LOSS_PCT:-2}"

RIGHT_IF=$(ip -o addr show | awk '/172[.]21[.]0[.]2\//{print $2;exit}')
tc qdisc del dev "${RIGHT_IF}" root 2>/dev/null || true
tc qdisc add dev "${RIGHT_IF}" root netem limit 200000 \
    delay "${CHAOS_DELAY_MS}ms" "${CHAOS_JITTER_MS}ms" \
    loss "${CHAOS_LOSS_PCT}%"

exec sleep infinity
