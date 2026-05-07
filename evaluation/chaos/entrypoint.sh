#!/bin/sh
set -eu
CHAOS_DELAY_MS="${CHAOS_DELAY_MS:-100}"
CHAOS_JITTER_MS="${CHAOS_JITTER_MS:-30}"
CHAOS_LOSS_PCT="${CHAOS_LOSS_PCT:-2}"
CHAOS_BW_MBPS="${CHAOS_BW_MBPS:-0}"

_addrs_tmp="/tmp/typhoon_right_if_$$"
ip -o addr show > "${_addrs_tmp}"
RIGHT_IF=$(awk '/172[.]21[.]0[.]2\//{print $2;exit}' "${_addrs_tmp}")
rm -f "${_addrs_tmp}"

tc qdisc del dev "${RIGHT_IF}" root 2>/dev/null || true

if [ "${CHAOS_BW_MBPS}" != "0" ] && [ "${CHAOS_BW_MBPS}" != "0.0" ]; then
    # tbf as root with netem as child (htb-less two-level hierarchy)
    BW_KBIT=$(awk "BEGIN{printf \"%d\", ${CHAOS_BW_MBPS} * 1000}")
    BURST_BYTES=$(awk "BEGIN{printf \"%d\", ${CHAOS_BW_MBPS} * 1000 * 1000 / 8 / 100}")
    tc qdisc add dev "${RIGHT_IF}" root handle 1: tbf \
        rate "${BW_KBIT}kbit" burst "${BURST_BYTES}" latency 200ms
    tc qdisc add dev "${RIGHT_IF}" parent 1:1 handle 10: netem limit 200000 \
        delay "${CHAOS_DELAY_MS}ms" "${CHAOS_JITTER_MS}ms" \
        loss "${CHAOS_LOSS_PCT}%"
else
    tc qdisc add dev "${RIGHT_IF}" root netem limit 200000 \
        delay "${CHAOS_DELAY_MS}ms" "${CHAOS_JITTER_MS}ms" \
        loss "${CHAOS_LOSS_PCT}%"
fi

exec sleep infinity
