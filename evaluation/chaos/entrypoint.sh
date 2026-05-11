#!/bin/sh
set -eu
CHAOS_DELAY_MS="${CHAOS_DELAY_MS:-100}"
CHAOS_JITTER_MS="${CHAOS_JITTER_MS:-30}"
CHAOS_LOSS_PCT="${CHAOS_LOSS_PCT:-2}"
CHAOS_DUPLICATE_PCT="${CHAOS_DUPLICATE_PCT:-0}"
CHAOS_REORDER_PCT="${CHAOS_REORDER_PCT:-0}"
CHAOS_BW_MBPS="${CHAOS_BW_MBPS:-0}"

# Find both observer interfaces — net_left (172.20.0.2) and net_right
# (172.21.0.2) — so chaos hits packets in both directions, not just c2s.
_addrs_tmp="/tmp/typhoon_chaos_$$"
ip -o addr show > "${_addrs_tmp}"
LEFT_IF=$(awk '/172[.]20[.]0[.]2\//{print $2;exit}' "${_addrs_tmp}")
RIGHT_IF=$(awk '/172[.]21[.]0[.]2\//{print $2;exit}' "${_addrs_tmp}")
rm -f "${_addrs_tmp}"

apply_qdisc() {
    iface="$1"
    if [ -z "${iface}" ]; then
        return
    fi
    tc qdisc del dev "${iface}" root 2>/dev/null || true
    # Build the netem perturbation tail once and re-use it for both the
    # bandwidth-shaped (tbf+netem) and unshaped paths.  Order matters for
    # netem: delay must precede reorder, otherwise reorder is silently
    # ignored (man tc-netem).
    NETEM_OPTS="delay ${CHAOS_DELAY_MS}ms ${CHAOS_JITTER_MS}ms"
    NETEM_OPTS="${NETEM_OPTS} loss ${CHAOS_LOSS_PCT}%"
    NETEM_OPTS="${NETEM_OPTS} duplicate ${CHAOS_DUPLICATE_PCT}%"
    NETEM_OPTS="${NETEM_OPTS} reorder ${CHAOS_REORDER_PCT}%"
    if [ "${CHAOS_BW_MBPS}" != "0" ] && [ "${CHAOS_BW_MBPS}" != "0.0" ]; then
        BW_KBIT=$(awk "BEGIN{printf \"%d\", ${CHAOS_BW_MBPS} * 1000}")
        BURST_BYTES=$(awk "BEGIN{printf \"%d\", ${CHAOS_BW_MBPS} * 1000 * 1000 / 8 / 100}")
        tc qdisc add dev "${iface}" root handle 1: tbf \
            rate "${BW_KBIT}kbit" burst "${BURST_BYTES}" latency 200ms
        # shellcheck disable=SC2086
        tc qdisc add dev "${iface}" parent 1:1 handle 10: netem limit 200000 ${NETEM_OPTS}
    else
        # shellcheck disable=SC2086
        tc qdisc add dev "${iface}" root netem limit 200000 ${NETEM_OPTS}
    fi
}

apply_qdisc "${LEFT_IF}"
apply_qdisc "${RIGHT_IF}"

exec sleep infinity
