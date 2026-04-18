#!/bin/sh
set -e

PCAP="/captures/${PROTOCOL}${PROTOCOL_SUFFIX:-}.pcap"
echo "[observer] protocol=${PROTOCOL} capture=${PCAP}"

# Capture all traffic between the fixed client (172.20.0.10) and server
# (172.21.0.10) addresses.
#
# Flags:
#   -U   packet-buffered writes (no data loss if killed mid-run)
#   -i any   capture on all interfaces (both net_left and net_right veth)
#   -n   no hostname resolution
#   -q   quiet (no per-packet output noise)
exec tcpdump -U -i any -n -q "host 172.20.0.10 and host 172.21.0.10" -w "${PCAP}"
