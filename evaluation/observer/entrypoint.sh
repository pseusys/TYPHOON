#!/bin/sh
set -e

{ echo 1 > /proc/sys/net/ipv4/ip_forward; } 2>/dev/null || true

# Docker doesn't guarantee eth0=net_left / eth1=net_right ordering, so derive
# interface names from assigned IPs.
LEFT_IF=$(ip -o addr show | awk '/172\.20\.0\.2\// { print $2; exit }')
RIGHT_IF=$(ip -o addr show | awk '/172\.21\.0\.2\// { print $2; exit }')

if [ -z "${LEFT_IF}" ] || [ -z "${RIGHT_IF}" ]; then
    echo "[observer] ERROR: cannot identify interfaces (left='${LEFT_IF}' right='${RIGHT_IF}')"
    ip addr
    exit 1
fi
echo "[observer] left(client)=${LEFT_IF} right(server)=${RIGHT_IF}"

# Docker 27 (CVE-2024-29018) adds raw PREROUTING rules in the HOST netns that
# drop packets arriving on a different bridge than the destination container's
# own.  Insert ACCEPT rules before Docker's DROPs via nsenter into host netns.
nsenter --net=/proc/1/ns/net nft insert rule ip raw PREROUTING \
    ip saddr 172.20.0.0/24 ip daddr 172.21.0.0/24 accept 2>/dev/null || true
nsenter --net=/proc/1/ns/net nft insert rule ip raw PREROUTING \
    ip saddr 172.21.0.0/24 ip daddr 172.20.0.0/24 accept 2>/dev/null || true

nft add table ip nat
nft add chain ip nat POSTROUTING '{ type nat hook postrouting priority 100; }'
# SNAT so return packets are routed back through observer via conntrack
nft add rule ip nat POSTROUTING oifname "${RIGHT_IF}" masquerade

PCAP="/captures/${PROTOCOL}${PROTOCOL_SUFFIX:-}.pcap"
echo "[observer] protocol=${PROTOCOL} capture=${PCAP}"

exec tcpdump -U -i any -n -q \
    "host 172.20.0.10 or host 172.21.0.10" \
    -w "${PCAP}"
