#!/bin/sh
set -e

AWG_JC=4; AWG_JMIN=40; AWG_JMAX=70
AWG_S1=0; AWG_S2=0
AWG_H1=6; AWG_H2=7; AWG_H3=8; AWG_H4=9

if [ -n "${OBSERVER_GW}" ]; then
    ip route del 172.21.0.0/24 2>/dev/null || true
    ip route add 172.21.0.0/24 via "${OBSERVER_GW}" || true
fi

until [ -f /keys/awg_server.pub ]; do sleep 0.5; done

awg genkey | tee /keys/awg_client.key | awg pubkey > /keys/awg_client.pub
chmod 600 /keys/awg_client.key

amneziawg-go awg0
ip addr add 10.100.0.2/24 dev awg0

awg set awg0 \
    private-key /keys/awg_client.key \
    jc "${AWG_JC}" jmin "${AWG_JMIN}" jmax "${AWG_JMAX}" \
    s1 "${AWG_S1}" s2 "${AWG_S2}" \
    h1 "${AWG_H1}" h2 "${AWG_H2}" h3 "${AWG_H3}" h4 "${AWG_H4}" \
    peer "$(cat /keys/awg_server.pub)" \
        allowed-ips 10.100.0.1/32 \
        endpoint 172.21.0.10:51820 \
        persistent-keepalive 5

ip link set awg0 up

for i in $(seq 1 30); do
    HS=$(awg show awg0 latest-handshakes 2>/dev/null | awk '{print $2}')
    [ -n "${HS}" ] && [ "${HS}" != "0" ] && break
    sleep 1
done

SERVER_HOST=10.100.0.1 SERVER_PORT=9000 OBSERVER_GW="" exec python3 /app/client.py
