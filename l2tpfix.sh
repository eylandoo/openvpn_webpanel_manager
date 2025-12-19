#!/bin/bash
set -e

VPN_IP_RANGE="192.168.42.10-192.168.42.250"
VPN_LOCAL_IP="192.168.42.1"

if [ ! -f /etc/strongswan.conf ]; then
cat > /etc/strongswan.conf <<EOF
charon {
    load_modular = yes
    plugins {
        include strongswan.d/charon/*.conf
    }
}
include strongswan.d/*.conf
EOF
fi

if [ -f /etc/xl2tpd/xl2tpd.conf ]; then cp /etc/xl2tpd/xl2tpd.conf /etc/xl2tpd/xl2tpd.conf.bak_fix; fi
cat > /etc/xl2tpd/xl2tpd.conf <<EOF
[global]
ipsec saref = yes
listen-addr = 0.0.0.0
port = 1701

[lns default]
ip range = $VPN_IP_RANGE
local ip = $VPN_LOCAL_IP
require chap = no
refuse pap = yes
require authentication = yes
name = l2tpd
ppp debug = yes
pppoptfile = /etc/ppp/options.xl2tpd
length bit = yes
EOF

cat > /etc/ppp/options.xl2tpd <<EOF
require-mschap-v2
refuse-mschap
refuse-chap
refuse-pap
ms-dns 8.8.8.8
ms-dns 1.1.1.1
auth
mtu 1400
mru 1400
crtscts
hide-password
modem
name = l2tpd
proxyarp
lcp-echo-interval 30
lcp-echo-failure 4
EOF

systemctl unmask strongswan-starter || true
systemctl restart strongswan-starter
systemctl restart xl2tpd

echo "FIXED"
