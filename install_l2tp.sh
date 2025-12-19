#!/bin/bash
set -e

IPSEC_PSK="eylan"
VPN_IP_RANGE="192.168.42.10-192.168.42.250"
VPN_LOCAL_IP="192.168.42.1"
VPN_SUBNET="192.168.42.0/24"

export DEBIAN_FRONTEND=noninteractive

MAIN_IFACE=$(ip route get 8.8.8.8 | awk -- '{print $5}')

apt-get update
apt-get install -y strongswan xl2tpd ppp net-tools iptables-persistent

sed -i 's/#net.ipv4.ip_forward=1/net.ipv4.ip_forward=1/' /etc/sysctl.conf
sysctl -w net.ipv4.ip_forward=1 > /dev/null 2>&1
sysctl -p > /dev/null 2>&1 || true

if [ -f /etc/ipsec.conf ]; then mv /etc/ipsec.conf /etc/ipsec.conf.bak.$(date +%s); fi
cat > /etc/ipsec.conf <<EOF
config setup
    charondebug="ike 1, knl 1, cfg 0"
    uniqueids=no

conn %default
    keyingtries=%forever
    dpddelay=30
    dpdtimeout=120
    dpdaction=clear

conn L2TP-PSK
    keyexchange=ikev1
    authby=secret
    ike=aes256-sha1-modp1024,3des-sha1-modp1024!
    esp=aes256-sha1,3des-sha1!
    pfs=no
    auto=add
    rekey=no
    ikelifetime=8h
    keylife=1h
    type=transport
    left=%any
    leftprotoport=17/1701
    right=%any
    rightprotoport=17/%any
EOF

if [ -f /etc/ipsec.secrets ]; then mv /etc/ipsec.secrets /etc/ipsec.secrets.bak.$(date +%s); fi
cat > /etc/ipsec.secrets <<EOF
: PSK "$IPSEC_PSK"
EOF
chmod 600 /etc/ipsec.secrets

if [ -f /etc/xl2tpd/xl2tpd.conf ]; then mv /etc/xl2tpd/xl2tpd.conf /etc/xl2tpd/xl2tpd.conf.bak.$(date +%s); fi
cat > /etc/xl2tpd/xl2tpd.conf <<EOF
[global]
port = 1701
access control = no

[lns default]
ip range = $VPN_IP_RANGE
local ip = $VPN_LOCAL_IP
require chap = yes
refuse pap = yes
require authentication = yes
name = l2tpd
ppp debug = yes
pppoptfile = /etc/ppp/options.xl2tpd
length bit = yes
EOF

if [ -f /etc/ppp/options.xl2tpd ]; then mv /etc/ppp/options.xl2tpd /etc/ppp/options.xl2tpd.bak.$(date +%s); fi
cat > /etc/ppp/options.xl2tpd <<EOF
ipcp-accept-local
ipcp-accept-remote
ms-dns 8.8.8.8
ms-dns 8.8.4.4
noccp
auth
mtu 1280
mru 1280
nodefaultroute
debug
lock
proxyarp
connect-delay 5000
refuse-pap
refuse-eap
refuse-chap
refuse-mschap
require-mschap-v2
EOF

touch /etc/ppp/chap-secrets
chmod 600 /etc/ppp/chap-secrets

add_rule() {
    iptables -C "$@" 2>/dev/null || iptables -I "$@"
}

add_rule INPUT -p udp --dport 500 -j ACCEPT
add_rule INPUT -p udp --dport 4500 -j ACCEPT
add_rule INPUT -p udp --dport 1701 -j ACCEPT

add_rule FORWARD -i ppp+ -o $MAIN_IFACE -j ACCEPT
add_rule FORWARD -i $MAIN_IFACE -o ppp+ -j ACCEPT

iptables -t nat -C POSTROUTING -s $VPN_SUBNET -o $MAIN_IFACE -j MASQUERADE 2>/dev/null || iptables -t nat -I POSTROUTING -s $VPN_SUBNET -o $MAIN_IFACE -j MASQUERADE

netfilter-persistent save > /dev/null 2>&1 || true

if [ ! -f /etc/ppp/ip-up ]; then
    echo '#!/bin/bash' > /etc/ppp/ip-up
    echo '/bin/run-parts /etc/ppp/ip-up.d' >> /etc/ppp/ip-up
    chmod +x /etc/ppp/ip-up
fi
if [ ! -f /etc/ppp/ip-down ]; then
    echo '#!/bin/bash' > /etc/ppp/ip-down
    echo '/bin/run-parts /etc/ppp/ip-down.d' >> /etc/ppp/ip-down
    chmod +x /etc/ppp/ip-down
fi

HOOK_UP="/etc/ppp/ip-up.d/00-panel-monitor"
cat > $HOOK_UP <<'HOOKEOF'
#!/bin/bash
LOG_FILE="/dev/shm/active_l2tp_users"
if [ -n "$PEERNAME" ] && [ -n "$IFNAME" ]; then
    echo "${PEERNAME}:${IFNAME}" >> "$LOG_FILE"
fi
HOOKEOF
chmod +x $HOOK_UP

HOOK_DOWN="/etc/ppp/ip-down.d/00-panel-monitor"
cat > $HOOK_DOWN <<'HOOKEOF'
#!/bin/bash
LOG_FILE="/dev/shm/active_l2tp_users"
if [ -n "$IFNAME" ]; then
    sed -i "/:${IFNAME}$/d" "$LOG_FILE"
fi
if [ -f "/var/run/$IFNAME.pid" ]; then
    rm -f "/var/run/$IFNAME.pid"
fi
HOOKEOF
chmod +x $HOOK_DOWN

systemctl unmask strongswan-starter || true
systemctl enable strongswan-starter
systemctl restart strongswan-starter
systemctl enable xl2tpd
systemctl restart xl2tpd

echo "L2TP Installation Completed Successfully."
echo "PSK (Secret): $IPSEC_PSK"
