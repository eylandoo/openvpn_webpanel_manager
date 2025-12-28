#!/bin/bash
set -e

IPSEC_PSK="eylan"
VPN_IP_RANGE="192.168.42.10-192.168.42.250"
VPN_LOCAL_IP="192.168.42.1"
VPN_SUBNET="192.168.42.0/24"

export DEBIAN_FRONTEND=noninteractive

killall apt apt-get dpkg 2>/dev/null || true
rm -f /var/lib/apt/lists/lock
rm -f /var/cache/apt/archives/lock
rm -f /var/lib/dpkg/lock*
dpkg --configure -a

apt-get update
apt-get install -y --fix-broken strongswan xl2tpd ppp net-tools iptables-persistent

sed -i 's/#net.ipv4.ip_forward=1/net.ipv4.ip_forward=1/' /etc/sysctl.conf
sysctl -w net.ipv4.ip_forward=1 > /dev/null 2>&1
sysctl -p > /dev/null 2>&1 || true

mkdir -p /etc/strongswan.d
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

if [ -f /etc/ipsec.conf ]; then mv /etc/ipsec.conf /etc/ipsec.conf.bak.$(date +%s); fi
cat > /etc/ipsec.conf <<EOF
config setup
    charondebug="ike 1, knl 1, cfg 0"
    uniqueids=no
conn %default
    keyexchange=ikev1
    authby=secret
    keyingtries=%forever
    ike=aes256-sha1-modp1024,3des-sha1-modp1024!
    esp=aes256-sha1,3des-sha1!
    dpddelay=30
    dpdtimeout=120
    dpdaction=clear
conn L2TP-PSK-NAT
    rightsubnet=vhost:%priv
    also=L2TP-PSK-noNAT
conn L2TP-PSK-noNAT
    authby=secret
    pfs=no
    auto=add
    keyingtries=3
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

mkdir -p /etc/xl2tpd
if [ -f /etc/xl2tpd/xl2tpd.conf ]; then mv /etc/xl2tpd/xl2tpd.conf /etc/xl2tpd/xl2tpd.conf.bak.$(date +%s); fi
cat > /etc/xl2tpd/xl2tpd.conf <<EOF
[global]
ipsec saref = yes
listen-addr = 0.0.0.0
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

mkdir -p /etc/ppp
if [ -f /etc/ppp/options.xl2tpd ]; then mv /etc/ppp/options.xl2tpd /etc/ppp/options.xl2tpd.bak.$(date +%s); fi
cat > /etc/ppp/options.xl2tpd <<EOF
require-mschap-v2
ms-dns 8.8.8.8
ms-dns 1.1.1.1
auth
mtu 1200
mru 1000
crtscts
hide-password
modem
name l2tpd
proxyarp
lcp-echo-interval 1
lcp-echo-failure 3
EOF

touch /etc/ppp/chap-secrets
chmod 600 /etc/ppp/chap-secrets

mkdir -p /etc/ppp/ip-up.d
mkdir -p /etc/ppp/ip-down.d

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
LOCK_FILE="/dev/shm/l2tp_monitor.lock"
if [ -n "$PEERNAME" ] && [ -n "$IFNAME" ]; then
    (
        flock -x 200
        echo "${PEERNAME}:${IFNAME}" >> "$LOG_FILE"
    ) 200>"$LOCK_FILE"
fi
HOOKEOF
chmod +x $HOOK_UP

HOOK_DOWN="/etc/ppp/ip-down.d/00-panel-monitor"
cat > $HOOK_DOWN <<'HOOKEOF'
#!/bin/bash
LOG_FILE="/dev/shm/active_l2tp_users"
LOCK_FILE="/dev/shm/l2tp_monitor.lock"
if [ -n "$IFNAME" ]; then
    (
        flock -x 200
        sed -i "/:${IFNAME}$/d" "$LOG_FILE"
    ) 200>"$LOCK_FILE"
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

add_rule() {
    iptables -C "$@" 2>/dev/null || iptables -I "$@"
}

MAIN_IFACE=$(ip route get 1.1.1.1 | awk '{print $5; exit}')

add_rule INPUT -p udp --dport 500 -j ACCEPT
add_rule INPUT -p udp --dport 4500 -j ACCEPT
add_rule INPUT -p udp --dport 1701 -j ACCEPT

add_rule FORWARD -i ppp+ -o $MAIN_IFACE -j ACCEPT
add_rule FORWARD -i $MAIN_IFACE -o ppp+ -j ACCEPT

iptables -t nat -C POSTROUTING -s $VPN_SUBNET -o $MAIN_IFACE -j MASQUERADE 2>/dev/null || iptables -t nat -I POSTROUTING -s $VPN_SUBNET -o $MAIN_IFACE -j MASQUERADE

netfilter-persistent save > /dev/null 2>&1 || true

echo "L2TP Installed Successfully."
