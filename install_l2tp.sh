#!/bin/bash


IPSEC_PSK="EylanPanelKey123"
VPN_IP_RANGE="192.168.42.10-192.168.42.250"
VPN_LOCAL_IP="192.168.42.1"

echo "--- [1/6] Updating and Installing Packages ---"
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y strongswan xl2tpd ppp net-tools

echo "--- [2/6] Configuring IPsec (StrongSwan) ---"
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

cat > /etc/ipsec.secrets <<EOF
: PSK "$IPSEC_PSK"
EOF
chmod 600 /etc/ipsec.secrets

echo "--- [3/6] Configuring L2TP (xl2tpd) ---"
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
lcp-echo-interval 30
lcp-echo-failure 4
EOF

echo "--- [4/6] Creating Secrets File ---"
touch /etc/ppp/chap-secrets
chmod 600 /etc/ppp/chap-secrets

echo "--- [5/6] Injecting Monitoring Hooks ---"

HOOK_UP="/etc/ppp/ip-up.d/00-panel-monitor"
cat > $HOOK_UP <<'EOF'
#!/bin/bash
# Hook script executed when a user connects
# $PEERNAME = Username, $IFNAME = Interface (ppp0)

LOG_FILE="/dev/shm/active_l2tp_users"
LOCK_FILE="/dev/shm/l2tp_monitor.lock"

if [ -n "$PEERNAME" ] && [ -n "$IFNAME" ]; then
    (
        flock -x 200
        echo "${PEERNAME}:${IFNAME}" >> "$LOG_FILE"
    ) 200>"$LOCK_FILE"
fi
EOF
chmod +x $HOOK_UP

HOOK_DOWN="/etc/ppp/ip-down.d/00-panel-monitor"
cat > $HOOK_DOWN <<'EOF'
#!/bin/bash
# Hook script executed when a user disconnects

LOG_FILE="/dev/shm/active_l2tp_users"
LOCK_FILE="/dev/shm/l2tp_monitor.lock"

if [ -n "$PEERNAME" ]; then
    (
        flock -x 200
        sed -i "/^${PEERNAME}:/d" "$LOG_FILE"
    ) 200>"$LOCK_FILE"
fi
EOF
chmod +x $HOOK_DOWN

echo "--- [6/6] Restarting Services ---"
systemctl restart strongswan-starter
systemctl enable strongswan-starter
systemctl restart xl2tpd
systemctl enable xl2tpd

# Firewall Rules
iptables -A INPUT -p udp --dport 500 -j ACCEPT
iptables -A INPUT -p udp --dport 4500 -j ACCEPT
iptables -A INPUT -p udp --dport 1701 -j ACCEPT
iptables -t nat -A POSTROUTING -s 192.168.42.0/24 -j MASQUERADE
iptables -A FORWARD -s 192.168.42.0/24 -j ACCEPT
iptables -A FORWARD -d 192.168.42.0/24 -j ACCEPT
netfilter-persistent save > /dev/null 2>&1

echo "✅ L2TP Installed Successfully."
