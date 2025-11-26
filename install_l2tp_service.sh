#!/bin/bash

# ==========================================
# OpenVPN Manager - L2TP/IPsec Installer Module
# ==========================================

IPSEC_PSK="eylan123"
VPN_IP_RANGE="192.168.42.0/24"
VPN_LOCAL_IP="192.168.42.1"
VPN_REMOTE_IP_RANGE="192.168.42.10-192.168.42.250"

echo "--- Starting L2TP/IPsec Installation ---"

echo "[1/6] Installing required packages..."
apt-get update -q
DEBIAN_FRONTEND=noninteractive apt-get install -y -q libreswan xl2tpd ppp lsof

echo "[2/6] Configuring IPsec..."
cat > /etc/ipsec.conf <<EOF
version 2.0

config setup
    dumpdir=/var/run/pluto/
    nat_traversal=yes
    virtual_private=%v4:10.0.0.0/8,%v4:192.168.0.0/16,%v4:172.16.0.0/12
    protostack=netkey

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
    left=%defaultroute
    leftprotoport=17/1701
    right=%any
    rightprotoport=17/%any
    dpddelay=40
    dpdtimeout=130
    dpdaction=clear
EOF

cat > /etc/ipsec.secrets <<EOF
%any: PSK "$IPSEC_PSK"
EOF

echo "[3/6] Configuring XL2TPD..."
cat > /etc/xl2tpd/xl2tpd.conf <<EOF
[global]
port = 1701
auth file = /etc/ppp/chap-secrets
debug avp = yes
debug network = yes
debug state = yes
debug tunnel = yes

[lns default]
ip range = $VPN_REMOTE_IP_RANGE
local ip = $VPN_LOCAL_IP
require chap = yes
refuse pap = yes
require authentication = yes
name = LinuxVPNserver
ppp debug = yes
pppoptfile = /etc/ppp/options.xl2tpd
length bit = yes
EOF

cat > /etc/ppp/options.xl2tpd <<EOF
ipcp-accept-local
ipcp-accept-remote
ms-dns 8.8.8.8
ms-dns 8.8.4.4
noccp
auth
crtscts
idle 1800
mtu 1410
mru 1410
nodefaultroute
debug
lock
proxyarp
connect-delay 5000
EOF

touch /etc/ppp/chap-secrets
chmod 600 /etc/ppp/chap-secrets

echo "[4/6] Installing Monitoring Hooks..."

cat > /etc/ppp/ip-up.d/z_l2tp_monitor <<'EOF'
#!/bin/bash

LOG_FILE="/dev/shm/active_l2tp_users"

if [ -n "$PEERNAME" ] && [ -n "$IFNAME" ]; then
    echo "$PEERNAME:$IFNAME" >> $LOG_FILE
fi
EOF

cat > /etc/ppp/ip-down.d/z_l2tp_monitor <<'EOF'
#!/bin/bash

LOG_FILE="/dev/shm/active_l2tp_users"

if [ -n "$PEERNAME" ] && [ -n "$IFNAME" ]; then
    sed -i "/^$PEERNAME:$IFNAME$/d" $LOG_FILE
fi
EOF

chmod +x /etc/ppp/ip-up.d/z_l2tp_monitor
chmod +x /etc/ppp/ip-down.d/z_l2tp_monitor

touch /dev/shm/active_l2tp_users
chmod 666 /dev/shm/active_l2tp_users

echo "[5/6] Configuring Network & Firewall..."
sysctl -w net.ipv4.ip_forward=1
sed -i 's/#net.ipv4.ip_forward=1/net.ipv4.ip_forward=1/g' /etc/sysctl.conf

iptables -I INPUT -p udp --dport 500 -j ACCEPT
iptables -I INPUT -p udp --dport 4500 -j ACCEPT
iptables -I INPUT -p udp --dport 1701 -j ACCEPT

if dpkg -l | grep -q netfilter-persistent; then
    netfilter-persistent save
fi

echo "[6/6] Restarting Services..."
systemctl restart ipsec
systemctl enable ipsec
systemctl restart xl2tpd
systemctl enable xl2tpd

echo "------------------------------------------------"
echo "✅ L2TP/IPsec Installation Completed Successfully!"
echo "   - PSK: $IPSEC_PSK"
echo "   - Monitoring File: /dev/shm/active_l2tp_users"
echo "------------------------------------------------"
