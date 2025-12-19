#!/bin/bash

echo "--- Starting Surgical L2TP Fix ---"

echo "1. Fixing IPsec Config for Windows/Modems..."
if [ -f /etc/ipsec.conf ]; then cp /etc/ipsec.conf /etc/ipsec.conf.bak.$(date +%s); fi
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

echo "2. Fixing xl2tpd & PPP settings..."
cat > /etc/xl2tpd/xl2tpd.conf <<EOF
[global]
port = 1701
access control = no

[lns default]
ip range = 192.168.42.10-192.168.42.250
local ip = 192.168.42.1
require chap = yes
refuse pap = yes
require authentication = yes
name = l2tpd
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

echo "3. Fixing Agent Hooks (PID Cleanup)..."

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

echo "4. Restarting Services..."
systemctl restart strongswan-starter
systemctl restart xl2tpd

echo "--- Fix Done! Secret and Users were NOT touched. ---"
