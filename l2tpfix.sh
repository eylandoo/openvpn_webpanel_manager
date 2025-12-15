(
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

if [ -f /etc/ipsec.conf ]; then
    sed -i 's/dpddelay=.*/dpddelay=5/' /etc/ipsec.conf
    sed -i 's/dpdtimeout=.*/dpdtimeout=10/' /etc/ipsec.conf
fi

mkdir -p /etc/ppp/ip-up.d /etc/ppp/ip-down.d

if [ ! -f /etc/ppp/ip-up ] || ! grep -q "run-parts" /etc/ppp/ip-up; then
    echo '#!/bin/bash' > /etc/ppp/ip-up
    echo '/bin/run-parts /etc/ppp/ip-up.d' >> /etc/ppp/ip-up
    chmod +x /etc/ppp/ip-up
fi

if [ ! -f /etc/ppp/ip-down ] || ! grep -q "run-parts" /etc/ppp/ip-down; then
    echo '#!/bin/bash' > /etc/ppp/ip-down
    echo '/bin/run-parts /etc/ppp/ip-down.d' >> /etc/ppp/ip-down
    chmod +x /etc/ppp/ip-down
fi

cat > /etc/ppp/ip-up.d/00-panel-monitor <<'EOF'
#!/bin/bash
LOG_FILE="/dev/shm/active_l2tp_users"
if [ -n "$PEERNAME" ] && [ -n "$IFNAME" ]; then
    echo "${PEERNAME}:${IFNAME}" >> "$LOG_FILE"
fi
EOF
chmod +x /etc/ppp/ip-up.d/00-panel-monitor

cat > /etc/ppp/ip-down.d/00-panel-monitor <<'EOF'
#!/bin/bash
LOG_FILE="/dev/shm/active_l2tp_users"
if [ -n "$IFNAME" ]; then
    sed -i "/:${IFNAME}$/d" "$LOG_FILE"
fi
if [ -f "/var/run/$IFNAME.pid" ]; then
    rm -f "/var/run/$IFNAME.pid"
fi
EOF
chmod +x /etc/ppp/ip-down.d/00-panel-monitor

rm -f /dev/shm/active_l2tp_users
touch /dev/shm/active_l2tp_users
chmod 666 /dev/shm/active_l2tp_users

systemctl restart strongswan-starter
systemctl restart xl2tpd
echo "✅ L2TP Ultimate Turbo Fix Applied!"
)