#!/bin/bash

cat <<'EOF' > /etc/ppp/ip-up.d/00-panel-monitor
#!/bin/bash
LOG_FILE="/dev/shm/active_l2tp_users"
if [ -n "$PEERNAME" ] && [ -n "$IFNAME" ]; then
    echo "${PEERNAME}:${IFNAME}" >> "$LOG_FILE"
fi
EOF
chmod +x /etc/ppp/ip-up.d/00-panel-monitor

cat <<'EOF' > /etc/ppp/ip-down.d/00-panel-monitor
#!/bin/bash
LOG_FILE="/dev/shm/active_l2tp_users"
if [ -n "$IFNAME" ]; then
    sed -i "/:${IFNAME}$/d" "$LOG_FILE"
fi
EOF
chmod +x /etc/ppp/ip-down.d/00-panel-monitor

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

touch /dev/shm/active_l2tp_users
chmod 666 /dev/shm/active_l2tp_users

systemctl restart xl2tpd
systemctl restart strongswan-starter
echo "✅ L2TP Monitoring Fixed Successfully."
