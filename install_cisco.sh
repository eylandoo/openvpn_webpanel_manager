#!/bin/bash
set -e

CISCO_PORT="${1:-4443}"
export DEBIAN_FRONTEND=noninteractive

echo ">>> Updating and installing packages..."
apt-get update
apt-get install -y ocserv gnutls-bin iptables-persistent

mkdir -p /etc/ocserv
if [ ! -f /etc/ocserv/ocpasswd ]; then
    touch /etc/ocserv/ocpasswd
fi

cd /etc/ocserv

if [ ! -f /etc/ocserv/server-cert.pem ] || [ ! -f /etc/ocserv/server-key.pem ]; then
    echo ">>> Generating Certificates..."
    cat > ca.tmpl <<EOF
cn = "VPN CA"
organization = "Cisco VPN"
serial = 1
expiration_days = 3650
ca
signing_key
cert_signing_key
crl_signing_key
EOF
    certtool --generate-privkey --outfile ca-key.pem
    certtool --generate-self-signed --load-privkey ca-key.pem --template ca.tmpl --outfile ca-cert.pem
    
    MY_IP=$(curl -s https://api.ipify.org || hostname -I | awk '{print $1}')
    
    cat > server.tmpl <<EOF
cn = "$MY_IP"
organization = "Cisco VPN"
expiration_days = 3650
signing_key
encryption_key
tls_www_server
EOF
    certtool --generate-privkey --outfile server-key.pem
    certtool --generate-certificate --load-privkey server-key.pem --load-ca-certificate ca-cert.pem --load-ca-privkey ca-key.pem --template server.tmpl --outfile server-cert.pem
    rm -f ca.tmpl server.tmpl
fi

if [ -f /etc/ocserv/ocserv.conf ]; then
    mv /etc/ocserv/ocserv.conf /etc/ocserv/ocserv.conf.bak.$(date +%s)
fi

echo ">>> Writing Config..."
cat > /etc/ocserv/ocserv.conf <<EOF
auth = "plain[passwd=/etc/ocserv/ocpasswd]"
tcp-port = $CISCO_PORT
udp-port = $CISCO_PORT
run-as-user = nobody
run-as-group = daemon
socket-file = /var/run/ocserv-socket
server-cert = /etc/ocserv/server-cert.pem
server-key = /etc/ocserv/server-key.pem
ca-cert = /etc/ocserv/ca-cert.pem
isolate-workers = false
max-clients = 1024
max-same-clients = 0
keepalive = 32400
dpd = 10
mobile-dpd = 25
switch-to-tcp-timeout = 25
try-mtu-discovery = true
server-leaked-dns = true
cert-user-oid = 0.9.2342.19200300.100.1.1
tls-priorities = "NORMAL:%SERVER_PRECEDENCE:%COMPAT:-VERS-SSL3.0"
auth-timeout = 240
min-reauth-time = 300
max-ban-score = 50
ban-reset-time = 300
cookie-timeout = 300
deny-roaming = false
rekey-time = 172800
rekey-method = ssl
use-occtl = true
pid-file = /var/run/ocserv.pid
device = vpns
predictable-ips = false
default-domain = example.com
ipv4-network = 192.168.100.0
ipv4-netmask = 255.255.255.0
dns = 8.8.8.8
dns = 1.1.1.1
route = default
cisco-client-compat = true
dtls-legacy = true
EOF

echo ">>> Applying System Settings..."
sed -i 's/#net.ipv4.ip_forward=1/net.ipv4.ip_forward=1/' /etc/sysctl.conf
sysctl -p > /dev/null || true

add_rule() {
    iptables -C "$@" 2>/dev/null || iptables -I "$@"
}

add_rule INPUT -p tcp --dport $CISCO_PORT -j ACCEPT
add_rule INPUT -p udp --dport $CISCO_PORT -j ACCEPT
add_rule FORWARD -i vpns+ -j ACCEPT
add_rule FORWARD -o vpns+ -j ACCEPT
add_rule FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu

MAIN_IFACE=$(ip route get 1.1.1.1 | awk '{print $5; exit}')
iptables -t nat -C POSTROUTING -s 192.168.100.0/24 -o $MAIN_IFACE -j MASQUERADE 2>/dev/null || iptables -t nat -I POSTROUTING -s 192.168.100.0/24 -o $MAIN_IFACE -j MASQUERADE

netfilter-persistent save > /dev/null 2>&1 || true

echo ">>> Restarting Service..."
systemctl unmask ocserv || true
systemctl enable ocserv
systemctl restart ocserv

if systemctl is-active --quiet ocserv; then
    echo "SUCCESS: Cisco AnyConnect (Ocserv) installed and running on port $CISCO_PORT"
else
    echo "ERROR: Failed to start Ocserv service. Check logs: journalctl -u ocserv"
    exit 1
fi
