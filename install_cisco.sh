#!/bin/bash
# Cisco AnyConnect (ocserv) Installer - Self Signed Version
# Args: $1 = Port (Default 4443)

CISCO_PORT="${1:-4443}"

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y ocserv gnutls-bin iptables-persistent

# Create Config Directory
mkdir -p /etc/ocserv
touch /etc/ocserv/ocpasswd
cd /etc/ocserv

# --- START: Generate Fake (Self-Signed) SSL Certificates ---
echo "Generating fake SSL certificates..."

# 1. CA Template
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

# 2. Generate CA Key and Cert
certtool --generate-privkey --outfile ca-key.pem
certtool --generate-self-signed --load-privkey ca-key.pem --template ca.tmpl --outfile ca-cert.pem

# 3. Server Template (Uses IP or generic name)
MY_IP=$(hostname -I | awk '{print $1}')
cat > server.tmpl <<EOF
cn = "$MY_IP"
organization = "Cisco VPN"
expiration_days = 3650
signing_key
encryption_key
tls_www_server
EOF

# 4. Generate Server Key and Cert
certtool --generate-privkey --outfile server-key.pem
certtool --generate-certificate --load-privkey server-key.pem --load-ca-certificate ca-cert.pem --load-ca-privkey ca-key.pem --template server.tmpl --outfile server-cert.pem

# Cleanup templates
rm ca.tmpl server.tmpl
echo "Fake SSL generated at /etc/ocserv/server-cert.pem"
# --- END: SSL Generation ---


# Create Config File (Pointing to the NEW fake certs)
cat > /etc/ocserv/ocserv.conf <<EOF
auth = "plain[passwd=/etc/ocserv/ocpasswd]"
tcp-port = $CISCO_PORT
udp-port = $CISCO_PORT
run-as-user = nobody
run-as-group = daemon
socket-file = /var/run/ocserv-socket

# Using Self-Signed Certs
server-cert = /etc/ocserv/server-cert.pem
server-key = /etc/ocserv/server-key.pem
ca-cert = /etc/ocserv/ca-cert.pem

isolate-workers = false
max-clients = 1024
max-same-clients = 0
keepalive = 32400
dpd = 90
mobile-dpd = 1800
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
predictable-ips = true
default-domain = example.com
ipv4-network = 192.168.100.0
ipv4-netmask = 255.255.255.0
dns = 8.8.8.8
dns = 1.1.1.1
route = default
cisco-client-compat = true
dtls-legacy = true
EOF

# Enable IP Forwarding
sed -i 's/#net.ipv4.ip_forward=1/net.ipv4.ip_forward=1/' /etc/sysctl.conf
sysctl -p

# Firewall Rules
iptables -I INPUT -p tcp --dport $CISCO_PORT -j ACCEPT
iptables -I INPUT -p udp --dport $CISCO_PORT -j ACCEPT
iptables -I FORWARD -i vpns+ -j ACCEPT
iptables -I FORWARD -o vpns+ -j ACCEPT
# Detect Main Interface dynamically
MAIN_IFACE=$(ip route get 1.1.1.1 | awk '{print $5; exit}')
iptables -t nat -I POSTROUTING -s 192.168.100.0/24 -o $MAIN_IFACE -j MASQUERADE
netfilter-persistent save > /dev/null 2>&1 || true

# Enable and Restart Service
systemctl unmask ocserv || true
systemctl enable ocserv
systemctl restart ocserv

echo "✅ Cisco AnyConnect (ocserv) installed on port $CISCO_PORT with Self-Signed SSL."
