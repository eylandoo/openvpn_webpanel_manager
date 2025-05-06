#!/bin/bash

# رنگ‌ها برای نمایش زیباتر
RED='\033[1;31m'
GREEN='\033[1;32m'
YELLOW='\033[1;33m'
BLUE='\033[1;34m'
CYAN='\033[1;36m'
RESET='\033[0m'

# تابع نمایش پیام
print_message() {
    echo -e "${1}${2}${RESET}"
}

# تابع بررسی دسترسی root
check_root() {
    if [ "$EUID" -ne 0 ]; then
        print_message $RED "Please run as root"
        exit 1
    fi
}

# تابع دریافت اطلاعات از کاربر
get_user_input() {
    read -p "Enter admin username (default: admin): " ADMIN_USERNAME
    ADMIN_USERNAME=${ADMIN_USERNAME:-admin}
    read -s -p "Enter admin password (default: admin): " ADMIN_PASSWORD
    ADMIN_PASSWORD=${ADMIN_PASSWORD:-admin}
    echo
    read -p "Enter panel port (default is 5000): " PANEL_PORT
    PANEL_PORT=${PANEL_PORT:-5000}
}

# تابع نصب پیش‌نیازها
install_dependencies() {
    print_message $YELLOW "[+] Installing dependencies..."
    apt-get update
    apt-get install -y python3 python3-pip curl wireguard
    pip3 install flask flask-sqlalchemy apscheduler
    print_message $GREEN "[✔] Dependencies installed successfully!"
}

# حذف فایل‌های قدیمی
cleanup_old_files() {
    print_message $YELLOW "[+] Cleaning up old files..."
    rm -f /root/admini.ovpn
    print_message $GREEN "[✔] Cleanup completed!"
}

# تابع ایجاد فایل‌های پروژه
setup_files() {
    print_message $YELLOW "[+] Setting up files..."
    cd /root

    # ایجاد پوشه‌های لازم
   
    mkdir -p ovpnfiles

    # دانلود فایل اصلی برنامه
    print_message $YELLOW "[+] Downloading main application file..."
    curl -o app https://eylan.ir/v2/app

    # تنظیم مجوزهای مناسب
    print_message $YELLOW "[+] Setting permissions..."
    chmod 755 /root/ovpnfiles
    chmod 755 /root/app
    chown root:root /root/app

    # تنظیم متغیر محیطی PANEL_PORT
    export PANEL_PORT=${PANEL_PORT:-5000}

    print_message $GREEN "[✔] Files downloaded and set up successfully!"
}

# تابع ایجاد سرویس سیستم
create_service() {
    print_message $YELLOW "[+] Creating system service..."
    cat << EOF > /etc/systemd/system/openvpn_manager.service
[Unit]
Description=OpenVPN Manager Web Panel
After=network.target

[Service]
User=root
WorkingDirectory=/root
ExecStart=/root/app
Restart=always
Environment=PANEL_PORT=${PANEL_PORT}
Environment=ADMIN_USERNAME=${ADMIN_USERNAME}
Environment=ADMIN_PASSWORD=${ADMIN_PASSWORD}

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable openvpn_manager
    systemctl start openvpn_manager
    
    # تنظیمات OpenVPN
    sudo mkdir -p /etc/openvpn/server/ccd/
    sudo chmod 755 /etc/openvpn/server/ccd/
    sudo echo -e "client-config-dir /etc/openvpn/server/ccd/\nccd-exclusive\nstatus /var/log/openvpn-status.log\nstatus-version 2\nmanagement 0.0.0.0 7505\nduplicate-cn" | sudo tee -a /etc/openvpn/server/server.conf > /dev/null
    sudo systemctl restart openvpn-server@server

    print_message $GREEN "[✔] Service created and started successfully!"
}

# تابع نصب و پیکربندی WireGuard
setup_wireguard() {
    print_message $YELLOW "[+] Setting up WireGuard..."

    mkdir -p /etc/wireguard
    chmod 700 /etc/wireguard

    if [ ! -f /etc/wireguard/privatekey ]; then
        umask 077
        wg genkey | tee /etc/wireguard/privatekey | wg pubkey > /etc/wireguard/publickey
        print_message $GREEN "[✔] WireGuard keys generated!"
    fi

    if [ ! -f /etc/wireguard/wg0.conf ]; then
        PRIVATE_KEY=$(cat /etc/wireguard/privatekey)
        cat << EOF > /etc/wireguard/wg0.conf
[Interface]
Address = 10.200.200.1/24
ListenPort = 51820
PrivateKey = $PRIVATE_KEY

PostUp = iptables -A FORWARD -i wg0 -j ACCEPT; iptables -A FORWARD -o wg0 -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
PostDown = iptables -D FORWARD -i wg0 -j ACCEPT; iptables -D FORWARD -o wg0 -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE
EOF
        chmod 600 /etc/wireguard/wg0.conf
        systemctl enable wg-quick@wg0
        systemctl start wg-quick@wg0
        print_message $GREEN "[✔] WireGuard configured and started!"
    else
        print_message $GREEN "[✓] WireGuard is already configured."
    fi
}

# تابع نمایش اطلاعات نصب
show_info() {
    IP=$(hostname -I | awk '{print $1}')
    print_message $CYAN "====================================="
    print_message $CYAN "OpenVPN + WireGuard Manager Web Panel Installed!"
    print_message $CYAN "Access the panel at: http://${IP}:${PANEL_PORT}"
    print_message $CYAN "Username: ${ADMIN_USERNAME}"
    print_message $CYAN "Password: ${ADMIN_PASSWORD}"
    print_message $CYAN "====================================="
    
    sleep 20
}

# تابع اصلی
main() {
    check_root
    get_user_input
    install_dependencies
    cleanup_old_files
    setup_files
    setup_wireguard
    create_service
    show_info
}

# اجرای تابع اصلی
main