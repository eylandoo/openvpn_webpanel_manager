#!/bin/bash

set -e

# Colors
GREEN='\033[1;32m'
YELLOW='\033[1;33m'
RED='\033[1;31m'
CYAN='\033[1;36m'
RESET='\033[0m'

BACKHAUL_URL="https://github.com/Musixal/Backhaul/releases/download/v0.6.5/backhaul_linux_amd64.tar.gz"
BACKHAUL_ARCHIVE="backhaul_linux_amd64.tar.gz"
BACKHAUL_BIN="/root/backhaul"

get_next_web_port() {
    base=2060
    used_ports=$(grep -h "web_port =" /root/*tcp*.toml /root/*udp*.toml 2>/dev/null | awk '{print $3}' | sort -n | uniq)

    while true; do
        if ! echo "$used_ports" | grep -qx "$base"; then
            echo "$base"
            return
        fi
        ((base++))
    done
}

show_active_services() {
    if [[ -f "$BACKHAUL_BIN" ]]; then
        echo -e "${GREEN}✅ Backhaul core is installed at $BACKHAUL_BIN${RESET}"
    else
        echo -e "${RED}❌ Backhaul core is NOT installed.${RESET}"
    fi

    echo -e "${CYAN}🔰 Active Tunnels:${RESET}"

    for conf in /root/*tcp*.toml /root/*udp*.toml; do
        [ -f "$conf" ] || continue

        name=$(basename "$conf" .toml)
        proto=$(echo "$name" | grep -oE 'tcp|udp')
        port=$(echo "$name" | cut -d'-' -f1)
        web_port=$(grep -m 1 "web_port" "$conf" 2>/dev/null | awk '{print $3}')

        # بررسی 50 خط آخر لاگ برای عبارات مشخص اتصال
        last_logs=$(journalctl -u "${name}.service" --no-pager -n 50 2>/dev/null | awk '{print tolower($0)}')

        if echo "$last_logs" | grep -Eq "control channel established successfully|server started successfully|client with remote address.*started successfully"; then
            status="🟢 connected"
        elif systemctl is-active "${name}.service" &>/dev/null; then
            status="🟡 running, not connected"
        else
            status="🔴 not running"
        fi

        if grep -q "\[server\]" "$conf"; then
            ports=$(grep -A 10 "ports" "$conf" 2>/dev/null | grep -oE '[0-9]+' | paste -sd "," -)
            echo -e " - ${port}-${proto} [Iran] : Ports → ${ports:-N/A} | Web → ${web_port:-N/A} | Status: $status"
        else
            remote_ip=$(grep "remote_addr" "$conf" 2>/dev/null | cut -d'"' -f2)
            echo -e " - ${port}-${proto} [Kharej] → ${remote_ip:-N/A} | Web → ${web_port:-N/A} | Status: $status"
        fi
    done
}

install_backhaul() {
    if [[ -f "$BACKHAUL_BIN" ]]; then
        echo -e "\n${GREEN}[✔] Backhaul is already installed at $BACKHAUL_BIN${RESET}\n"
        sleep 2
        return
    fi
    echo -e "\n${YELLOW}[+] Downloading Backhaul core...${RESET}"
    wget -q "$BACKHAUL_URL" -O "$BACKHAUL_ARCHIVE" || {
        echo -e "${RED}[✘] Failed to download Backhaul.${RESET}"
        sleep 2
        return
    }
    echo -e "${YELLOW}[+] Extracting...${RESET}"
    tar -xzf "$BACKHAUL_ARCHIVE"
    chmod +x backhaul
    mv backhaul "$BACKHAUL_BIN"
    echo -e "\n${GREEN}🎉 Backhaul successfully installed! Location: $BACKHAUL_BIN${RESET}\n"
    sleep 3
}

configure_iran_server() {
    while true; do
        echo -e "${YELLOW}[?] Select tunnel protocol:${RESET}"
        echo "1) TCP"
        echo "2) UDP"
        echo "0) Back to main menu"
        read -p "Enter your choice [0-2]: " proto_choice

        if [[ "$proto_choice" == "1" ]]; then
            proto="tcp"
        elif [[ "$proto_choice" == "2" ]]; then
            proto="udp"
        elif [[ "$proto_choice" == "0" ]]; then
            return
        else
            echo -e "${RED}[✘] Invalid choice.${RESET}"
            continue
        fi

        read -p "Enter main tunnel port (e.g. 8080): " BASE_PORT
        TUNNEL_PORT=$BASE_PORT
        CONFIG_NAME="${TUNNEL_PORT}-${proto}"
        CONFIG_PATH="/root/${CONFIG_NAME}.toml"

        while [[ -f "$CONFIG_PATH" ]]; do
            ((TUNNEL_PORT++))
            CONFIG_NAME="${TUNNEL_PORT}-${proto}"
            CONFIG_PATH="/root/${CONFIG_NAME}.toml"
        done

        read -p "Enter tunnel token: " TUNNEL_TOKEN
        read -p "Enter tunnel ports (comma-separated): " TUNNEL_PORTS_RAW

        WEB_PORT=$(get_next_web_port)

        IFS=',' read -ra PORT_ARRAY <<< "$TUNNEL_PORTS_RAW"
        PORT_LINES=""
        for p in "${PORT_ARRAY[@]}"; do
            PORT_LINES+="\"$p\",
"
        done
        PORT_LINES=$(echo -e "$PORT_LINES" | sed '$s/,$//')

        SERVICE_PATH="/etc/systemd/system/${CONFIG_NAME}.service"

        cat > "$CONFIG_PATH" <<EOF
[server]
bind_addr = "0.0.0.0:$TUNNEL_PORT"
transport = "$proto"
token = "$TUNNEL_TOKEN"
heartbeat = 40
channel_size = 2048
sniffer = true
web_port = $WEB_PORT
sniffer_log = "/root/backhaul.json"
log_level = "info"
ports = [
$PORT_LINES
]
EOF

        chmod 755 "$CONFIG_PATH"

        cat > "$SERVICE_PATH" <<EOF
[Unit]
Description=Backhaul Reverse Tunnel Service
After=network.target

[Service]
Type=simple
ExecStart=$BACKHAUL_BIN -c $CONFIG_PATH
Restart=always
RestartSec=3
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF

        systemctl daemon-reload
        systemctl enable "${CONFIG_NAME}.service"
        systemctl start "${CONFIG_NAME}.service"

        echo -e "${GREEN}[✔] $CONFIG_NAME service started.${RESET}"
        break
    done
}

configure_kharej_server() {
    while true; do
        echo -e "${YELLOW}[?] Select protocol for Kharej server:${RESET}"
        echo "1) TCP"
        echo "2) UDP"
        echo "0) Back to main menu"
        read -p "Enter your choice [0-2]: " proto_choice

        if [[ "$proto_choice" == "1" ]]; then
            proto="tcp"
        elif [[ "$proto_choice" == "2" ]]; then
            proto="udp"
        elif [[ "$proto_choice" == "0" ]]; then
            return
        else
            echo -e "${RED}[✘] Invalid choice.${RESET}"
            continue
        fi

        read -p "Enter remote server address (e.g. 1.2.3.4:6644): " REMOTE_ADDR
        read -p "Enter tunnel token (authentication): " TUNNEL_TOKEN

        WEB_PORT=$(get_next_web_port)
        PORT_FROM_REMOTE=$(echo "$REMOTE_ADDR" | cut -d':' -f2)
        CONFIG_NAME="${PORT_FROM_REMOTE}-${proto}"
        CONFIG_PATH="/root/${CONFIG_NAME}.toml"
        SERVICE_PATH="/etc/systemd/system/${CONFIG_NAME}.service"

        cat > "$CONFIG_PATH" <<EOF
[client]
remote_addr = "$REMOTE_ADDR"
transport = "$proto"
token = "$TUNNEL_TOKEN"
connection_pool = 8
aggressive_pool = false
keepalive_period = 75
dial_timeout = 10
nodelay = true
retry_interval = 3
sniffer = true
web_port = $WEB_PORT
sniffer_log = "/root/backhaul.json"
log_level = "info"
EOF

        chmod 755 "$CONFIG_PATH"

        cat > "$SERVICE_PATH" <<EOF
[Unit]
Description=Backhaul Client Service
After=network.target

[Service]
Type=simple
ExecStart=$BACKHAUL_BIN -c $CONFIG_PATH
Restart=always
RestartSec=3
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF

        systemctl daemon-reload
        systemctl enable "${CONFIG_NAME}.service"
        systemctl start "${CONFIG_NAME}.service"

        echo -e "${GREEN}[✔] $CONFIG_NAME client service started.${RESET}"
        break
    done
}

uninstall_config() {
    echo -e "${YELLOW}[?] Scanning for active Backhaul configurations...${RESET}"
    configs=()
    for file in /root/*-*.toml; do
        [ -e "$file" ] || continue
        name=$(basename "$file" .toml)
        if systemctl list-units --type=service --all | grep -q "${name}.service"; then
            configs+=("$name")
        fi
    done

    if [ ${#configs[@]} -eq 0 ]; then
        echo -e "${RED}[✘] No Backhaul configurations found.${RESET}"
        return
    fi

    echo -e "${YELLOW}[?] Select a configuration to uninstall:${RESET}"
    for i in "${!configs[@]}"; do
        echo "$((i+1))) ${configs[$i]}"
    done
    echo "0) Back to main menu"

    read -p "Enter your choice [0-${#configs[@]}]: " sel

    if [[ "$sel" == "0" ]]; then
        return
    fi

    index=$((sel-1))
    selected="${configs[$index]}"

    SERVICE_NAME="${selected}.service"
    CONFIG_FILE="/root/${selected}.toml"
    SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}"

    echo -e "${YELLOW}[!] Stopping and removing $SERVICE_NAME...${RESET}"
    systemctl stop "$SERVICE_NAME" 2>/dev/null || true
    systemctl disable "$SERVICE_NAME" 2>/dev/null || true
    rm -f "$SERVICE_FILE"
    rm -f "$CONFIG_FILE"
    systemctl daemon-reload

    echo -e "${GREEN}[✔] $selected uninstalled successfully.${RESET}"
}

full_uninstall() {
    echo -e "${YELLOW}[!] This will remove all Backhaul configs, services, and binaries.${RESET}"
    read -p "Are you sure? (yes/no): " confirm
    if [[ "$confirm" != "yes" ]]; then
        echo -e "${RED}Cancelled.${RESET}"
        return
    fi

    echo -e "${YELLOW}[+] Stopping and removing TCP/UDP related services...${RESET}"
    for svc in /etc/systemd/system/*tcp*.service /etc/systemd/system/*udp*.service; do
        [ -f "$svc" ] || continue
        svc_name=$(basename "$svc")
        systemctl stop "$svc_name" 2>/dev/null || true
        systemctl disable "$svc_name" 2>/dev/null || true
        rm -f "$svc"
    done

    echo -e "${YELLOW}[+] Removing related .toml config files...${RESET}"
    find /root -type f \( -name "*tcp*.toml" -o -name "*udp*.toml" \) -exec rm -f {} \;

    echo -e "${YELLOW}[+] Removing Backhaul-related binaries (except backhaul.sh)...${RESET}"
    find /root -maxdepth 1 -type f -name "*backhaul*" ! -name "backhaul.sh" -exec rm -f {} \;

    systemctl daemon-reload
    echo -e "${GREEN}[✔] Clean uninstall completed safely.${RESET}"
}

main_menu() {
    while true; do
        clear
        show_active_services
        echo -e "${CYAN}"
        echo "┌────────────────────────────────────────────────────────────────────────────┐"
        echo "│                                                                            │"
        echo "│   ███████╗██╗   ██╗██╗      █████╗ ███╗   ██╗                              │"
        echo "│   ██╔════╝╚██╗ ██╔╝██║     ██╔══██╗████╗  ██║                              │"
        echo "│   █████╗   ╚████╔╝ ██║     ███████║██╔██╗ ██║                              │"
        echo "│   ██╔══╝    ╚██╔╝  ██║     ██╔══██║██║╚██╗██║                              │"
        echo "│   ███████╗   ██║   ███████╗██║  ██║██║ ╚████║                              │"
        echo "│   ╚══════╝   ╚═╝   ╚══════╝╚═╝  ╚═╝╚═╝  ╚═══╝                              │"
        echo "│                                                                            │"
        echo "│   █████████╗██╗   ██╗███╗   ██╗███╗   ██╗███████╗██╗                       │"
        echo "│   ╚══██╔══╝██║   ██║████╗  ██║████╗  ██║██╔════╝██║                        │"
        echo "│      ██║   ██║   ██║██╔██╗ ██║██╔██╗ ██║█████╗  ██║                        │"
        echo "│      ██║   ██║   ██║██║╚██╗██║██║╚██╗██║██╔══╝  ██║                        │"
        echo "│      ██║   ╚██████╔╝██║ ╚████║██║ ╚████║███████╗███████╗                   │"
        echo "│      ╚═╝    ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚══════╝                   │"
        echo "│                                                                            │"
        echo "├────────────────────────────────────────────────────────────────────────────┤"
        echo "│   1. Install Backhaul Core                                                 │"
        echo "│   2. Configure Iran Server                                                 │"
        echo "│   3. Configure Kharej Server                                               │"
        echo "│   4. Remove Individual Configuration                                       │"
        echo "│   5. Full Uninstall (All configs + core)                                   │"
        echo "│   0. Exit                                                                  │"
        echo "└────────────────────────────────────────────────────────────────────────────┘"
        echo -e "${RESET}"
        read -p "   Select an option [0-5]: " choice

        case $choice in
            1) install_backhaul ;;
            2) configure_iran_server ;;
            3) configure_kharej_server ;;
            4) uninstall_config ;;
            5) full_uninstall ;;
            0) exit 0 ;;
            *) echo -e "${RED}\n   Invalid option! Please try again.${RESET}" && sleep 1 ;;
        esac
    done
}

main_menu
