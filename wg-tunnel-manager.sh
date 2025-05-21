#!/bin/bash

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m'

# Configuration
WG_INTERFACE="wg1"
WG_PORT="6464"
WG_NETWORK="10.100.100.0/24"
IRAN_IP="10.100.100.1"
PEERS_FILE="/etc/wireguard/peers.json"
CONFIG_BACKUP_DIR="/etc/wireguard/backups"
MTU_SIZE="1420"
PERSISTENT_KEEPALIVE="25"
DEFAULT_SSH_PORT="22"
DEFAULT_SSH_USER="root"
IRAN_PUBLIC_IP_FILE="/etc/wireguard/iran_public_ip.txt"

# DNS Settings - Improved with multiple fallback servers
PRIMARY_DNS="8.8.8.8"
SECONDARY_DNS="1.1.1.1"
TERTIARY_DNS="9.9.9.9"
DNS_SETTINGS="$PRIMARY_DNS, $SECONDARY_DNS"


# ==============================================
# Initialize system
# ==============================================

init() {
    check_root
    install_dependencies
    init_filesystem
}

check_root() {
    [[ $EUID -ne 0 ]] && msg error "This script must be run as root!" && exit 1
}

msg() {
    local type="$1"; shift
    case "$type" in
        error) echo -e "${RED}✗ ERROR: $*${NC}" >&2 ;;
        success) echo -e "${GREEN}✓ SUCCESS: $*${NC}" ;;
        info) echo -e "${BLUE}ℹ INFO: $*${NC}" ;;
        warn) echo -e "${YELLOW}⚠ WARNING: $*${NC}" ;;
    esac
}

init_filesystem() {
    mkdir -p "$CONFIG_BACKUP_DIR"
    [[ ! -f "$PEERS_FILE" ]] && echo '[]' > "$PEERS_FILE"
}



fix_dns_if_broken() {
    current_dns=$(grep -E '^nameserver' /etc/resolv.conf | head -n 1 | awk '{print $2}')
    if [[ -z "$current_dns" || "$current_dns" == "127.0.0.53" ]]; then
        echo -e "${YELLOW}⚠ DNS seems broken or set to local stub — fixing...${NC}"
        chattr -i /etc/resolv.conf 2>/dev/null || true
        echo "nameserver 8.8.8.8" > /etc/resolv.conf
        echo "nameserver 8.8.4.4" >> /etc/resolv.conf
        chattr +i /etc/resolv.conf
        echo -e "${GREEN}✓ DNS reset to 8.8.8.8 and 8.8.4.4 and locked${NC}"
    else
        echo -e "${BLUE}ℹ DNS looks fine: $current_dns${NC}"
    fi
}

# ==============================================
# Status checking functions
# ==============================================

is_iran_installed() {
    [[ -f "/etc/wireguard/$WG_INTERFACE.conf" ]]
}

get_service_status() {
    if systemctl is-active --quiet wg-quick@$WG_INTERFACE; then
        echo -e "${GREEN}Active${NC}"
    else
        echo -e "${RED}Inactive${NC}"
    fi
}

get_peer_count() {
    if [[ -f "$PEERS_FILE" ]]; then
        jq length "$PEERS_FILE"
    else
        echo "0"
    fi
}

get_connected_peers() {
    wg show $WG_INTERFACE 2>/dev/null | grep -E '^peer:' | wc -l || echo "0"
}

check_peer_connection() {
    local peer_ip=$1
    local peer_pubkey=$2
    
    if ping -c 1 -W 2 "$peer_ip" >/dev/null 2>&1; then
        echo -e "${GREEN}Connected${NC}"
    elif wg show $WG_INTERFACE | grep -A 5 "$peer_pubkey" | grep -q "latest handshake"; then
        echo -e "${YELLOW}Handshake only${NC}"
    else
        echo -e "${RED}Disconnected${NC}"
    fi
}


install_dependencies() {
    msg info "Installing required dependencies..."
    apt-get update -y
    apt-get install -y wireguard wireguard-tools jq sshpass iptables
}


# ==============================================
# Enhanced header with peer status
# ==============================================

show_header() {
    clear
    echo -e "${MAGENTA}┌────────────────────────────────────────────────────────────┐${NC}"
    echo -e "${MAGENTA}│        WireGuard Reverse Tunnel Manager - Status           │${NC}"
    echo -e "${MAGENTA}├────────────────────────────────────────────────────────────┤${NC}"

    local service_status=$(get_service_status)
    local peer_count=$(get_peer_count)
    local connected_count=$(get_connected_peers)

    printf "${CYAN}│ %-69s │\n" "Service: $service_status"
    printf "${CYAN}│ %-58s │\n" "Peers: $peer_count     Connected: $connected_count"

    if is_iran_installed; then
        local iran_pubkey=$(grep -oP '(?<=PrivateKey = ).*' "/etc/wireguard/$WG_INTERFACE.conf" | wg pubkey | cut -c 1-16)
        printf "${CYAN}│ %-58s │\n" "Iran Public Key: $iran_pubkey..."
        printf "${CYAN}│ %-58s │\n" "IP: $IRAN_IP     Port: $WG_PORT"
    fi

    echo -e "${MAGENTA}└────────────────────────────────────────────────────────────┘${NC}"

    if [[ -f "$PEERS_FILE" && $(jq length "$PEERS_FILE") -gt 0 ]]; then
        echo -e "\n${CYAN}Active Peer Connections:${NC}"

echo -e "${CYAN}┌───────────────┬────────────────────┬───────────────────────┐${NC}"
echo -e "${CYAN}│ Private IP    │ Public IP          │ Status                │${NC}"
echo -e "${CYAN}├───────────────┼────────────────────┼───────────────────────┤${NC}"

jq -r '.[] | "\(.ip)|\(.public_ip)|\(.pubkey)"' "$PEERS_FILE" | while IFS='|' read -r ip public_ip pubkey; do
    status_raw=$(check_peer_connection "$ip" "$pubkey")
    
    # حذف رنگ ANSI برای محاسبه طول دقیق
    status_plain=$(echo -e "$status_raw" | sed 's/\x1B\[[0-9;]*[mK]//g')

    # تراز متن اصلی بدون رنگ
    status_padded=$(printf "%-21s" "$status_plain")

    # جایگزینی متن پد شده با رنگ واقعی
    status_colored=$(echo "$status_padded" | sed "s|$status_plain|$status_raw|")

    # چاپ نهایی با طول دقیق هر ستون
    printf "${CYAN}│ %-13s │ %-18s │ %s │\n" "$ip" "$public_ip" "$status_colored"
done

echo -e "${CYAN}└───────────────┴────────────────────┴───────────────────────┘${NC}"

    fi

    echo ""
}



# ==============================================
# Core functionality (working menu options)
# ==============================================

install_iran_server() {
    if is_iran_installed; then
        msg info "Iran server is already installed!"
        return
    fi

    msg info "Configuring Iran server..."

    # Detect default network interface
    DEFAULT_IFACE=$(ip route get 1 | awk '{print $5; exit}')
    if [[ -z "$DEFAULT_IFACE" ]]; then
        msg error "Could not detect default network interface!"
        exit 1
    fi

    # Cleanup previous configuration if exists
    systemctl stop wg-quick@$WG_INTERFACE 2>/dev/null || true
    ip link del $WG_INTERFACE 2>/dev/null || true

    # Generate keys
    PRIVATE_KEY=$(wg genkey)
    PUBLIC_KEY=$(echo "$PRIVATE_KEY" | wg pubkey)

    # Create WireGuard config file with improved DNS settings
    cat > "/etc/wireguard/$WG_INTERFACE.conf" <<EOF
[Interface]
Address = $IRAN_IP/24
ListenPort = $WG_PORT
PrivateKey = $PRIVATE_KEY
MTU = $MTU_SIZE
DNS = $DNS_SETTINGS
PostUp = iptables -A FORWARD -i $WG_INTERFACE -j ACCEPT; iptables -t nat -A POSTROUTING -o $DEFAULT_IFACE -j MASQUERADE; printf "nameserver $PRIMARY_DNS\nnameserver $SECONDARY_DNS\nnameserver $TERTIARY_DNS\n" > /etc/resolv.conf; chattr +i /etc/resolv.conf 2>/dev/null || true
PostDown = iptables -D FORWARD -i $WG_INTERFACE -j ACCEPT; iptables -t nat -D POSTROUTING -o $DEFAULT_IFACE -j MASQUERADE; chattr -i /etc/resolv.conf 2>/dev/null || true
EOF

    chmod 600 /etc/wireguard/$WG_INTERFACE.conf

    # Enable and start service
    systemctl enable --now wg-quick@$WG_INTERFACE >/dev/null 2>&1

    if systemctl is-active --quiet wg-quick@$WG_INTERFACE; then
        msg success "Iran WireGuard interface started successfully on $IRAN_IP"
    else
        msg error "Failed to start Iran WireGuard interface"
        exit 1
    fi

    # Add firewall rule if not exists
    if ! iptables -C INPUT -p udp --dport $WG_PORT -j ACCEPT 2>/dev/null; then
        iptables -A INPUT -p udp --dport $WG_PORT -j ACCEPT
    fi

    read -p "Enter the public IP of this Iran server: " IRAN_PUBLIC_IP
    echo "$IRAN_PUBLIC_IP" > "$IRAN_PUBLIC_IP_FILE"
}

add_foreign_server() {
    if ! is_iran_installed; then
        msg error "Iran server must be installed first!"
        return 1
    fi

    local NEXT_ID=$(jq length "$PEERS_FILE")
    local FOREIGN_IP="10.100.100.$((NEXT_ID + 2))"

    read -p "Enter foreign server public IP: " FIP
    read -p "Enter SSH port [$DEFAULT_SSH_PORT]: " SPORT
    SPORT=${SPORT:-$DEFAULT_SSH_PORT}
    read -p "Enter SSH username [$DEFAULT_SSH_USER]: " SUSER
    SUSER=${SUSER:-$DEFAULT_SSH_USER}
    read -s -p "Enter SSH password: " SPASS; echo ""

    local PKEY=$(wg genkey)
    local PUBKEY=$(echo "$PKEY" | wg pubkey)
    local PSK=$(wg genpsk)
    local IRAN_PUB=$(wg show $WG_INTERFACE public-key)
    local IRAN_PUBLIC_IP=$(cat "$IRAN_PUBLIC_IP_FILE")

    # Detect default interface
    local DEFAULT_IFACE=$(ip route get 1 | awk '{print $5; exit}')

    # Add to peers file
    jq ". += [{
        \"ip\": \"$FOREIGN_IP\",
        \"public_ip\": \"$FIP\",
        \"ssh_port\": \"$SPORT\",
        \"ssh_user\": \"$SUSER\",
        \"pubkey\": \"$PUBKEY\",
        \"psk\": \"$PSK\",
        \"added_at\": \"$(date +%Y-%m-%dT%H:%M:%S)\"
    }]" "$PEERS_FILE" > tmp.json && mv tmp.json "$PEERS_FILE"

    # Add to Iran config
    wg set $WG_INTERFACE peer "$PUBKEY" allowed-ips "$FOREIGN_IP/32" persistent-keepalive $PERSISTENT_KEEPALIVE preshared-key <(echo "$PSK")

    # Create remote config with improved DNS settings
    local REMOTE_CFG="[Interface]
Address = $FOREIGN_IP/24
PrivateKey = $PKEY
ListenPort = $WG_PORT
MTU = $MTU_SIZE
DNS = $DNS_SETTINGS

[Peer]
PublicKey = $IRAN_PUB
PresharedKey = $PSK
AllowedIPs = $IRAN_IP/32
Endpoint = $IRAN_PUBLIC_IP:$WG_PORT
PersistentKeepalive = $PERSISTENT_KEEPALIVE"

    # Install on foreign server with DNS fixes
    sshpass -p "$SPASS" ssh -o StrictHostKeyChecking=no -p "$SPORT" "$SUSER@$FIP" "
        sudo apt-get update
        sudo apt-get install -y wireguard wireguard-tools jq sshpass resolvconf iptables dnsutils

        # Cleanup previous config if exists
        sudo systemctl stop wg-quick@wg1 2>/dev/null || true
        sudo ip link del wg1 2>/dev/null || true

        # Create config and start service
        sudo mkdir -p /etc/wireguard
        echo '$REMOTE_CFG' | sudo tee /etc/wireguard/wg1.conf >/dev/null
        sudo chmod 600 /etc/wireguard/wg1.conf
        
        # Fix DNS settings
        sudo systemctl stop systemd-resolved 2>/dev/null || true
        sudo systemctl disable systemd-resolved 2>/dev/null || true
        printf \"nameserver $PRIMARY_DNS\nnameserver $SECONDARY_DNS\nnameserver $TERTIARY_DNS\n\" | sudo tee /etc/resolv.conf >/dev/null
        sudo chattr +i /etc/resolv.conf 2>/dev/null || true
        
        sudo systemctl enable wg-quick@wg1
        sudo wg-quick up wg1
    " && msg success "Foreign server configured successfully" || msg error "Failed to configure foreign server"
}


list_foreign_servers() {
    if [[ ! -f "$PEERS_FILE" ]] || [[ $(jq length "$PEERS_FILE") -eq 0 ]]; then
        msg info "No foreign servers configured"
        return
    fi

    echo -e "\n${GREEN}Configured Foreign Servers:${NC}"
    echo -e "${CYAN}┌────┬───────────────┬────────────────────┬────────────────────────────┬──────────────────────┐${NC}"
    echo -e "${CYAN}│ #  │ Private IP    │ Public IP          │ SSH Info                   │ Added At             │${NC}"
    echo -e "${CYAN}├────┼───────────────┼────────────────────┼────────────────────────────┼──────────────────────┤${NC}"

    local idx=0
    jq -r '.[] | "\(.ip)|\(.public_ip)|\(.ssh_user)@\(.public_ip):\(.ssh_port)|\(.added_at)"' "$PEERS_FILE" | while IFS='|' read -r ip public_ip ssh_info added_at; do
        idx=$((idx+1))
        printf "${CYAN}│ %-2s │ %-13s │ %-18s │ %-26s │ %-20s │\n" "$idx" "$ip" "$public_ip" "$ssh_info" "$added_at"
    done

    echo -e "${CYAN}└────┴───────────────┴────────────────────┴────────────────────────────┴──────────────────────┘${NC}"

    echo -e "\n${YELLOW}Connection Status:${NC}"
    jq -r '.[] | "\(.ip) \(.pubkey)"' "$PEERS_FILE" | while read -r ip pubkey; do
        status=$(check_peer_connection "$ip" "$pubkey")
        echo -e "$ip: $status"
    done
}


remove_foreign_peer() {
    list_foreign_servers
    local count=$(jq length "$PEERS_FILE")
    
    [[ $count -eq 0 ]] && return
    
    read -p "Select peer to remove (number): " IDX
    [[ ! "$IDX" =~ ^[0-9]+$ ]] || [[ $IDX -lt 1 ]] || [[ $IDX -gt $count ]] && msg error "Invalid selection" && return
    
    IDX=$((IDX - 1))
    local IP=$(jq -r ".[$IDX].ip" "$PEERS_FILE")
    local PUB=$(jq -r ".[$IDX].pubkey" "$PEERS_FILE")
    
    # Remove from WireGuard
    wg set $WG_INTERFACE peer "$PUB" remove
    
    # Remove from peers file
    jq "del(.[$IDX])" "$PEERS_FILE" > tmp.json && mv tmp.json "$PEERS_FILE"
    
    msg success "Removed peer $IP"
}

uninstall_iran() {
    read -p "Are you sure you want to uninstall the Iran tunnel? [y/N] " confirm
    [[ "$confirm" != "y" && "$confirm" != "Y" ]] && return
    
    systemctl stop wg-quick@$WG_INTERFACE
    systemctl disable wg-quick@$WG_INTERFACE
    rm -f "/etc/wireguard/$WG_INTERFACE.conf"
    msg success "Iran tunnel has been uninstalled"
}

# ==============================================
# Main menu
# ==============================================

show_menu() {
echo -e "${CYAN}"
        echo "┌────────────────────────────────────────────────────────────┐"
        echo "│                                                            │"
        echo "│   ███████╗██╗   ██╗██╗      █████╗ ███╗   ██╗              │"
        echo "│   ██╔════╝╚██╗ ██╔╝██║     ██╔══██╗████╗  ██║              │"
        echo "│   █████╗   ╚████╔╝ ██║     ███████║██╔██╗ ██║              │"
        echo "│   ██╔══╝    ╚██╔╝  ██║     ██╔══██║██║╚██╗██║              │"
        echo "│   ███████╗   ██║   ███████╗██║  ██║██║ ╚████║              │"
        echo "│   ╚══════╝   ╚═╝   ╚══════╝╚═╝  ╚═╝╚═╝  ╚═══╝              │"
        echo "│                                                            │"
        echo "│   █████████╗██╗   ██╗███╗   ██╗███╗   ██╗███████╗██╗       │"
        echo "│   ╚══██╔══╝██║   ██║████╗  ██║████╗  ██║██╔════╝██║        │"
        echo "│      ██║   ██║   ██║██╔██╗ ██║██╔██╗ ██║█████╗  ██║        │"
        echo "│      ██║   ██║   ██║██║╚██╗██║██║╚██╗██║██╔══╝  ██║        │"
        echo "│      ██║   ╚██████╔╝██║ ╚████║██║ ╚████║███████╗███████╗   │"
        echo "│      ╚═╝    ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚══════╝   │"
        echo "│                                                            │"
    echo -e "${MAGENTA}┌────────────────────────────────────────────────────────────┐${NC}"
    echo -e "${MAGENTA}│               WireGuard Tunnel - Main Menu                 │${NC}"
    echo -e "${MAGENTA}├────────────────────────────────────────────────────────────┤${NC}"
    echo -e "${CYAN}│ ${GREEN}1${CYAN}. Install Iran (Main) Server                              │${NC}"
    echo -e "${CYAN}│ ${GREEN}2${CYAN}. Add Foreign Server                                      │${NC}"
    echo -e "${CYAN}│ ${GREEN}3${CYAN}. List Foreign Servers                                    │${NC}"
    echo -e "${CYAN}│ ${GREEN}4${CYAN}. Remove a Foreign Server                                 │${NC}"
    echo -e "${CYAN}│ ${GREEN}5${CYAN}. Uninstall Iran Tunnel                                   │${NC}"
    echo -e "${CYAN}│ ${RED}0${CYAN}. Exit                                                    │${NC}"
    echo -e "${MAGENTA}└────────────────────────────────────────────────────────────┘${NC}"
}



# ==============================================
# Main execution
# ==============================================

main() {
    init
    
    while true; do
        show_header
        show_menu
        read -p $'\nSelect an option: ' opt
        
        case $opt in
            1) install_iran_server ;;
            2) add_foreign_server ;;
            3) list_foreign_servers ;;
            4) remove_foreign_peer ;;
            5) uninstall_iran ;;
            0) exit 0 ;;
            *) msg error "Invalid option" ;;
        esac
        
        [[ $opt -ne 0 ]] && read -p $'\nPress Enter to continue...'
    done
}

main
 
