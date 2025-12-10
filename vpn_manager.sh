#!/bin/bash

OS_VERSION=$(lsb_release -rs)
ARCHITECTURE=$(uname -m)

if [[ "$OS_VERSION" != "22.04" || "$ARCHITECTURE" != "x86_64" ]]; then
    echo -e "\033[1;31m[✘] This installer only supports Ubuntu 22.04 with x86_64 architecture.\033[0m"
    echo -e "\033[1;33m    Your system: Ubuntu $OS_VERSION - Architecture: $ARCHITECTURE\033[0m"
    exit 1
fi

stty erase ^? 2>/dev/null

if [[ "$1" == "panel" && "$2" == "restart" ]]; then
    systemctl restart openvpn_manager && echo -e "\033[1;32m[✔] Web Panel restarted.\033[0m" || echo -e "\033[1;31m[✘] Failed to restart Web Panel.\033[0m"
    exit 0
elif [[ "$1" == "openvpn" && "$2" == "restart" ]]; then
    systemctl restart openvpn-server@server && echo -e "\033[1;32m[✔] OpenVPN Core restarted.\033[0m" || echo -e "\033[1;31m[✘] Failed to restart OpenVPN Core.\033[0m"
    exit 0
fi

if [ ! -f /usr/local/bin/vpn_manager ]; then
    SCRIPT_PATH=$(readlink -f "$0")
    cp "$SCRIPT_PATH" /usr/local/bin/vpn_manager
    chmod +x /usr/local/bin/vpn_manager
    echo -e "\033[1;32m[✔] You can now run this tool anytime by typing: vpn_manager\033[0m"
fi

wget -q -O /root/install_vpn.sh https://eylanpanel.top/install_vpn.sh
chmod +x /root/install_vpn.sh

wget -q -O /root/install_web_panel.sh https://eylanpanel.top/install_web_panel.sh
chmod +x /root/install_web_panel.sh

RED='\033[1;31m'
GREEN='\033[1;32m'
YELLOW='\033[1;33m'
BLUE='\033[1;34m'
CYAN='\033[1;36m'
RESET='\033[0m'

draw_progress_bar() {
    local duration=${1}
    local block_char="█"
    local empty_char="░"
    local width=50
    local percentage=0
    local step=$(echo "scale=3; 100 / ($duration * 10)" | bc)
    
    echo -ne "\n"
    
    for ((i=0; i<=$((duration * 10)); i++)); do
        percentage=$(echo "scale=0; $i * $step" | bc)
        if (( $(echo "$percentage > 100" | bc -l) )); then percentage=100; fi
        
        local filled_len=$(echo "scale=0; $width * $percentage / 100" | bc)
        local empty_len=$((width - filled_len))
        
        local bar=""
        for ((j=0; j<filled_len; j++)); do bar="${bar}${block_char}"; done
        for ((j=0; j<empty_len; j++)); do bar="${bar}${empty_char}"; done
        
        echo -ne "\r${BLUE}[${bar}] ${percentage}%${RESET}"
        sleep 0.1
    done
    echo -ne "\n"
}

uninstall_openvpn() {
    echo -e "${YELLOW}[+] Uninstalling OpenVPN...${RESET}"
    apt-get remove --purge openvpn -y
    rm -rf /etc/openvpn /root/openvpn.sh /root/answers.txt
    echo -e "${GREEN}[✔] OpenVPN has been uninstalled successfully!${RESET}"
}

uninstall_web_panel() {
    echo -e "${YELLOW}[+] Uninstalling OpenVPN Web Panel...${RESET}"
    systemctl stop openvpn_manager
    systemctl disable openvpn_manager
    rm -rf /etc/systemd/system/openvpn_manager.service
    rm -rf /root/app.bin
    rm -rf /root/instance/users.db
    rm -rf /root/ovpnfiles /root/instance/users.db
    rm -rf /etc/ssl/openvpn_manager/* /etc/ssl/openvpn_manager/.* 2>/dev/null
    echo -e "${GREEN}[✔] OpenVPN Web Panel has been uninstalled successfully!${RESET}"
}

uninstall_cisco() {
    echo -e "${YELLOW}[+] Uninstalling Cisco AnyConnect (ocserv)...${RESET}"
    systemctl stop ocserv
    systemctl disable ocserv
    apt-get remove --purge ocserv -y
    rm -rf /etc/ocserv
    echo -e "${GREEN}[✔] Cisco AnyConnect has been uninstalled successfully!${RESET}"
}

uninstall_l2tp() {
    echo -e "${YELLOW}[+] Uninstalling L2TP/IPsec...${RESET}"
    systemctl stop xl2tpd
    systemctl disable xl2tpd
    systemctl stop ipsec
    systemctl disable ipsec
    apt-get remove --purge xl2tpd strongswan strongswan-pki -y
    rm -rf /etc/xl2tpd /etc/ipsec.conf /etc/ipsec.secrets /etc/ipsec.d
    echo -e "${GREEN}[✔] L2TP/IPsec has been uninstalled successfully!${RESET}"
}

check_openvpn_installed() {
    command -v openvpn &>/dev/null && echo "installed" || echo "not_installed"
}

check_web_panel_installed() {
    if systemctl is-active --quiet openvpn_manager; then
        echo "installed"
    else
        echo "not_installed"
    fi
}

check_cisco_installed() {
    command -v ocserv &>/dev/null && echo "installed" || echo "not_installed"
}

check_l2tp_installed() {
    command -v xl2tpd &>/dev/null && echo "installed" || echo "not_installed"
}

change_username() {
    read -p "Enter new username: " new_user
    sed -i "s/\(Environment=.*\)ADMIN_USERNAME=[^ ]*/\1ADMIN_USERNAME=$new_user/" /etc/systemd/system/openvpn_manager.service
    systemctl daemon-reload
    systemctl restart openvpn_manager
    echo -e "${GREEN}[✔] Username updated and panel restarted.${RESET}"
}

change_password() {
    read -p "Enter new password: " new_pass
    sed -i "s/\(Environment=.*\)ADMIN_PASSWORD=[^ ]*/\1ADMIN_PASSWORD=$new_pass/" /etc/systemd/system/openvpn_manager.service
    systemctl daemon-reload
    systemctl restart openvpn_manager
    echo -e "${GREEN}[✔] Password updated and panel restarted.${RESET}"
}

change_port() {
    read -p "Enter new panel port: " new_port
    sed -i "s/\(Environment=.*\)PANEL_PORT=[^ ]*/\1PANEL_PORT=$new_port/" /etc/systemd/system/openvpn_manager.service
    systemctl daemon-reload
    systemctl restart openvpn_manager
    echo -e "${GREEN}[✔] Port updated and panel restarted.${RESET}"
}

show_panel_settings_menu() {
    while true; do
        clear
        echo -e "${CYAN}========= Panel Settings =========${RESET}"
        echo -e "1) Change Username"
        echo -e "2) Change Password"
        echo -e "3) Change Port"
        echo -e "4) Back to Main Menu"
        echo
        read -p "Choose an option: " opt
        case $opt in
            1) change_username ;;
            2) change_password ;;
            3) change_port ;;
            4) break ;;
            *) echo -e "${RED}Invalid option. Try again.${RESET}"; sleep 1 ;;
        esac
    done
}

show_panel_info() {
    echo -e "${CYAN}========= OpenVPN Web Panel Info =========${RESET}"

    local panel_status=$(check_web_panel_installed)
    if [[ "$panel_status" == "not_installed" ]]; then
        echo -e "${RED}OpenVPN Web Panel is not installed or not running!${RESET}"
        read -p "Press Enter to return to menu..."
        return
    fi

    ENV_VARS=$(systemctl show openvpn_manager --property=Environment | sed 's/^Environment=//')
    if [[ -z "$ENV_VARS" ]]; then
        echo -e "${RED}[✘] Could not retrieve panel environment variables. Service might not be fully configured or running correctly.${RESET}"
        read -p "Press Enter to return to menu..."
        return
    fi

    eval "$ENV_VARS"

    SERVER_HOST=$(hostname -I | awk '{print $1}')
    PROTOCOL="http"
    
    SSL_DIR_DEFAULT="/etc/ssl/openvpn_manager"
    SSL_DIR_LIVE="/etc/ssl/openvpn_manager/live"

    if [[ -f "$SSL_DIR_DEFAULT/cert.pem" && -f "$SSL_DIR_DEFAULT/key.pem" ]]; then
        PROTOCOL="https"
        CN_DOMAIN=$(openssl x509 -in "$SSL_DIR_DEFAULT/cert.pem" -noout -subject | sed -n 's/^subject=CN = \(.*\)$/\1/p')
        [[ -n "$CN_DOMAIN" ]] && SERVER_HOST="$CN_DOMAIN"
    elif [[ -d "$SSL_DIR_LIVE" ]]; then
        FIRST_DOMAIN_DIR=$(ls -d "$SSL_DIR_LIVE"/*/ 2>/dev/null | head -n 1)
        if [[ -n "$FIRST_DOMAIN_DIR" ]]; then
            DOMAIN_NAME=$(basename "$FIRST_DOMAIN_DIR")
            if [[ -f "$FIRST_DOMAIN_DIR/fullchain.pem" && -f "$FIRST_DOMAIN_DIR/privkey.pem" ]] || [[ -f "$FIRST_DOMAIN_DIR/cert.pem" && -f "$FIRST_DOMAIN_DIR/key.pem" ]]; then
                PROTOCOL="https"
                SERVER_HOST="$DOMAIN_NAME"
            fi
        fi
    fi

    echo -e "${GREEN}Panel Address: ${RESET}${PROTOCOL}://${SERVER_HOST}:${PANEL_PORT}"
    echo -e "${GREEN}Username:      ${RESET}${ADMIN_USERNAME}"
    echo -e "${GREEN}Password:      ${RESET}${ADMIN_PASSWORD}"

    echo -e "\n${CYAN}========= Shortcut Command =========${RESET}"
    echo -e "${YELLOW}To run this tool anytime, just type:${RESET}"
    echo -e "${BLUE}vpn_manager${RESET}"

    echo -e "\n${CYAN}========= Service Commands =========${RESET}"
    echo -e "${YELLOW}To restart OpenVPN Core:${RESET}"
    echo -e "${BLUE}systemctl restart openvpn-server@server${RESET}"
    echo -e "${YELLOW}To restart Web Panel:${RESET}"
    echo -e "${BLUE}systemctl restart openvpn_manager${RESET}"
    echo -e "${YELLOW}To restart Cisco AnyConnect:${RESET}"
    echo -e "${BLUE}systemctl restart ocserv${RESET}"
    echo -e "${YELLOW}To restart L2TP/IPsec:${RESET}"
    echo -e "${BLUE}systemctl restart xl2tpd${RESET}"

    echo -e "\n${CYAN}========= Log Monitoring =========${RESET}"
    echo -e "${YELLOW}OpenVPN Core Logs:${RESET}"
    echo -e "${BLUE}journalctl -u openvpn-server@server -e -f${RESET}"
    echo -e "${YELLOW}Web Panel Logs:${RESET}"
    echo -e "${BLUE}journalctl -u openvpn_manager -e -f${RESET}"
    echo -e "${YELLOW}Cisco AnyConnect Logs:${RESET}"
    echo -e "${BLUE}journalctl -u ocserv -e -f${RESET}"
    echo -e "${YELLOW}L2TP/IPsec Logs:${RESET}"
    echo -e "${BLUE}journalctl -u xl2tpd -e -f${RESET}"

    echo -e "\n${CYAN}========= Service Status =========${RESET}"
    
    if systemctl is-active --quiet openvpn-server@server; then
        echo -e "${GREEN}[✔] OpenVPN Core service is running${RESET}"
    else
        echo -e "${RED}[✘] OpenVPN Core service is NOT running${RESET}"
    fi

    if systemctl is-active --quiet openvpn_manager; then
        echo -e "${GREEN}[✔] Web Panel service is running${RESET}"
    else
        echo -e "${RED}[✘] Web Panel service is NOT running${RESET}"
    fi

    if systemctl is-active --quiet ocserv; then
        echo -e "${GREEN}[✔] Cisco AnyConnect service is running${RESET}"
    else
        echo -e "${RED}[✘] Cisco AnyConnect service is NOT running${RESET}"
    fi

    if systemctl is-active --quiet xl2tpd; then
        echo -e "${GREEN}[✔] L2TP service is running${RESET}"
    else
        echo -e "${RED}[✘] L2TP service is NOT running${RESET}"
    fi

    echo
    read -p "Press Enter to return to menu..."
}

show_menu() {
    reset
    echo -e "${CYAN}"
    echo "███████╗██╗   ██╗██╗      █████╗ ███╗   ██╗"
    echo "██╔════╝╚██╗ ██╔╝██║     ██╔══██╗████╗  ██║"
    echo "█████╗   ╚████╔╝ ██║     ███████║██╔██╗ ██║"
    echo "██╔══╝    ╚██╔╝  ██║     ██╔══██║██║╚██╗██║"
    echo "███████╗   ██║   ███████╗██║  ██║██║ ╚████║"
    echo "╚══════╝   ╚═╝   ╚══════╝╚═╝  ╚═╝╚═╝  ╚═══╝"
    echo
    echo "██████╗  █████╗ ███╗   ██╗███████╗██╗      "
    echo "██╔══██╗██╔══██╗████╗  ██║██╔════╝██║      "
    echo "██████╔╝███████║██╔██╗ ██║█████╗  ██║      "
    echo "██╔═══╝ ██╔══██║██║╚██╗██║██╔══╝  ██║      "
    echo "██║     ██║  ██║██║ ╚████║███████╗███████╗ "
    echo "╚═╝     ╚═╝  ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝ "
    echo -e "${RESET}"
    echo -e "${CYAN}====================================="
    echo -e "      🚀 VPN Management Dashboard    "
    echo -e "=====================================${RESET}"

    openvpn_status=$(check_openvpn_installed)
    web_panel_status=$(check_web_panel_installed)
    cisco_status=$(check_cisco_installed)
    l2tp_status=$(check_l2tp_installed)

    [[ "$openvpn_status" == "installed" ]] && echo -e "${GREEN}[✔] OpenVPN Core     : Installed${RESET}" || echo -e "${RED}[✘] OpenVPN Core     : Not Installed${RESET}"
    [[ "$web_panel_status" == "installed" ]] && echo -e "${GREEN}[✔] OpenVPN Web Panel: Installed${RESET}" || echo -e "${RED}[✘] OpenVPN Web Panel: Not Installed${RESET}"
    [[ "$cisco_status" == "installed" ]] && echo -e "${GREEN}[✔] Cisco AnyConnect : Installed${RESET}" || echo -e "${RED}[✘] Cisco AnyConnect : Not Installed${RESET}"
    [[ "$l2tp_status" == "installed" ]] && echo -e "${GREEN}[✔] L2TP/IPsec       : Installed${RESET}" || echo -e "${RED}[✘] L2TP/IPsec       : Not Installed${RESET}"

    echo ""

    options=()

    if [[ "$openvpn_status" == "not_installed" ]]; then
        options+=("Install OpenVPN Core")
    fi

    if [[ "$openvpn_status" == "installed" && "$web_panel_status" == "not_installed" ]]; then
        options+=("Install OpenVPN Web Panel")
    fi

    if [[ "$cisco_status" == "not_installed" ]]; then
        options+=("Install Cisco AnyConnect")
    fi

    if [[ "$l2tp_status" == "not_installed" ]]; then
        options+=("Install L2TP/IPsec")
    fi

    echo "-------------------------------------"

    if [[ "$openvpn_status" == "installed" ]]; then
        options+=("Uninstall OpenVPN Core")
    fi

    if [[ "$web_panel_status" == "installed" ]]; then
        options+=("Uninstall OpenVPN Web Panel")
        options+=("Show Web Panel Info")
        options+=("Panel Settings")
        options+=("Update Web Panel")
    fi

    if [[ "$cisco_status" == "installed" ]]; then
        options+=("Uninstall Cisco AnyConnect")
    fi

    if [[ "$l2tp_status" == "installed" ]]; then
        options+=("Uninstall L2TP/IPsec")
    fi

    options+=("Exit")

    for i in "${!options[@]}"; do
        index=$((i+1))
        text="${options[$i]}"
        case "$text" in
            "Install"*) color="${GREEN}" ;;
            "Uninstall"*) color="${YELLOW}" ;;
            "Exit") color="${RED}" ;;
            *) color="${RESET}" ;;
        esac
        echo -e " $index) ${color}${text}${RESET}"
    done

    echo
    read -p "Select an option: " choice

    if [[ "$choice" =~ ^[0-9]+$ ]] && (( choice >= 1 && choice <= ${#options[@]} )); then
        action="${options[$((choice-1))]}"
    else
        echo -e "${RED}Invalid choice! Please select a valid number.${RESET}"
        sleep 1
        return
    fi

    case $action in
        "Install OpenVPN Core")
            echo -e "${YELLOW}Installing OpenVPN...${RESET}"
            bash install_vpn.sh ;;
            
        "Install OpenVPN Web Panel")
            echo -e "${YELLOW}Installing OpenVPN Web Panel...${RESET}"
            bash install_web_panel.sh ;;

        "Install Cisco AnyConnect")
            clear
            echo -e "${CYAN}Downloading Cisco Installation Script...${RESET}"
            wget -q -O /root/install_cisco.sh https://raw.githubusercontent.com/eylandoo/openvpn_webpanel_manager/main/install_cisco.sh
            chmod +x /root/install_cisco.sh
            echo -e "${GREEN}Download Complete.${RESET}"
            echo -e "${YELLOW}Starting Installation Process...${RESET}"
            draw_progress_bar 2
            clear
            bash /root/install_cisco.sh
            rm -f /root/install_cisco.sh
            echo -e "${GREEN}Installation Finalizing...${RESET}"
            draw_progress_bar 1
            echo -e "${GREEN}[✔] Cisco AnyConnect Installation Completed.${RESET}"
            read -p "Press Enter to return to menu..." ;;

        "Install L2TP/IPsec")
            clear
            echo -e "${CYAN}Downloading L2TP Installation Script...${RESET}"
            wget -q -O /root/install_l2tp.sh https://raw.githubusercontent.com/eylandoo/openvpn_webpanel_manager/main/install_l2tp.sh
            chmod +x /root/install_l2tp.sh
            echo -e "${GREEN}Download Complete.${RESET}"
            echo -e "${YELLOW}Starting Installation Process...${RESET}"
            draw_progress_bar 2
            clear
            bash /root/install_l2tp.sh
            rm -f /root/install_l2tp.sh
            echo -e "${GREEN}Installation Finalizing...${RESET}"
            draw_progress_bar 1
            echo -e "${GREEN}[✔] L2TP/IPsec Installation Completed.${RESET}"
            read -p "Press Enter to return to menu..." ;;
            
        "Uninstall OpenVPN Core")
            echo -e "${YELLOW}Are you sure you want to uninstall OpenVPN? (y/n): ${RESET}"
            read confirm
            [[ "$confirm" =~ ^[yY]$ ]] && uninstall_openvpn || echo -e "${YELLOW}Uninstall canceled.${RESET}" ;;
            
        "Uninstall OpenVPN Web Panel")
            echo -e "${YELLOW}Are you sure you want to uninstall OpenVPN Web Panel? (y/n): ${RESET}"
            read confirm
            [[ "$confirm" =~ ^[yY]$ ]] && uninstall_web_panel || echo -e "${YELLOW}Uninstall canceled.${RESET}" ;;

        "Uninstall Cisco AnyConnect")
            echo -e "${YELLOW}Are you sure you want to uninstall Cisco AnyConnect? (y/n): ${RESET}"
            read confirm
            [[ "$confirm" =~ ^[yY]$ ]] && uninstall_cisco || echo -e "${YELLOW}Uninstall canceled.${RESET}" ;;

        "Uninstall L2TP/IPsec")
            echo -e "${YELLOW}Are you sure you want to uninstall L2TP/IPsec? (y/n): ${RESET}"
            read confirm
            [[ "$confirm" =~ ^[yY]$ ]] && uninstall_l2tp || echo -e "${YELLOW}Uninstall canceled.${RESET}" ;;
            
        "Show Web Panel Info")
            show_panel_info ;;
            
        "Panel Settings")
            show_panel_settings_menu ;;
            
        "Update Web Panel")
            echo -e "${YELLOW}Updating Web Panel...${RESET}"
            wget -q -O /root/update_app.sh https://eylanpanel.top/update_app.sh && chmod +x /root/update_app.sh && /root/update_app.sh
            read -p "Press Enter to return to menu..." ;;
            
        "Exit")
            echo -e "${GREEN}Exiting...${RESET}"
            exit 0 ;;
        *)
            echo -e "${RED}Invalid choice! Please select again.${RESET}" ;;
    esac
}

while true; do
    show_menu
done
