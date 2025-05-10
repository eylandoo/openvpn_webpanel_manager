#!/bin/bash

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

wget -q -O /root/install_vpn.sh https://eylan.ir/v2/install_vpn.sh
chmod +x /root/install_vpn.sh

wget -q -O /root/install_web_panel.sh https://eylan.ir/v2/install_web_panel.sh
chmod +x /root/install_web_panel.sh

RED='\033[1;31m'
GREEN='\033[1;32m'
YELLOW='\033[1;33m'
BLUE='\033[1;34m'
CYAN='\033[1;36m'
RESET='\033[0m'

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
    rm -rf /root/app /root/ovpnfiles /root/instance/users.db
    rm -rf /etc/ssl/openvpn_manager/* /etc/ssl/openvpn_manager/.* 2>/dev/null
    echo -e "${GREEN}[✔] OpenVPN Web Panel has been uninstalled successfully!${RESET}"
}

check_openvpn_installed() {
    command -v openvpn &>/dev/null && echo "installed" || echo "not_installed"
}

check_web_panel_installed() {
    [[ -f /root/app ]] && echo "installed" || echo "not_installed"
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

    if [[ ! -f /root/app ]]; then
        echo -e "${RED}OpenVPN Web Panel is not installed!${RESET}"
        return
    fi

    ENV_VARS=$(systemctl show openvpn_manager --property=Environment | sed 's/^Environment=//')
    eval "$ENV_VARS"

    SERVER_HOST=$(hostname -I | awk '{print $1}')
    PROTOCOL="http"
    SSL_DIR="/etc/ssl/openvpn_manager"
    CERT_FILE="$SSL_DIR/cert.pem"
    KEY_FILE="$SSL_DIR/key.pem"

    if [[ -f "$CERT_FILE" && -f "$KEY_FILE" ]]; then
        PROTOCOL="https"
        CN_DOMAIN=$(openssl x509 -in "$CERT_FILE" -noout -subject | sed -n 's/^subject=CN = \(.*\)$/\1/p')
        [[ -n "$CN_DOMAIN" ]] && SERVER_HOST="$CN_DOMAIN"
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

    echo -e "\n${CYAN}========= Log Monitoring =========${RESET}"
    echo -e "${YELLOW}OpenVPN Core Logs:${RESET}"
    echo -e "${BLUE}journalctl -u openvpn-server@server -e -f${RESET}"
    echo -e "${YELLOW}Web Panel Logs:${RESET}"
    echo -e "${BLUE}journalctl -u openvpn_manager -e -f${RESET}"

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

    echo
    read -p "Press Enter to return to menu..."
}



show_menu() {
    reset
    echo -e "${CYAN}====================================="
    echo -e "      🚀 OpenVPN Management Menu     "
    echo -e "=====================================${RESET}"

    openvpn_status=$(check_openvpn_installed)
    web_panel_status=$(check_web_panel_installed)

    [[ "$openvpn_status" == "installed" ]] && echo -e "${GREEN}[✔] OpenVPN Core is installed${RESET}" || echo -e "${RED}[✘] OpenVPN Core is NOT installed${RESET}"
    [[ "$web_panel_status" == "installed" ]] && echo -e "${GREEN}[✔] OpenVPN Web Panel is installed${RESET}" || echo -e "${RED}[✘] OpenVPN Web Panel is NOT installed${RESET}"

    echo ""

    options=()

    if [[ "$openvpn_status" == "not_installed" ]]; then
        options+=("Install OpenVPN Core")
    fi

    if [[ "$openvpn_status" == "installed" && "$web_panel_status" == "not_installed" ]]; then
        options+=("Install OpenVPN Web Panel")
    fi

    if [[ "$openvpn_status" == "installed" ]]; then
        options+=("Uninstall OpenVPN")
    fi

    if [[ "$web_panel_status" == "installed" ]]; then
        options+=("Uninstall OpenVPN Web Panel")
        options+=("Show Web Panel Info")
        options+=("Panel Settings")
    fi

    options+=("Exit")

    for i in "${!options[@]}"; do
        index=$((i+1))
        text="${options[$i]}"
        case "$text" in
            "Install OpenVPN Core"|"Install OpenVPN Web Panel") color="${GREEN}" ;;
            "Uninstall OpenVPN"|"Uninstall OpenVPN Web Panel") color="${YELLOW}" ;;
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
        "Uninstall OpenVPN")
            echo -e "${YELLOW}Are you sure you want to uninstall OpenVPN? (y/n): ${RESET}"
            read confirm
            [[ "$confirm" =~ ^[yY]$ ]] && uninstall_openvpn || echo -e "${YELLOW}Uninstall canceled.${RESET}" ;;
        "Uninstall OpenVPN Web Panel")
            echo -e "${YELLOW}Are you sure you want to uninstall OpenVPN Web Panel? (y/n): ${RESET}"
            read confirm
            [[ "$confirm" =~ ^[yY]$ ]] && uninstall_web_panel || echo -e "${YELLOW}Uninstall canceled.${RESET}" ;;
        "Show Web Panel Info")
            show_panel_info ;;
        "Panel Settings")
            show_panel_settings_menu ;;
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
