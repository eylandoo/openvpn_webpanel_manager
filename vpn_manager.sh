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

# رنگ‌ها برای نمایش زیباتر
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
    echo -e "${GREEN}[✔] OpenVPN Web Panel has been uninstalled successfully!${RESET}"
}
check_openvpn_installed() {
    command -v openvpn &>/dev/null && echo "installed" || echo "not_installed"
}

check_web_panel_installed() {
    systemctl is-active --quiet openvpn_manager && echo "installed" || echo "not_installed"
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
