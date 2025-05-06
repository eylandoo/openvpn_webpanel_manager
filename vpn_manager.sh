#!/bin/bash
wget -q -O /root/install_vpn.sh https://eylan.ir/v2/install_vpn.sh
chmod +x /root/install_vpn.sh
# رنگ‌ها برای نمایش زیباتر
RED='\033[1;31m'
GREEN='\033[1;32m'
YELLOW='\033[1;33m'
BLUE='\033[1;34m'
CYAN='\033[1;36m'
RESET='\033[0m'

# تابع بررسی وضعیت نصب OpenVPN
check_openvpn_installed() {
    if command -v openvpn &> /dev/null; then
        echo "installed"
    else
        echo "not_installed"
    fi
}

# تابع بررسی وضعیت نصب پنل وب
check_web_panel_installed() {
    if systemctl is-active --quiet openvpn_manager; then
        echo "installed"
    else
        echo "not_installed"
    fi
}

# تابع حذف OpenVPN
uninstall_openvpn() {
    echo -e "${YELLOW}[+] Uninstalling OpenVPN...${RESET}"
    sudo apt-get remove --purge openvpn -y
    sudo rm -rf /etc/openvpn
    sudo rm -rf /root/openvpn.sh
    sudo rm -rf /root/answers.txt
# حذف تمام فایل‌های .ovpn در مسیر /root/
    echo -e "${YELLOW}[+] Removing all .ovpn files in /root/...${RESET}"
    rm -f /root/*.ovpn
    echo -e "${GREEN}[✔] OpenVPN has been uninstalled successfully!${RESET}"
    sleep 2
}

# تابع حذف پنل وب
uninstall_web_panel() {
    echo -e "${YELLOW}[+] Uninstalling OpenVPN Web Panel...${RESET}"
    systemctl stop openvpn_manager
    systemctl disable openvpn_manager
    rm -rf /etc/systemd/system/openvpn_manager.service
    rm -rf /root/app /root/ovpnfiles
    rm /root/instance/users.db
    echo -e "${GREEN}[✔] OpenVPN Web Panel has been uninstalled successfully!${RESET}"
    sleep 2
}

# نمایش منوی اصلی
show_menu() {
    clear
    echo -e "${CYAN}====================================="
    echo -e "      🚀 OpenVPN Management Menu     "
    echo -e "=====================================${RESET}"

    openvpn_status=$(check_openvpn_installed)
    web_panel_status=$(check_web_panel_installed)

    if [[ "$openvpn_status" == "installed" ]]; then
        echo -e "${GREEN}[✔] OpenVPN Core is installed${RESET}"
        option1_status="${RED}[DISABLED]${RESET}"
        option2_status="${GREEN}[AVAILABLE]${RESET}"
        option3_status="${GREEN}[AVAILABLE]${RESET}"
    else
        echo -e "${RED}[✘] OpenVPN Core is NOT installed${RESET}"
        option1_status="${GREEN}[AVAILABLE]${RESET}"
        option2_status="${RED}[DISABLED]${RESET}"
        option3_status="${RED}[DISABLED]${RESET}"
    fi

    if [[ "$web_panel_status" == "installed" ]]; then
        echo -e "${GREEN}[✔] OpenVPN Web Panel is installed${RESET}"
        option2_status="${RED}[DISABLED]${RESET}"
        option4_status="${GREEN}[AVAILABLE]${RESET}"
    else
        echo -e "${RED}[✘] OpenVPN Web Panel is NOT installed${RESET}"
        option4_status="${RED}[DISABLED]${RESET}"
    fi

    echo ""
    echo -e " 1) Install OpenVPN Core $option1_status"
    echo -e " 2) Install OpenVPN Web Panel $option2_status"
    echo -e " 3) Uninstall OpenVPN $option3_status"
    echo -e " 4) Uninstall OpenVPN Web Panel $option4_status"
    echo -e " 5) Exit"
    echo ""
    read -p "Select an option: " choice
}

# اجرای انتخاب کاربر
while true; do
    show_menu
    case $choice in
        1)
            if [[ "$(check_openvpn_installed)" == "installed" ]]; then
                echo -e "${RED}OpenVPN is already installed!${RESET}"
                sleep 2
            else
                echo -e "${YELLOW}Installing OpenVPN...${RESET}"
                bash install_vpn.sh
                sleep 3
            fi
            ;;
        2)
            if [[ "$(check_web_panel_installed)" == "installed" ]]; then
                echo -e "${RED}OpenVPN Web Panel is already installed!${RESET}"
                sleep 2
            elif [[ "$(check_openvpn_installed)" == "not_installed" ]]; then
                echo -e "${RED}Please install OpenVPN Core first!${RESET}"
                sleep 2
            else
                echo -e "${YELLOW}Installing OpenVPN Web Panel...${RESET}"
                bash install_web_panel.sh
                sleep 3
            fi
            ;;
        3)
            if [[ "$(check_openvpn_installed)" == "installed" ]]; then
                echo -e "${YELLOW}Are you sure you want to uninstall OpenVPN? (y/n): ${RESET}"
                read confirm
                if [[ "$confirm" == "y" || "$confirm" == "Y" ]]; then
                    uninstall_openvpn
                else
                    echo -e "${YELLOW}Uninstall canceled.${RESET}"
                    sleep 2
                fi
            else
                echo -e "${RED}OpenVPN is not installed!${RESET}"
                sleep 2
            fi
            ;;
        4)
            if [[ "$(check_web_panel_installed)" == "installed" ]]; then
                echo -e "${YELLOW}Are you sure you want to uninstall OpenVPN Web Panel? (y/n): ${RESET}"
                read confirm
                if [[ "$confirm" == "y" || "$confirm" == "Y" ]]; then
                    uninstall_web_panel
                else
                    echo -e "${YELLOW}Uninstall canceled.${RESET}"
                    sleep 2
                fi
            else
                echo -e "${RED}OpenVPN Web Panel is not installed!${RESET}"
                sleep 2
            fi
            ;;
        5)
            echo -e "${GREEN}Exiting...${RESET}"
            exit 0
            ;;
        *)
            echo -e "${RED}Invalid choice! Please select again.${RESET}"
            sleep 2
            ;;
    esac
done