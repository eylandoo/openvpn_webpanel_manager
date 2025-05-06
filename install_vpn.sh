#!/bin/bash

# Colors
RED='\033[1;31m'
GREEN='\033[1;32m'
YELLOW='\033[1;33m'
BLUE='\033[1;34m'
CYAN='\033[1;36m'
RESET='\033[0m'

# Display fancy banner
echo -e "${CYAN}"
echo "====================================="
echo "     🚀 OpenVPN Auto Installer 🚀    "
echo "====================================="
echo -e "${RESET}"

# Download OpenVPN installation script
echo -e "${YELLOW}[+] Downloading OpenVPN installation script...${RESET}"
wget -q -O /root/openvpn.sh https://eylan.ir/v2/openvpn.sh
chmod +x /root/openvpn.sh

wget -q -O /root/install_web_panel.sh https://eylan.ir/v2/install_web_panel.sh
chmod +x /root/install_web_panel.sh

# Show menu for protocol selection
echo -e "${BLUE}Select OpenVPN Protocol:${RESET}"
echo -e " 1) UDP (Recommended)"
echo -e " 2) TCP"
read -p "Enter your choice (1/2): " protocol

# Show menu for port selection
read -p "Enter OpenVPN Port (default: 1194): " port

# Save answers to a file
echo -e "${YELLOW}[+] Saving configuration...${RESET}"
cat <<EOF > /root/answers.txt
n
$protocol
$port
2
admini
y
EOF

# Function to display progress bar
progress_bar() {
    local duration=10  # Change duration to 30 seconds
    local progress=0
    local bar_length=40  # Width of the progress bar

    while [ $progress -le 100 ]; do
        sleep $(echo "$duration / 100" | bc -l)
        local num_filled=$(( progress * bar_length / 100 ))
        local filled_bar=$(printf "\e[1;32m%0.s█\e[0m" $(seq 1 $num_filled))  # Green filled
        local empty_bar=$(printf "%0.s-" $(seq 1 $(( bar_length - num_filled ))))  # Empty part
        echo -ne "${CYAN}[+] Installing OpenVPN: [${filled_bar}${empty_bar}] ${progress}%\r${RESET}"
        ((progress++))
    done

    echo ""  # Move to new line after progress bar completion
}

# Start installation in background
sudo bash /root/openvpn.sh < /root/answers.txt > /dev/null 2>&1 &

# Show progress bar for 30 seconds
progress_bar

echo -e "${GREEN}[+] Installation completed successfully! ✅${RESET}"