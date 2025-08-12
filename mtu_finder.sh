#!/bin/bash

# ==============================================================================
# Script Name: Smart MTU & MSS Finder
# Description: Automatically finds the optimal MTU and MSS values for your server.
# Author:      eylan
# Version:     1.2
# ==============================================================================

# --- Configuration ---
# You can change this to a reliable host. 8.8.8.8 or your provider's gateway are good options.
TARGET_HOST="google.com"

# --- Colors for better output ---
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# --- Script Logic ---
echo -e "${BLUE}
===========================================
    Smart MTU & MSS Finder
===========================================
${NC}"

# Check for required commands
if ! command -v ping &> /dev/null || ! command -v ip &> /dev/null; then
    echo -e "${RED}Error: 'ping' or 'ip' command not found. Please install them.${NC}"
    exit 1
fi

# Auto-detect the default network interface
INTERFACE=$(ip route | grep '^default' | awk '{print $5}' | head -1)
if [ -z "$INTERFACE" ]; then
    echo -e "${YELLOW}Warning: Could not auto-detect default network interface. You'll need to specify it manually when applying settings.${NC}"
else
    echo -e "Auto-detected default interface: ${YELLOW}$INTERFACE${NC}"
fi

echo -e "Pinging ${YELLOW}${TARGET_HOST}${NC} to find the optimal MTU..."
echo "This may take a minute."
echo ""

# We start from 1500 (standard Ethernet MTU) and go down.
# The ping payload size needs to be MTU - 28 (20 bytes for IP header, 8 bytes for ICMP header).
optimal_mtu=0
for mtu in $(seq 1500 -1 1300); do
    packet_size=$((mtu - 28))
    
    # -M do => Set "Don't Fragment" (DF) bit
    # -c 1  => Send only 1 packet
    # -W 1  => Wait 1 second for a reply
    if ping -c 1 -M do -s "$packet_size" -W 1 "$TARGET_HOST" &> /dev/null; then
        optimal_mtu=$mtu
        break
    else
        # Print dots to show progress without spamming the screen
        echo -n "."
    fi
done

echo "" # Newline after progress dots

if [ "$optimal_mtu" -ne 0 ]; then
    mssfix=$((optimal_mtu - 40)) # MSS = MTU - 40 (20 bytes IP header + 20 bytes TCP header)

    echo -e "
${GREEN}===========================================
            ✨  RESULTS  ✨
===========================================
${NC}
The highest MTU value that works without fragmentation is: ${YELLOW}${optimal_mtu}${NC}

Based on this, the recommended settings are:

    🔹 ${GREEN}Optimal MTU:${NC}  ${YELLOW}${optimal_mtu}${NC}
    🔹 ${GREEN}Optimal MSS:${NC}  ${YELLOW}${mssfix}${NC} (This is the value for mssfix)

"
    echo -e "${BLUE}--- How to Apply ---${NC}
To apply these settings temporarily (resets on reboot):
${YELLOW}sudo ip link set dev $INTERFACE mtu $optimal_mtu${NC}

For VPNs (like OpenVPN), add this line to your config:
${YELLOW}mssfix $mssfix${NC}
"
else
    echo -e "${RED}
===========================================
            ❌ FAILED ❌
===========================================
Could not find a working MTU value in the range 1500-1300.
This could be due to:
1.  Network connectivity issues to '${TARGET_HOST}'.
2.  A firewall blocking ICMP packets.
3.  A very low MTU path (< 1300).
Please check your connection and try again.
${NC}"
fi
