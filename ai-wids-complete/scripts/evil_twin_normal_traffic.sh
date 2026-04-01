#!/bin/bash
###############################################################################
# AI-WIDS EVIL TWIN TRAFFIC COLLECTION
###############################################################################
# Purpose: Collect Evil Twin attack traffic from Ubiquiti U6+ OpenWrt router
# Setup:
#   - AP Phone: FreeWiFi hotspot (Channel 1, 2.4GHz) - Legitimate AP
#   - ET Phone: FreeWiFi hotspot (Channel 1, 2.4GHz) - Evil Twin AP
#   - Phone A/B: Connect to either FreeWiFi hotspot
# Output: ../data/raw/attack/evil_twin_YYYYMMDD_HHMMSS.pcap
###############################################################################

set -e                                       # Exit on error
# ===========================
# CONFIGURATION
# ===========================
OPENWRT_IP="192.168.32.55"                   # OpenWrt router IP address
INTERFACE="phy0-mon0"                        # Monitor mode interface (2.4GHz, Channel 1)
DURATION=300                                 # Capture duration in seconds (5 minutes)
OUTPUT_DIR_NOR="../data/raw/normal"              # Output directory for PCAP files
OUTPUT_DIR_ATT="../data/raw/attack"              # Output directory for PCAP files

# ===========================
# START CAPTURE
# ===========================

# Normal Traffic - Clients connect to Normal
echo "AI-WIDS Normal Traffic Collection"
echo "OpenWrt: $OPENWRT_IP | Server: $SERVER_IP"
echo "Duration: $DURATION seconds per capture"
echo ""
# Channel 1 (2.4GHz) - Normal browsing
echo "[*] Capture 1: Channel 1 (2.4GHz) - Normal browsing"
echo "Phone A/B: Normal browsing, YouTube, browsing"
echo "Press Enter to start..."
read
# Create output directory Normal
mkdir -p "$OUTPUT_DIR_NOR"
NOR_OUTPUT_FILE="$OUTPUT_DIR_NOR/normal_traffic_$(date +%Y%m%d_%H%M%S).pcap"
echo "Starting capture Browsing, Streaming, Apps Traffics..."
ssh root@$OPENWRT_IP "tcpdump -i $INTERFACE -w - -s 0" > "$NOR_OUTPUT_FILE" & TCP_PID=$!
sleep $DURATION
kill $TCP_PID 2>/dev/null || true

# Evil Twin Attack - Clients connect to both APs
echo "AI-WIDS Evil Twin Attack Traffic Collection"
echo "Setup:"
echo "1. AP Phone: Enable FreeWiFi hotspot (Channel 1)"
echo "2. ET Phone: Enable FreeWiFi hotspot (Channel 1)"
echo "3. Phone A: Connect to AP Phone FreeWiFi"
echo "4. Phone B: Connect to ET Phone FreeWiFi"
echo "5. Both phones: Browse, stream during capture"
echo ""
echo "Press Enter when ready..."
read
# Create output directory Traffic
mkdir -p "$OUTPUT_DIR_ATT"          
ATT_OUTPUT_FILE="$OUTPUT_DIR_ATT/evil_twin_traffic_$(date +%Y%m%d_%H%M%S).pcap"
echo "Starting capture Attack Traffics..."
ssh root@$OPENWRT_IP "tcpdump -i $INTERFACE -w - -s 0" > "$ATT_OUTPUT_FILE" & TCP_PID=$!
sleep $DURATION
kill $TCP_PID 2>/dev/null || true

echo ""
echo "✅ Normal traffic captures complete:"
ls -lh "$NOR_OUTPUT_FILE"/*.pcap
echo ""
echo "✅ Evil Twin attack captures complete:"
ls -lh "$ATT_OUTPUT_FILE"/*.pcap
echo ""
echo "{Fore.GREEN} Next: ./extract_features.py {Style.RESET_ALL}\n"

