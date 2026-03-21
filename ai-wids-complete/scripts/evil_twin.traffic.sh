#!/bin/bash
###############################################################################
# evil_twin.traffic.sh
# Collect Evil Twin attack traffic from Ubiquiti U6+ OpenWrt router
# Evil Twin Setup:
# - AP Phone: FreeWiFi (Channel 1, 2.4GHz) - Legitimate AP
# - ET Phone: FreeWiFi (Channel 1, 2.4GHz) - Evil Twin AP  
# - Phone A/B: Connect to either FreeWiFi hotspot
###############################################################################

set -e

OPENWRT_IP="192.168.32.55"
#INTERFACE="br-lan"
INTERFACE="phy0-mon0"  # Channel 1 interface (2.4GHz) iw dev
INTERFACE_2="phy1-mon0"  # Channel 2 interface (5GHz) iw dev
DURATION=300  # 5 minutes
OUTPUT_DIR="../data/raw/attack"

echo "AI-WIDS Evil Twin Attack Traffic Collection"
echo "OpenWrt: $OPENWRT_IP | Channel: 1 (2.4GHz)"
echo "Evil Twin Setup:"
echo "  AP Phone: FreeWiFi (legitimate)"
echo "  ET Phone: FreeWiFi (evil twin)"
echo "  Phone A/B: Connect to FreeWiFi hotspots"
echo ""

# Create output directory
mkdir -p "$OUTPUT_DIR"

# Evil Twin Attack - Clients connect to both APs
echo "[*] Evil Twin Attack Capture"
echo "Setup:"
echo "1. AP Phone: Enable FreeWiFi hotspot (Channel 1)"
echo "2. ET Phone: Enable FreeWiFi hotspot (Channel 1)"
echo "3. Phone A: Connect to AP Phone FreeWiFi"
echo "4. Phone B: Connect to ET Phone FreeWiFi"
echo "5. Both phones: Browse, stream during capture"
echo ""
echo "Press Enter when ready..."
read

ssh root@$OPENWRT_IP "tcpdump -i $INTERFACE -w - -s 0" > "$OUTPUT_DIR/evil_twin_$(date +%Y%m%d_%H%M%S).pcap" & TCP_PID=$!
sleep $DURATION
kill $TCP_PID 2>/dev/null || true

echo ""
echo "✅ Evil Twin attack captures complete:"
ls -lh "$OUTPUT_DIR"/*.pcap
echo ""
echo "Next: ./extract_features.py"
