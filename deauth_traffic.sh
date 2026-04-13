#!/bin/bash
###############################################################################
# deauth_traffic.sh
# Capture Deauthentication (DoS) attack traffic from Ubiquiti U6+ OpenWrt router
#
# Attack setup:
#   Attacker device: run  aireplay-ng --deauth 0 -a <AP_MAC> <interface>
#   Victim device:   connected to the AP being attacked
#   Router:          U6+ in monitor mode captures the flood
###############################################################################

set -e

OPENWRT_IP="192.168.32.55"
INTERFACE="phy0-mon0"     # 2.4 GHz monitor interface
DURATION=300              # 5 minutes
OUTPUT_DIR="../data/raw/deauth"

echo "AI-WIDS Deauth Attack Traffic Collection"
echo "Router: $OPENWRT_IP | Interface: $INTERFACE"
echo ""
echo "Setup:"
echo "  1. Connect a victim device to any AP"
echo "  2. On the attacker device run:"
echo "       sudo aireplay-ng --deauth 0 -a <AP_BSSID> <monitor_interface>"
echo "     (or use mdk4 / WiFi-Pumpkin for the same effect)"
echo "  3. Press Enter here to begin the 5-minute capture"
echo ""
read -p "Press Enter when the attack is running..."

mkdir -p "$OUTPUT_DIR"

echo "[*] Capturing deauth flood for ${DURATION}s..."
ssh root@$OPENWRT_IP "tcpdump -i $INTERFACE -w - -s 0" \
    > "$OUTPUT_DIR/deauth_$(date +%Y%m%d_%H%M%S).pcap" & TCP_PID=$!

sleep $DURATION
kill $TCP_PID 2>/dev/null || true

echo ""
echo "✅ Deauth captures complete:"
ls -lh "$OUTPUT_DIR"/*.pcap
echo ""
echo "Next: python src/extract_features.py"
