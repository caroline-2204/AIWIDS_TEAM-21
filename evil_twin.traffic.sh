#!/bin/bash
###############################################################################
# evil_twin.traffic.sh
# Capture Evil Twin attack traffic from Ubiquiti U6+ OpenWrt router
#
# Setup:
#   AP Phone:  Create hotspot "FreeWiFi" on Channel 1 (2.4 GHz) — legitimate AP
#   ET Phone:  Create hotspot "FreeWiFi" on Channel 1 (2.4 GHz) — Evil Twin AP
#   Phone A/B: Connect to FreeWiFi (they may connect to either AP)
###############################################################################

set -e

OPENWRT_IP="192.168.32.55"
INTERFACE="phy0-mon0"
DURATION=300
OUTPUT_DIR="../data/raw/attack"

mkdir -p "$OUTPUT_DIR"

echo "AI-WIDS Evil Twin Attack Traffic Collection"
echo "Router: $OPENWRT_IP | Interface: $INTERFACE"
echo ""
echo "Setup checklist:"
echo "  [ ] AP Phone:  FreeWiFi hotspot active (Channel 1, 2.4 GHz)"
echo "  [ ] ET Phone:  FreeWiFi hotspot active (Channel 1, 2.4 GHz) ← Evil Twin"
echo "  [ ] Phone A:   Connected to AP Phone FreeWiFi"
echo "  [ ] Phone B:   Connected to ET Phone FreeWiFi"
echo "  [ ] Both phones browsing/streaming"
echo ""
read -p "Press Enter when all devices are running..."

echo "[*] Capturing Evil Twin traffic for ${DURATION}s..."
ssh root@$OPENWRT_IP "tcpdump -i $INTERFACE -w - -s 0" \
    > "$OUTPUT_DIR/evil_twin_$(date +%Y%m%d_%H%M%S).pcap" & TCP_PID=$!

sleep $DURATION
kill $TCP_PID 2>/dev/null || true

echo ""
echo "✅ Evil Twin captures complete:"
ls -lh "$OUTPUT_DIR"/*.pcap
echo ""
echo "Next: python src/extract_features.py"
