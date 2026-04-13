#!/bin/bash
###############################################################################
# normal_traffic.sh
# Collect normal Wi-Fi traffic from Ubiquiti U6+ (192.168.32.55)
# Captures both 2.4 GHz (Channel 1) and 5 GHz (Channel 2)
###############################################################################

set -e

OPENWRT_IP="192.168.32.55"
INTERFACE="phy0-mon0"      # 2.4 GHz monitor
INTERFACE_2="phy1-mon0"    # 5 GHz monitor
DURATION=300               # 5 minutes per capture
OUTPUT_DIR="../data/raw/normal"

mkdir -p "$OUTPUT_DIR"

echo "AI-WIDS Normal Traffic Collection"
echo "Router: $OPENWRT_IP | Duration: ${DURATION}s per capture"
echo ""

# 2.4 GHz capture
echo "[*] Capture 1: 2.4 GHz — normal browsing"
echo "    Phone A/B: browse websites, stream YouTube"
read -p "    Press Enter to start..."

ssh root@$OPENWRT_IP "tcpdump -i $INTERFACE -w - -s 0" \
    > "$OUTPUT_DIR/normal_ch1_$(date +%Y%m%d_%H%M%S).pcap" & TCP_PID=$!
sleep $DURATION
kill $TCP_PID 2>/dev/null || true
echo "    ✅ 2.4 GHz capture done"
echo ""

# 5 GHz capture
echo "[*] Capture 2: 5 GHz — streaming / video calls"
echo "    Phone A/B: YouTube, WhatsApp video, Zoom"
read -p "    Press Enter to start..."

ssh root@$OPENWRT_IP "tcpdump -i $INTERFACE_2 -w - -s 0" \
    > "$OUTPUT_DIR/normal_ch2_$(date +%Y%m%d_%H%M%S).pcap" & TCP_PID=$!
sleep $DURATION
kill $TCP_PID 2>/dev/null || true
echo "    ✅ 5 GHz capture done"
echo ""

echo "✅ Normal traffic captures complete:"
ls -lh "$OUTPUT_DIR"/*.pcap
echo ""
echo "Next: ./evil_twin.traffic.sh"
