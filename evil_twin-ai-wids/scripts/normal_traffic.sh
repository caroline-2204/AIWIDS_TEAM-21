#!/bin/bash
###############################################################################
# normal_traffic.sh
# Collect normal traffic from Ubiquiti U6+ OpenWrt router
# IP: 192.168.32.55 | Interface: br-lan | Channels: 1 (2.4GHz), 2 (5GHz)
# Server: 192.168.32.10 (Linux Mint/Ubuntu)
###############################################################################

set -e

OPENWRT_IP="192.168.32.55"
SERVER_IP="192.168.32.10"
#INTERFACE="br-lan"
INTERFACE="phy0-mon0"  # Channel 1 interface (2.4GHz) iw dev
INTERFACE_2="phy1-mon0"  # Channel 2 interface (5GHz) iw dev
DURATION=300  # 5 minutes
OUTPUT_DIR="../data/raw/normal"

echo "AI-WIDS Normal Traffic Collection"
echo "OpenWrt: $OPENWRT_IP | Server: $SERVER_IP"
echo "Duration: $DURATION seconds per capture"
echo ""

# Create output directory
mkdir -p "$OUTPUT_DIR"

# Channel 1 (2.4GHz) - Normal browsing
echo "[*] Capture 1: Channel 1 (2.4GHz) - Normal browsing"
echo "Phone A/B: Normal browsing, YouTube, browsing"
echo "Press Enter to start..."
read

# ssh root@$OPENWRT_IP "iwconfig $INTERFACE channel 1 && tcpdump -i $INTERFACE -w - -s 0" > "$OUTPUT_DIR/normal_ch1_$(date +%Y%m%d_%H%M%S).pcap" &
# TCP_PID=$!
ssh root@$OPENWRT_IP "tcpdump -i $INTERFACE -w - -s 0" > "$OUTPUT_DIR/normal_ch1_$(date +%Y%m%d_%H%M%S).pcap" & TCP_PID=$!
sleep $DURATION
kill $TCP_PID 2>/dev/null || true

# Channel 2 (5GHz) - Normal streaming
echo "[*] Capture 2: Channel 2 (5GHz) - Normal streaming"
echo "Phone A/B: YouTube streaming, video calls"
echo "Press Enter to start..."
read

# ssh root@$OPENWRT_IP "iwconfig $INTERFACE channel 2 && tcpdump -i $INTERFACE -w - -s 0" > "$OUTPUT_DIR/normal_ch2_$(date +%Y%m%d_%H%M%S).pcap" &
# TCP_PID=$!

ssh root@$OPENWRT_IP "tcpdump -i $INTERFACE_2 -w - -s 0" > "$OUTPUT_DIR/normal_ch2_$(date +%Y%m%d_%H%M%S).pcap" & TCP_PID=$!
sleep $DURATION
kill $TCP_PID 2>/dev/null || true

echo ""
echo "✅ Normal traffic captures complete:"
ls -lh "$OUTPUT_DIR"/*.pcap
echo ""
echo "Next: ./evil_twin.traffic.sh"

