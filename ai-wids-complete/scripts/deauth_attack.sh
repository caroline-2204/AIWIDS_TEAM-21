#!/bin/bash
###############################################################################
# deauth_attack.sh
# Capture Deauthentication / Disassociation attack traffic for training data
#
# Deauth Attack Setup:
#   - Run this while performing a deauth flood on your TEST network
#   - Captures frames with type=management, subtype=deauth (12) or disassoc (10)
#   - Output goes to data/raw/attack/deauth/ for use in training
#
# WARNING: Only use on networks you own or have explicit permission to test.
###############################################################################

set -e

OPENWRT_IP="192.168.32.55"
INTERFACE="phy0-mon0"
DURATION=120          # 2 minutes of deauth capture
OUTPUT_DIR="../data/raw/attack/deauth"

echo "============================================="
echo " AI-WIDS Deauth Attack Traffic Collection"
echo "============================================="
echo "OpenWrt   : $OPENWRT_IP"
echo "Interface : $INTERFACE"
echo "Duration  : ${DURATION}s"
echo "Output    : $OUTPUT_DIR"
echo ""
echo "Setup instructions:"
echo "  1. Use a second device to flood deauth frames toward your test AP"
echo "  2. Ensure the interface is in monitor mode on OpenWrt"
echo "  3. Press Enter below when ready to capture"
echo ""
echo "Press Enter when ready..."
read

mkdir -p "$OUTPUT_DIR"

OUTFILE="$OUTPUT_DIR/deauth_$(date +%Y%m%d_%H%M%S).pcap"

echo "[*] Capturing deauth/disassoc frames for ${DURATION}s..."
echo "    Output: $OUTFILE"
echo ""

# Capture all management frames (includes deauth subtype=12, disassoc subtype=10)
ssh root@$OPENWRT_IP \
    "tcpdump -i $INTERFACE -w - -s 0 'wlan type mgt'" \
    > "$OUTFILE" &
TCP_PID=$!

sleep $DURATION
kill $TCP_PID 2>/dev/null || true

echo ""
echo "✅ Deauth capture complete:"
ls -lh "$OUTPUT_DIR"/*.pcap
echo ""
echo "Next steps:"
echo "  1. python extract_features.py  (re-run to include deauth samples)"
echo "  2. python train_model.py       (retrain with deauth as a 3rd class)"
