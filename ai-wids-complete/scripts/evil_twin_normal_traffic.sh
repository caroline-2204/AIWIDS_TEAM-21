#!/bin/bash
###############################################################################
# AI-WIDS DUAL-BAND TRAFFIC COLLECTION (UCI PERSISTENT VERSION)
###############################################################################
set -e

# ===========================
# CONFIGURATION
# ===========================
OPENWRT_IP="192.168.32.55"
CH_2G=1   
CH_5G=36  
DURATION=300
OUT_NOR="../data/raw/normal"
OUT_ATT="../data/raw/attack"

# ===========================
# REMOTE HARDWARE SETUP
# ===========================
prepare_router() {
    echo "[*] Configuring Router System for Persistent Monitor Mode..."
    ssh root@$OPENWRT_IP << EOF
        # 1. Stop network to apply hardware changes safely
        /etc/init.d/network stop

        # 2. Configure Radio 0 (2.4GHz) via UCI
        uci set wireless.radio0.channel='$CH_2G'
        uci set wireless.mon0=wifi-iface
        uci set wireless.mon0.device='radio0'
        uci set wireless.mon0.mode='monitor'
        uci set wireless.mon0.ifname='phy0-mon0'

        # 3. Configure Radio 1 (5GHz) via UCI
        uci set wireless.radio1.channel='$CH_5G'
        uci set wireless.mon1=wifi-iface
        uci set wireless.mon1.device='radio1'
        uci set wireless.mon1.mode='monitor'
        uci set wireless.mon1.ifname='phy1-mon0'

        # 4. Commit and Restart
        uci commit wireless
        /etc/init.d/network start
        sleep 5

        # 5. Force Up
        ifconfig phy0-mon0 up
        ifconfig phy1-mon0 up
        
        echo "[SUCCESS] Hardware state:"
        iw dev | grep type
EOF
}

# ===========================
# CAPTURE LOGIC
# ===========================
run_capture() {
    local folder=$1
    local prefix=$2
    mkdir -p "$folder"
    TS=$(date +%Y%m%d_%H%M%S)

    echo "[*] Starting $prefix Dual-Band Capture (5 Minutes)..."
    
    # -l: line buffered, -U: packet buffered (Critical for SSH streaming)
    # -y IEEE802_11_RADIO: ensures radiotap headers are included
    ssh root@$OPENWRT_IP "tcpdump -i phy0-mon0 -y IEEE802_11_RADIO -l -U -w - -s 0" > "$folder/${prefix}_2g_$TS.pcap" & P1=$!
    ssh root@$OPENWRT_IP "tcpdump -i phy1-mon0 -y IEEE802_11_RADIO -l -U -w - -s 0" > "$folder/${prefix}_5g_$TS.pcap" & P2=$!

    sleep $DURATION
    kill $P1 $P2 2>/dev/null || true
    echo "✓ $prefix Capture Finished."
}

# ===========================
# MAIN EXECUTION
# ===========================
prepare_router

echo "-----------------------------------------------------"
echo "PHASE 1: NORMAL TRAFFIC (Trusted + Unmanaged)"
echo "-----------------------------------------------------"
echo "1. AP Phone: ENABLE 'FreeWiFi' (Ch $CH_2G or $CH_5G)"
echo "2. Phone A/B: Connect to AP Phone"
read -p "Press [Enter] to start..."
run_capture "$OUT_NOR" "normal"

echo -e "\n-----------------------------------------------------"
echo "PHASE 2: ATTACK TRAFFIC (Evil Twin)"
echo "-----------------------------------------------------"
echo "1. AP Phone: TURN OFF"
echo "2. ET Phone: ENABLE 'FreeWiFi' (Ch $CH_2G or $CH_5G)"
read -p "Press [Enter] to start..."
run_capture "$OUT_ATT" "attack"

echo -e "\n[DONE] All PCAPs saved to ../data/raw/"
