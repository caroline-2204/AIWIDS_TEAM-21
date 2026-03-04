#!/bin/bash
###############################################################################
# run_live_demo.sh
#
# Run live demonstration with UniFi remote sniffer
#
# This script:
# 1. Checks that inference server is running
# 2. Starts live packet sniffer
# 3. Displays real-time detections
#
# Usage:
#   ./run_live_demo.sh <AP_IP> [INTERFACE] [THRESHOLD]
#
# AP_IP: UniFi AP IP address (required)
# INTERFACE: Capture interface (default: br0)
# THRESHOLD: Alert threshold (default: 0.7)
###############################################################################

# Enable error handling
set -e
set -u

# --- Parse arguments ---
# AP IP (required)
AP_IP="${1:-}"

# Interface (optional, default br0)
INTERFACE="${2:-br0}"

# Alert threshold (optional, default 0.7)
THRESHOLD="${3:-0.7}"

# Validate AP IP
if [ -z "$AP_IP" ]; then
    echo "Usage: $0 <AP_IP> [INTERFACE] [THRESHOLD]"
    echo ""
    echo "Example:"
    echo "  $0 192.168.1.20"
    echo "  $0 192.168.1.20 br0 0.7"
    exit 1
fi

# --- Configuration ---
# AP SSH user
AP_USER="ubnt"

# Inference server URL
SERVER_URL="http://localhost:8000"

# Log directory
LOG_DIR="logs"
mkdir -p "$LOG_DIR"

# Log file
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
LOG_FILE="${LOG_DIR}/live_demo_${TIMESTAMP}.log"

# --- Color codes ---
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

# --- Check prerequisites ---
echo ""
echo "======================================================================"
echo "  AI-WIDS Live Demonstration"
echo "======================================================================"
echo ""

# Check venv
if [ ! -d "venv" ]; then
    echo -e "${RED}[!]${NC} Virtual environment not found"
    echo "    Run ./scripts/quick_start.sh first"
    exit 1
fi

# Activate venv
echo -e "${BLUE}[*]${NC} Activating virtual environment..."
source venv/bin/activate

# Check if inference server is running
echo -e "${BLUE}[*]${NC} Checking inference server..."

if curl -s "${SERVER_URL}/health" > /dev/null 2>&1; then
    # Server is running
    echo -e "${GREEN}[+]${NC} Inference server is running"

    # Get server info
    SERVER_INFO=$(curl -s "${SERVER_URL}/health")
    echo "    Server info: $SERVER_INFO"
else
    # Server is not running
    echo -e "${RED}[!]${NC} ERROR: Inference server is not running"
    echo ""
    echo "Please start the server first:"
    echo "  ./scripts/run_inference_server.sh"
    echo ""
    echo "In a separate terminal, run:"
    echo "  $0 $AP_IP"
    exit 1
fi

# Check SSH connectivity to AP
echo -e "${BLUE}[*]${NC} Checking SSH connectivity to AP..."

if ssh -o ConnectTimeout=5 "${AP_USER}@${AP_IP}" "echo 'SSH OK'" > /dev/null 2>&1; then
    echo -e "${GREEN}[+]${NC} SSH connection successful"
else
    echo -e "${RED}[!]${NC} ERROR: Cannot connect to AP at $AP_IP"
    echo "    Check AP IP address and SSH access"
    exit 1
fi

# --- Print demo configuration ---
echo ""
echo "======================================================================"
echo "  Configuration"
echo "======================================================================"
echo "  AP IP:            $AP_IP"
echo "  Capture Interface: $INTERFACE"
echo "  Inference Server:  $SERVER_URL"
echo "  Alert Threshold:   $THRESHOLD"
echo "  Log File:          $LOG_FILE"
echo "======================================================================"
echo ""

# --- Instructions for user ---
echo -e "${YELLOW}╔════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${YELLOW}║                    LIVE DEMO INSTRUCTIONS                      ║${NC}"
echo -e "${YELLOW}╔════════════════════════════════════════════════════════════════╗${NC}"
echo ""
echo "  The sniffer will now capture and classify traffic in real-time."
echo ""
echo "  Color codes:"
echo -e "    ${GREEN}[OK   ]${NC} Normal traffic (high confidence)"
echo -e "    ${YELLOW}[WARN ]${NC} Possible attack (low confidence)"
echo -e "    ${RED}[ALERT!]${NC} Attack detected (high confidence)"
echo ""
echo "  For demonstration:"
echo "    1. Phone A: Browse normally (should show green OK)"
echo "    2. Phone B: Generate attack traffic (should show red ALERT)"
echo ""
echo -e "${YELLOW}  Press Ctrl+C to stop the demo${NC}"
echo ""
echo "======================================================================"
echo ""

# Wait for user to be ready
read -p "Press Enter to start live capture..." -r
echo ""

# --- Start live sniffer ---
echo -e "${BLUE}[*]${NC} Starting live packet capture..."
echo ""

# Run sniffer with output to both console and log
python src/unifi_remote_sniffer.py \
    --ap-ip "$AP_IP" \
    --ap-user "$AP_USER" \
    --interface "$INTERFACE" \
    --server-url "$SERVER_URL" \
    --alert-threshold "$THRESHOLD" \
    --verbose \
    2>&1 | tee "$LOG_FILE"

# Cleanup on exit
echo ""
echo -e "${GREEN}[+]${NC} Demo stopped"
echo -e "${BLUE}[*]${NC} Log saved to: $LOG_FILE"
echo ""
