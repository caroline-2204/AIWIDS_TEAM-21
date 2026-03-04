#!/bin/bash
###############################################################################
# capture_pcap_u6.sh
#
# Capture packets from UniFi U6+ AP via SSH + tcpdump
#
# Usage:
#   ./capture_pcap_u6.sh <AP_IP> <OUTPUT_FILE> <DURATION>
#
# Example:
#   ./capture_pcap_u6.sh 192.168.1.20 normal_traffic.pcap 60
###############################################################################

# Enable strict error handling
set -e  # Exit on any error
set -u  # Exit on undefined variable
set -o pipefail  # Exit if any command in a pipeline fails

# --- Parse command-line arguments ---
# First argument: AP IP address (required)
AP_IP="${1:-}"

# Second argument: Output filename (required)
OUTPUT="${2:-}"

# Third argument: Capture duration in seconds (required)
DURATION="${3:-}"

# --- Validate arguments ---
if [ -z "$AP_IP" ] || [ -z "$OUTPUT" ] || [ -z "$DURATION" ]; then
    # Print usage message if any argument is missing
    echo "Usage: $0 <AP_IP> <OUTPUT_FILE> <DURATION_SECONDS>"
    echo ""
    echo "Example:"
    echo "  $0 192.168.1.20 normal.pcap 60"
    exit 1
fi

# --- Configuration ---
# SSH username for AP (usually "ubnt" for UniFi devices)
AP_USER="ubnt"

# Interface to capture on:
# - br0: main bridge (captures uplink traffic)
# - ath0/ath1: wireless interfaces (captures WiFi frames)
INTERFACE="br0"

# --- Print capture information ---
echo "=============================================="
echo "  UniFi U6+ Packet Capture"
echo "=============================================="
echo "AP IP:       $AP_IP"
echo "Interface:   $INTERFACE"
echo "Duration:    ${DURATION}s"
echo "Output:      $OUTPUT"
echo "=============================================="
echo ""

# --- Test SSH connectivity ---
echo "[*] Testing SSH connection..."

# Try to SSH and run a simple command (echo success message)
if ssh -o ConnectTimeout=5 "${AP_USER}@${AP_IP}" "echo 'SSH OK'" > /dev/null 2>&1; then
    # SSH connection successful
    echo "[+] SSH connection successful"
else
    # SSH connection failed
    echo "[!] ERROR: Cannot connect to ${AP_IP} via SSH"
    echo "[!] Please check:"
    echo "    - AP IP address is correct"
    echo "    - SSH is enabled on the AP"
    echo "    - SSH credentials are configured (ssh-copy-id recommended)"
    exit 1
fi

# --- Run packet capture ---
echo "[*] Starting capture (${DURATION}s)..."
echo "[*] Press Ctrl+C to stop early"
echo ""

# SSH to AP and run tcpdump remotely
# tcpdump options:
#   -i $INTERFACE: capture on specified interface
#   -U: unbuffered output (important for streaming)
#   -w -: write packets to stdout (dash means stdout)
#   
# timeout command: stops tcpdump after DURATION seconds
#
# Output redirection (> $OUTPUT): save captured packets to file
ssh "${AP_USER}@${AP_IP}" \
    "timeout ${DURATION} tcpdump -i ${INTERFACE} -U -w -" \
    > "${OUTPUT}" 2>/dev/null

# Check if output file was created and has data
if [ -f "$OUTPUT" ] && [ -s "$OUTPUT" ]; then
    # File exists and has non-zero size

    # Get file size in human-readable format
    FILE_SIZE=$(du -h "$OUTPUT" | cut -f1)

    # Count packets in the capture (using tcpdump -r)
    PACKET_COUNT=$(tcpdump -r "$OUTPUT" 2>/dev/null | wc -l || echo "unknown")

    # Print success message
    echo ""
    echo "[+] Capture complete!"
    echo "[+] File: $OUTPUT"
    echo "[+] Size: $FILE_SIZE"
    echo "[+] Packets: $PACKET_COUNT"
else
    # File is empty or doesn't exist
    echo ""
    echo "[!] ERROR: Capture failed or no packets captured"
    exit 1
fi
