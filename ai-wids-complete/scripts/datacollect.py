#!/usr/bin/env python3
"""
AI-WIDS Normal Traffic Collection - v2.2 (DUAL-BAND)
Captures FreeWiFi beacon traffic on both 2.4 GHz and 5 GHz,
filters to FreeWiFi only, and saves each band to its own PCAP file.
Dashboard removed; all data-collection logic preserved.
"""
import threading
import subprocess
import time
import os
from datetime import datetime
from scapy.all import Dot11Elt, PcapReader, PcapWriter
from colorama import Fore, Style, init

init(autoreset=True)

# --- CONFIGURATION ---
OPENWRT_IP     = "192.168.32.55"
TARGET_SSID    = "FreeWiFi"
IFACE_24       = "phy0-mon0"
IFACE_50       = "phy1-mon0"
OUTPUT_DIR_NOR = "../data/raw/normal"
OUTPUT_DIR_ATT = "../data/raw/attack"


# ---------------------------------------------------------------------------
# HARDWARE SETUP
# ---------------------------------------------------------------------------

def setup_hardware():
    print(f"{Fore.CYAN}[*] Configuring Dual Monitoring (phy0 & phy1)...{Style.RESET_ALL}")
    cmd = f"""
    /etc/init.d/network stop;
    uci delete wireless.mon24 2>/dev/null;
    uci set wireless.mon24=wifi-iface; uci set wireless.mon24.device='radio0';
    uci set wireless.mon24.mode='monitor'; uci set wireless.mon24.ifname='{IFACE_24}';
    uci delete wireless.mon50 2>/dev/null;
    uci set wireless.mon50=wifi-iface; uci set wireless.mon50.device='radio1';
    uci set wireless.mon50.mode='monitor'; uci set wireless.mon50.ifname='{IFACE_50}';
    uci commit wireless; /etc/init.d/network start; sleep 5;
    ifconfig {IFACE_24} up; ifconfig {IFACE_50} up;
    """
    subprocess.run(['ssh', f'root@{OPENWRT_IP}', cmd], check=True, stderr=subprocess.DEVNULL)


# ---------------------------------------------------------------------------
# CHANNEL HOPPER
# ---------------------------------------------------------------------------

def channel_hopper():
    ch_24 = [1, 6, 11]
    ch_50 = [36, 44, 149, 157]
    while True:
        for i in range(max(len(ch_24), len(ch_50))):
            c24 = ch_24[i % len(ch_24)]
            c50 = ch_50[i % len(ch_50)]
            subprocess.run(
                ['ssh', f'root@{OPENWRT_IP}', f'iw dev {IFACE_24} set channel {c24}'],
                stderr=subprocess.DEVNULL)
            subprocess.run(
                ['ssh', f'root@{OPENWRT_IP}', f'iw dev {IFACE_50} set channel {c50}'],
                stderr=subprocess.DEVNULL)
            time.sleep(4)


# ---------------------------------------------------------------------------
# FREEWIFI DETECTION
# ---------------------------------------------------------------------------

def detect_freewifi_on_iface(iface, band_label, timeout=30):
    """
    Briefly sniff one interface for FreeWiFi beacons.
    A threading.Timer kills the tcpdump process after `timeout` seconds so that
    PcapReader (which blocks on the pipe) is unblocked from the outside.
    """
    print(f"{Fore.CYAN}[*] Pre-scan: looking for '{TARGET_SSID}' on {band_label} ({iface})...{Style.RESET_ALL}")
    cmd = ['ssh', f'root@{OPENWRT_IP}',
           'tcpdump', '-i', iface, '-y', 'IEEE802_11_RADIO',
           '-l', '-U', '-w', '-', 'type mgt subtype beacon']
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)

    # Kill after timeout — closes the pipe and unblocks PcapReader
    timer = threading.Timer(timeout, proc.kill)
    timer.start()

    detected, bssid_found = False, None
    try:
        reader = PcapReader(proc.stdout)
        for pkt in reader:
            if not pkt.haslayer(Dot11Elt):
                continue
            try:
                ssid = pkt[Dot11Elt].info.decode('utf-8', errors='ignore').strip()
                if ssid == TARGET_SSID:
                    bssid_found = pkt.addr3
                    detected = True
                    proc.kill()   # found — stop early
                    break
            except Exception:
                continue
    except Exception:
        pass   # EOFError / BrokenPipeError when proc is killed — expected
    finally:
        timer.cancel()
        proc.kill()

    return detected, bssid_found


def detect_freewifi():
    """Run pre-scan on both bands in parallel; return True if FreeWiFi is found on at least one."""
    results = {}

    def scan(iface, label):
        results[label] = detect_freewifi_on_iface(iface, label)

    threads = [
        threading.Thread(target=scan, args=(IFACE_24, "2.4GHz")),
        threading.Thread(target=scan, args=(IFACE_50, "5GHz")),
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    detected_any = False
    for label, (det, bssid) in results.items():
        if det:
            print(f"{Fore.GREEN}[+] '{TARGET_SSID}' DETECTED on {label}: BSSID={bssid}{Style.RESET_ALL}")
            detected_any = True
        else:
            print(f"{Fore.YELLOW}[-] '{TARGET_SSID}' NOT found on {label} during pre-scan{Style.RESET_ALL}")
    return detected_any


# ---------------------------------------------------------------------------
# SNIFFER — FreeWiFi only, saves to PCAP
# ---------------------------------------------------------------------------

def sniffer_worker(iface, band_label, duration, output_dir):
    """Capture FreeWiFi beacon frames for `duration` seconds and write to a PCAP."""
    os.makedirs(output_dir, exist_ok=True)
    timestamp   = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_band   = band_label.replace(".", "_").replace(" ", "_")
    pcap_path   = os.path.join(output_dir, f"FreeWiFi_{safe_band}_{timestamp}.pcap")
    pcap_writer = PcapWriter(pcap_path, append=False, sync=True)
    print(f"{Fore.GREEN}[+] [{band_label}] Saving to → {pcap_path}{Style.RESET_ALL}")

    cmd = ['ssh', f'root@{OPENWRT_IP}',
           'tcpdump', '-i', iface, '-y', 'IEEE802_11_RADIO',
           '-l', '-U', '-w', '-', 'type mgt subtype beacon']
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)

    # Stop tcpdump after duration — unblocks PcapReader from the outside
    timer = threading.Timer(duration, proc.kill)
    timer.start()

    pkt_count = 0
    try:
        reader = PcapReader(proc.stdout)
        for pkt in reader:
            if not pkt.haslayer(Dot11Elt):
                continue
            try:
                ssid = pkt[Dot11Elt].info.decode('utf-8', errors='ignore').strip()
                if ssid != TARGET_SSID:
                    continue
                pcap_writer.write(pkt)
                pkt_count += 1
            except Exception:
                continue
    except Exception:
        pass  # EOFError / BrokenPipeError when timer kills proc — expected
    finally:
        timer.cancel()
        proc.kill()

    size_kb = os.path.getsize(pcap_path) // 1024
    print(f"{Fore.GREEN}[+] [{band_label}] Done — {pkt_count} packets  |  {pcap_path}  ({size_kb} KB){Style.RESET_ALL}")


# ---------------------------------------------------------------------------
# ENTRY POINT
# ---------------------------------------------------------------------------

if __name__ == '__main__':
    setup_hardware()

    # Start channel hopper BEFORE pre-scan so detection covers all channels
    threading.Thread(target=channel_hopper, daemon=True).start()
    print(f"{Fore.CYAN}[*] Channel hopper started — waiting 5s for interfaces to settle...{Style.RESET_ALL}")
    time.sleep(5)

    capture_num = 0

    while True:
        capture_num += 1
        print(f"\n{Fore.YELLOW}--- Capture #{capture_num} ---{Style.RESET_ALL}")

        # --- Capture type ---
        print("  Capture type:")
        print("    [1] Normal traffic  →  ../data/raw/normal")
        print("    [2] Attack traffic  →  ../data/raw/attack")
        ctype = input("  Choose [1/2, default 1]: ").strip()
        if ctype == "2":
            output_dir  = OUTPUT_DIR_ATT
            type_label  = "ATTACK"
            type_color  = Fore.RED
        else:
            output_dir  = OUTPUT_DIR_NOR
            type_label  = "NORMAL"
            type_color  = Fore.GREEN
        print(f"  {type_color}[{type_label}] Output → {output_dir}{Style.RESET_ALL}")

        # --- Duration ---
        raw = input("  Duration in seconds [default 300]: ").strip()
        try:
            duration = int(raw) if raw else 300
        except ValueError:
            print(f"{Fore.RED}  Invalid — using 300s.{Style.RESET_ALL}")
            duration = 300

        # --- Detect FreeWiFi before collecting ---
        if not detect_freewifi():
            print(f"{Fore.RED}[!] '{TARGET_SSID}' not detected on any band. Aborting.{Style.RESET_ALL}")
            raise SystemExit(1)

        input(f"\n  Press Enter to start {duration}s [{type_label}] capture...")

        # Launch both band sniffers (non-daemon so we can join them)
        t24 = threading.Thread(target=sniffer_worker, args=(IFACE_24, "2.4GHz", duration, output_dir))
        t50 = threading.Thread(target=sniffer_worker, args=(IFACE_50, "5GHz",   duration, output_dir))
        t24.start()
        t50.start()

        # Countdown in main thread
        try:
            for remaining in range(duration, 0, -1):
                print(f"\r  Capturing... {remaining:>4}s remaining", end="", flush=True)
                time.sleep(1)
            print()
        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}[*] Capture interrupted by user.{Style.RESET_ALL}")

        t24.join()
        t50.join()

        # --- Another capture? ---
        again = input("\n  Collect another capture? [Y/n]: ").strip().lower()
        if again == "n":
            break

    print(f"\n{Fore.GREEN}[*] Done. Files saved to {OUTPUT_DIR_NOR} and/or {OUTPUT_DIR_ATT}{Style.RESET_ALL}")

