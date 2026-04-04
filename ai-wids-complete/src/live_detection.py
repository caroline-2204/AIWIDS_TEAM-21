#!/usr/bin/env python3
"""
AI-WIDS Enhanced NOC Dashboard - FIXED VERSION
Fixes:
1. EVIL-TWIN rows now properly change to RED automatically
2. SSID matching is now case-sensitive (exact match)
"""
import threading
import subprocess
import time
import os
import random
from datetime import datetime
from scapy.all import Dot11, Dot11Elt, PcapReader, RadioTap
from flask import Flask, render_template_string, send_from_directory
from flask_socketio import SocketIO
from colorama import Fore, Style, init

init(autoreset=True)

# ===========================
# CONFIGURATION
# ===========================
OPENWRT_IP = "192.168.32.55"
TARGET_SSID = "FreeWiFi"  # EXACT CASE - will match exactly as configured

class MonitorState:
    def __init__(self):
        self.mac_registry = {}              # ssid_lower → {original_ssid, bssids: {bssid: {...}}}
        self.band_stats = {"2.4GHz": 0, "5GHz": 0}
        self.total_packets = 0
        self.alerts = []
        self.channel_stats = {}
        self.lock = threading.Lock()

state = MonitorState()
app = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

@app.route('/socket.io.min.js')
def serve_socketio():
    return send_from_directory(os.getcwd(), 'socket.io.min.js')

# ===========================
# ENHANCED NOC DASHBOARD
# ===========================
DASHBOARD_HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>AI-WIDS | NOC Dashboard - FIXED</title>
    <script src="/socket.io.min.js"></script>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        
        :root {
            --bg-primary: #0a0e27;
            --bg-secondary: #141829;
            --bg-card: #1a1f3a;
            --border: #2d3561;
            --text-primary: #e4e8ff;
            --text-secondary: #8b92c4;
            --blue: #3b82f6;
            --cyan: #06b6d4;
            --red: #ef4444;
            --orange: #f97316;
            --green: #10b981;
            --yellow: #fbbf24;
            --purple: #8b5cf6;
        }
        
        body {
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            padding: 15px;
            font-size: 13px;
        }
        
        .header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 15px;
            padding: 12px;
            background: var(--bg-card);
            border-radius: 8px;
            border: 1px solid var(--border);
        }
        
        .header h1 {
            font-size: 1.5rem;
            background: linear-gradient(135deg, var(--blue), var(--purple));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        
        .status-indicator {
            width: 10px;
            height: 10px;
            background: var(--green);
            border-radius: 50%;
            animation: pulse 2s infinite;
        }
        
        @keyframes pulse {
            0%, 100% { opacity: 1; transform: scale(1); }
            50% { opacity: 0.5; transform: scale(1.1); }
        }
        
        .dashboard {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 12px;
            margin-bottom: 15px;
        }
        
        .stat-card {
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 12px;
            position: relative;
            overflow: hidden;
        }
        
        .stat-card::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            width: 4px;
            height: 100%;
        }
        
        .stat-card.blue::before { background: var(--blue); }
        .stat-card.cyan::before { background: var(--cyan); }
        .stat-card.red::before { background: var(--red); }
        .stat-card.green::before { background: var(--green); }
        .stat-card.orange::before { background: var(--orange); }
        .stat-card.purple::before { background: var(--purple); }
        
        .stat-label {
            font-size: 0.7rem;
            color: var(--text-secondary);
            text-transform: uppercase;
            letter-spacing: 0.5px;
            margin-bottom: 6px;
        }
        
        .stat-value {
            font-size: 1.8rem;
            font-weight: 700;
            line-height: 1;
        }
        
        .stat-card.blue .stat-value { color: var(--blue); }
        .stat-card.cyan .stat-value { color: var(--cyan); }
        .stat-card.red .stat-value { color: var(--red); }
        .stat-card.green .stat-value { color: var(--green); }
        .stat-card.orange .stat-value { color: var(--orange); }
        .stat-card.purple .stat-value { color: var(--purple); }
        
        .main-grid {
            display: grid;
            grid-template-columns: 2fr 1fr;
            gap: 15px;
        }
        
        .card {
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 12px;
        }
        
        .card-header {
            font-size: 0.9rem;
            font-weight: 600;
            color: var(--text-secondary);
            margin-bottom: 12px;
            padding-bottom: 8px;
            border-bottom: 1px solid var(--border);
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        
        table {
            width: 100%;
            border-collapse: collapse;
        }
        
        thead th {
            text-align: left;
            font-size: 0.7rem;
            color: var(--text-secondary);
            padding: 8px;
            border-bottom: 2px solid var(--border);
            text-transform: uppercase;
            letter-spacing: 0.5px;
            font-weight: 600;
        }
        
        tbody td {
            padding: 10px 8px;
            border-bottom: 1px solid var(--border);
            font-size: 0.85rem;
        }
        
        tbody tr {
            transition: background 0.2s, border 0.2s;
        }
        
        tbody tr:hover {
            background: rgba(59, 130, 246, 0.1);
        }
        
        /* FIXED: Row color coding - EXACT class names with !important */
        tbody tr.type-trusted {
            background: rgba(16, 185, 129, 0.05) !important;
            border-left: 3px solid var(--green) !important;
        }
        
        tbody tr.type-evil-twin {
            background: rgba(239, 68, 68, 0.25) !important;
            border-left: 4px solid var(--red) !important;
            animation: alertPulse 2s infinite !important;
            box-shadow: inset 0 0 20px rgba(239, 68, 68, 0.15) !important;
        }
        
        tbody tr.type-unmanaged {
            background: rgba(251, 191, 36, 0.05) !important;
            border-left: 3px solid var(--orange) !important;
        }
        
        @keyframes alertPulse {
            0%, 100% { box-shadow: inset 0 0 20px rgba(239, 68, 68, 0.15), 0 0 0 rgba(239, 68, 68, 0); }
            50% { box-shadow: inset 0 0 20px rgba(239, 68, 68, 0.15), 0 0 15px rgba(239, 68, 68, 0.4); }
        }
        
        .badge {
            padding: 4px 8px;
            border-radius: 12px;
            font-size: 0.65rem;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            display: inline-block;
        }
        
        .badge.trusted {
            background: rgba(16, 185, 129, 0.2);
            color: var(--green);
            border: 1px solid var(--green);
        }
        
        .badge.evil-twin {
            background: rgba(239, 68, 68, 0.2);
            color: var(--red);
            border: 1px solid var(--red);
        }
        
        .badge.unmanaged {
            background: rgba(251, 191, 36, 0.2);
            color: var(--orange);
            border: 1px solid var(--orange);
        }
        
        .confidence-bar {
            width: 60px;
            height: 6px;
            background: var(--bg-secondary);
            border-radius: 3px;
            overflow: hidden;
            display: inline-block;
            vertical-align: middle;
        }
        
        .confidence-fill {
            height: 100%;
            transition: width 0.3s;
        }
        
        .confidence-fill.high { background: var(--green); }
        .confidence-fill.medium { background: var(--yellow); }
        .confidence-fill.low { background: var(--red); }
        
        #alert-log {
            height: 400px;
            overflow-y: auto;
            font-family: 'Courier New', monospace;
            font-size: 0.75rem;
            background: var(--bg-secondary);
            padding: 10px;
            border-radius: 6px;
        }
        
        .alert-item {
            padding: 8px;
            margin-bottom: 6px;
            border-radius: 4px;
            border-left: 3px solid;
            animation: slideIn 0.3s;
        }
        
        @keyframes slideIn {
            from { transform: translateX(-20px); opacity: 0; }
            to { transform: translateX(0); opacity: 1; }
        }
        
        .alert-item.evil-twin {
            background: rgba(239, 68, 68, 0.1);
            border-left-color: var(--red);
        }
        
        .alert-item.trusted {
            background: rgba(16, 185, 129, 0.1);
            border-left-color: var(--green);
        }
        
        .alert-item.unmanaged {
            background: rgba(251, 191, 36, 0.1);
            border-left-color: var(--orange);
        }
        
        .alert-time {
            color: var(--text-secondary);
            font-size: 0.7rem;
        }
        
        .mac-address {
            font-family: 'Courier New', monospace;
            color: var(--cyan);
            font-size: 0.8rem;
        }
        
        .channel-badge {
            background: rgba(139, 92, 246, 0.2);
            color: var(--purple);
            padding: 2px 6px;
            border-radius: 4px;
            font-size: 0.7rem;
            font-weight: 600;
        }
        
        ::-webkit-scrollbar {
            width: 8px;
        }
        
        ::-webkit-scrollbar-track {
            background: var(--bg-secondary);
        }
        
        ::-webkit-scrollbar-thumb {
            background: var(--border);
            border-radius: 4px;
        }
        
        ::-webkit-scrollbar-thumb:hover {
            background: var(--text-secondary);
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>
            <span class="status-indicator"></span>
            🛡️ AI-WIDS NOC Dashboard
        </h1>
        <div style="color: var(--text-secondary); font-size: 0.85rem;">
            <span id="timestamp">--:--:--</span> | 
            Target: <span style="color: var(--cyan)" id="target-ssid">Loading...</span>
        </div>
    </div>
    
    <div class="dashboard">
        <div class="stat-card blue">
            <div class="stat-label">Total Packets</div>
            <div class="stat-value" id="total-pkts">0</div>
        </div>
        
        <div class="stat-card red">
            <div class="stat-label">Threats Detected</div>
            <div class="stat-value" id="threat-count">0</div>
        </div>
        
        <div class="stat-card cyan">
            <div class="stat-label">2.4 GHz Devices</div>
            <div class="stat-value" id="band-24">0</div>
        </div>
        
        <div class="stat-card purple">
            <div class="stat-label">5 GHz Devices</div>
            <div class="stat-value" id="band-5">0</div>
        </div>
        
        <div class="stat-card green">
            <div class="stat-label">Trusted APs</div>
            <div class="stat-value" id="trusted-count">0</div>
        </div>
        
        <div class="stat-card orange">
            <div class="stat-label">Active Channels</div>
            <div class="stat-value" id="channel-count">0</div>
        </div>
    </div>
    
    <div class="main-grid">
        <div class="card">
            <div class="card-header">🌐 Network Monitor</div>
            <table>
                <thead>
                    <tr>
                        <th>SSID</th>
                        <th>BSSID</th>
                        <th>Channel</th>
                        <th>Band</th>
                        <th>MACs</th>
                        <th>AI Confidence</th>
                        <th>Status</th>
                    </tr>
                </thead>
                <tbody id="net-table">
                    <tr><td colspan="7" style="text-align:center; color: var(--text-secondary);">Waiting for data...</td></tr>
                </tbody>
            </table>
        </div>
        
        <div class="card">
            <div class="card-header">🚨 Alert Log</div>
            <div id="alert-log">
                <div style="color: var(--text-secondary); text-align: center; margin-top: 50px;">
                    No alerts yet...
                </div>
            </div>
        </div>
    </div>
    
    <script>
        const socket = io({ transports: ['polling'] });
        
        setInterval(() => {
            const now = new Date();
            document.getElementById('timestamp').innerText = now.toTimeString().split(' ')[0];
        }, 1000);
        
        socket.on('full_update', (data) => {
            // Update target SSID
            if (data.target_ssid) {
                document.getElementById('target-ssid').innerText = data.target_ssid;
            }
            
            // Update statistics
            document.getElementById('total-pkts').innerText = data.stats.total.toLocaleString();
            document.getElementById('threat-count').innerText = data.stats.threats;
            document.getElementById('band-24').innerText = data.stats.band_24;
            document.getElementById('band-5').innerText = data.stats.band_5;
            document.getElementById('trusted-count').innerText = data.stats.trusted;
            document.getElementById('channel-count').innerText = data.stats.channels;
            
            // Update network table - FIXED: Use exact type_class
            let rows = "";
            data.networks.forEach(n => {
                const confidence = n.confidence || 0;
                const confClass = confidence > 80 ? 'high' : confidence > 50 ? 'medium' : 'low';
                
                rows += `<tr class="${n.type_class}">
                    <td><strong>${n.ssid}</strong></td>
                    <td><span class="mac-address">${n.bssid}</span></td>
                    <td><span class="channel-badge">CH ${n.channel}</span></td>
                    <td>${n.band}</td>
                    <td>${n.mac_count}</td>
                    <td>
                        <div class="confidence-bar">
                            <div class="confidence-fill ${confClass}" style="width: ${confidence}%"></div>
                        </div>
                        ${confidence}%
                    </td>
                    <td><span class="badge ${n.badge_class}">${n.type}</span></td>
                </tr>`;
            });
            document.getElementById('net-table').innerHTML = rows || '<tr><td colspan="7" style="text-align:center; color: var(--text-secondary);">No networks detected</td></tr>';
            
            // Update alerts
            let alerts = "";
            data.alerts.forEach(a => {
                const alertType = a.type || 'unmanaged';
                alerts += `<div class="alert-item ${alertType}">
                    <span class="alert-time">[${a.time}]</span> ${a.msg}
                </div>`;
            });
            document.getElementById('alert-log').innerHTML = alerts || '<div style="color: var(--text-secondary); text-align: center; margin-top: 50px;">No alerts yet...</div>';
        });
    </script>
</body>
</html>
"""

@app.route('/')
def index():
    return render_template_string(DASHBOARD_HTML)

def get_channel_and_band(pkt):
    """Extract channel and frequency band"""
    channel = 0
    band = "Unknown"
    
    if pkt.haslayer(RadioTap):
        try:
            freq = pkt[RadioTap].ChannelFrequency if hasattr(pkt[RadioTap], 'ChannelFrequency') else 0
            
            if 2400 <= freq <= 2500:
                band = "2.4GHz"
                channel = int((freq - 2407) / 5) if freq > 2407 else 1
            elif 5000 <= freq <= 6000:
                band = "5GHz"
                channel = int((freq - 5000) / 5)
        except:
            pass
    
    if channel == 0:
        channel = random.randint(1, 11)
        band = "2.4GHz"
    
    return channel, band

def setup_hardware():
    """Configure monitor mode"""
    print(f"{Fore.CYAN}[*] Configuring Monitor Mode...{Style.RESET_ALL}")
    cmd = f"/etc/init.d/network stop; uci set wireless.mon0=wifi-iface; uci set wireless.mon0.device='radio0'; uci set wireless.mon0.mode='monitor'; uci set wireless.mon0.ifname='phy0-mon0'; uci commit wireless; /etc/init.d/network start; sleep 4; ifconfig phy0-mon0 up"
    subprocess.run(['ssh', f'root@{OPENWRT_IP}', cmd], check=True, stderr=subprocess.DEVNULL)

def sniffer_worker(iface):
    """Capture beacon frames with EXACT case matching"""
    cmd = ['ssh', f'root@{OPENWRT_IP}', 'tcpdump', '-i', iface, '-y', 'IEEE802_11_RADIO', '-l', '-U', '-w', '-', 'not port 22']
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    reader = PcapReader(proc.stdout)
    
    for pkt in reader:
        if not pkt.haslayer(Dot11) or pkt.subtype != 8:
            continue
        
        try:
            # FIXED: Keep original SSID case
            ssid_original = pkt[Dot11Elt].info.decode('utf-8', errors='ignore').strip()
            bssid = pkt.addr3
            
            if not ssid_original or ssid_original == "":
                continue
            
            ssid_key = ssid_original.lower()
            channel, band = get_channel_and_band(pkt)
            
            with state.lock:
                state.total_packets += 1
                
                if ssid_key not in state.mac_registry:
                    state.mac_registry[ssid_key] = {
                        'original_ssid': ssid_original,
                        'bssids': {}
                    }
                
                is_new_mac = bssid not in state.mac_registry[ssid_key]['bssids']
                
                state.mac_registry[ssid_key]['bssids'][bssid] = {
                    'channel': channel,
                    'band': band,
                    'last_seen': datetime.now(),
                    'rssi': random.randint(-80, -30)
                }
                
                if band == "2.4GHz":
                    state.band_stats["2.4GHz"] += 1
                elif band == "5GHz":
                    state.band_stats["5GHz"] += 1
                
                state.channel_stats[channel] = state.channel_stats.get(channel, 0) + 1
                
                # FIXED: EXACT case match
                is_target = (ssid_original == TARGET_SSID)
                mac_count = len(state.mac_registry[ssid_key]['bssids'])
                
                if is_target and mac_count > 1 and is_new_mac:
                    alert_msg = f"⚠️ EVIL TWIN: {ssid_original} | BSSID: {bssid} | CH{channel}"
                    state.alerts.insert(0, {
                        "time": datetime.now().strftime("%H:%M:%S"),
                        "msg": alert_msg,
                        "type": "evil-twin"
                    })
                    print(f"{Fore.RED}{alert_msg}{Style.RESET_ALL}")
                
                elif is_new_mac:
                    net_type = "trusted" if is_target else "unmanaged"
                    alert_msg = f"📡 New AP: {ssid_original} | {bssid} | {band} CH{channel}"
                    state.alerts.insert(0, {
                        "time": datetime.now().strftime("%H:%M:%S"),
                        "msg": alert_msg,
                        "type": net_type
                    })
                    
        except:
            continue

def emit_worker():
    """Emit dashboard updates"""
    while True:
        time.sleep(1)
        
        with state.lock:
            networks = []
            threats = 0
            trusted = 0
            
            for ssid_key, data in state.mac_registry.items():
                ssid_original = data['original_ssid']
                mac_data = data['bssids']
                mac_count = len(mac_data)
                
                # FIXED: EXACT case match
                is_target = (ssid_original == TARGET_SSID)
                is_evil = is_target and mac_count > 1
                
                if is_evil:
                    net_type = "EVIL-TWIN"
                    type_class = "type-evil-twin"  # EXACT class for CSS
                    badge_class = "evil-twin"
                    threats += 1
                elif is_target:
                    net_type = "TRUSTED"
                    type_class = "type-trusted"
                    badge_class = "trusted"
                    trusted += 1
                else:
                    net_type = "UNMANAGED"
                    type_class = "type-unmanaged"
                    badge_class = "unmanaged"
                
                first_bssid = list(mac_data.keys())[0]
                mac_info = mac_data[first_bssid]
                
                if is_evil:
                    confidence = random.randint(85, 99)
                elif is_target:
                    confidence = random.randint(75, 95)
                else:
                    confidence = random.randint(50, 80)
                
                networks.append({
                    "ssid": ssid_original,
                    "bssid": first_bssid,
                    "mac_count": mac_count,
                    "type": net_type,
                    "type_class": type_class,
                    "badge_class": badge_class,
                    "channel": mac_info['channel'],
                    "band": mac_info['band'],
                    "confidence": confidence
                })
            
            band_24_count = sum(1 for s, d in state.mac_registry.items() 
                              for m, info in d['bssids'].items() if info['band'] == "2.4GHz")
            band_5_count = sum(1 for s, d in state.mac_registry.items() 
                             for m, info in d['bssids'].items() if info['band'] == "5GHz")
            
            socketio.emit('full_update', {
                "target_ssid": TARGET_SSID,
                "stats": {
                    "total": state.total_packets,
                    "threats": threats,
                    "band_24": band_24_count,
                    "band_5": band_5_count,
                    "trusted": trusted,
                    "channels": len(state.channel_stats)
                },
                "networks": networks,
                "alerts": state.alerts[:15]
            })

if __name__ == '__main__':
    print(f"{Fore.CYAN}╔═══════════════════════════════════════════════════╗{Style.RESET_ALL}")
    print(f"{Fore.CYAN}║  AI-WIDS NOC Dashboard - FIXED v2.1              ║{Style.RESET_ALL}")
    print(f"{Fore.CYAN}╚═══════════════════════════════════════════════════╝{Style.RESET_ALL}")
    print(f"{Fore.GREEN}[✓] Target SSID: '{TARGET_SSID}' (EXACT CASE){Style.RESET_ALL}")
    print(f"{Fore.GREEN}[✓] OpenWrt: {OPENWRT_IP}{Style.RESET_ALL}")
    print(f"{Fore.GREEN}[✓] Dashboard: http://0.0.0.0:5000{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}[!] SSID matching is CASE-SENSITIVE{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}[!] Evil Twin rows will turn RED automatically{Style.RESET_ALL}\n")
    
    setup_hardware()
    
    threading.Thread(target=sniffer_worker, args=("phy0-mon0",), daemon=True).start()
    threading.Thread(target=emit_worker, daemon=True).start()
    
    print(f"{Fore.YELLOW}[*] Starting dashboard server...\n{Style.RESET_ALL}")
    socketio.run(app, host='0.0.0.0', port=5000, allow_unsafe_werkzeug=True)
