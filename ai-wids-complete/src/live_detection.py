#!/usr/bin/env python3
import threading
import subprocess
import time
import os
import numpy as np
import torch
import torch.nn as nn
from datetime import datetime
from scapy.all import Dot11, Dot11Elt, PcapReader, RadioTap
from flask import Flask, render_template_string, send_from_directory
from flask_socketio import SocketIO
from colorama import Fore, Style, init

init(autoreset=True)

# --- CONFIGURATION ---
OPENWRT_IP    = "192.168.32.55"
TARGET_SSID   = "FreeWiFi"
IFACE_24      = "phy0-mon0"
IFACE_50      = "phy1-mon0"
MODEL_PATH    = "../data/model/wireless_ids.pt"
STALE_TIMEOUT       = 15    # seconds — remove a beacon BSSID after this long
EVIL_THRESHOLD      = 0.45  # evil_prob must RISE above this to flip to EVIL TWIN
SAFE_THRESHOLD      = 0.30  # evil_prob must FALL below this to flip back to TRUSTED
EVIL_EMA_ALPHA      = 0.55  # smoothing factor — higher = faster detection
HOP_INTERVAL        = 1     # seconds per channel — lower = faster detection
DEAUTH_RATE_ALERT   = 3     # deauth frames/second sustained to trigger alert
DEAUTH_WINDOW       = 5     # sliding window in seconds for rate calculation
DEAUTH_HOLD_SECS    = 20    # keep deauth row visible for this long after last frame
DEAUTH_MIN_RATE     = 1.0   # minimum rate to UPDATE an existing attacker entry (frames/sec)
                            # stray frames below this rate are ignored entirely
DEAUTH_AI_EMA       = 0.2   # EMA smoothing for deauth AI confidence (lower = smoother)


TRUSTED_BSSIDS: set = {"fa:c6:f7:9e:cf:0c"}   # ← your phone hotspot MAC (always lowercase)

class WirelessIDS(nn.Module):
    def __init__(self, input_size, num_classes=3):
        super().__init__()
        self.fc1     = nn.Linear(input_size, 128)
        self.fc2     = nn.Linear(128, 64)
        self.fc3     = nn.Linear(64, 32)
        self.fc4     = nn.Linear(32, num_classes)   # 2=binary (old), 3=normal/evil/deauth (new)
        self.relu    = nn.ReLU()
        self.dropout = nn.Dropout(0.3)

    def forward(self, x):
        x = self.relu(self.fc1(x))
        x = self.dropout(x)
        x = self.relu(self.fc2(x))
        x = self.dropout(x)
        x = self.relu(self.fc3(x))
        return self.fc4(x)

class MonitorState:
    def __init__(self):
        self.mac_registry  = {}
        self.total_packets = 0
        self.alerts        = []
        self.channel_stats = set()
        self.lock          = threading.Lock()
        # AI model components (populated by load_model)
        self.model         = None
        self.scaler        = None
        self.feature_order = []
        # Deauth tracking: src_mac → list of timestamps of received deauths
        self.deauth_registry  = {}
        self.deauth_total     = 0
        # Active deauth attackers for the table: src_mac → {rate, dst, band, ch, last_seen}
        self.deauth_attackers = {}

state = MonitorState()
app = Flask(__name__)
# Keep your specific socketio configuration
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading', ping_timeout=60, ping_interval=25)

@app.route('/socket.io.min.js')
def serve_socketio():
    return send_from_directory(os.getcwd(), 'socket.io.min.js')

# --- DASHBOARD SECTION (UNCHANGED AS REQUESTED) ---
DASHBOARD_HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>AI-WIDS | NOC Dashboard - AUTO-REFRESH</title>
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
        
        .update-indicator {
            width: 8px;
            height: 8px;
            background: var(--cyan);
            border-radius: 50%;
            display: inline-block;
            margin-left: 8px;
            opacity: 0;
            transition: opacity 0.3s;
        }
        
        .update-indicator.flash {
            animation: flashUpdate 0.5s;
        }
        
        @keyframes flashUpdate {
            0%, 100% { opacity: 0; }
            50% { opacity: 1; }
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
            transition: all 0.3s ease;
        }
        
        tbody tr:hover {
            background: rgba(59, 130, 246, 0.1) !important;
        }
        
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

        tbody tr.type-deauth {
            background: rgba(239, 68, 68, 0.20) !important;
            border-left: 4px solid #ff0000 !important;
            animation: alertPulse 1s infinite !important;
        }

        tbody tr.type-deauth-ended {
            background: rgba(239, 68, 68, 0.06) !important;
            border-left: 4px solid #aa2222 !important;
        }

        .badge.deauth {
            background: rgba(239, 68, 68, 0.3);
            color: #ff4444;
            border: 1px solid #ff0000;
            animation: alertPulse 1s infinite;
        }

        .badge.deauth-ended {
            background: rgba(239, 68, 68, 0.1);
            color: #aa4444;
            border: 1px solid #aa2222;
        }
        
        tbody tr.row-changed {
            animation: rowFlash 0.5s;
        }
        
        @keyframes rowFlash {
            0% { transform: translateX(-5px); }
            50% { transform: translateX(5px); }
            100% { transform: translateX(0); }
        }
        
        @keyframes alertPulse {
            0%, 100% { 
                box-shadow: inset 0 0 20px rgba(239, 68, 68, 0.15), 0 0 0 rgba(239, 68, 68, 0);
            }
            50% { 
                box-shadow: inset 0 0 20px rgba(239, 68, 68, 0.15), 0 0 15px rgba(239, 68, 68, 0.4);
            }
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
            animation: dropDown 0.3s;
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
            🛡️AI Wireless Intrusion Detection System (AI-WIDS) NOC Dashboard
            <span class="update-indicator" id="update-flash"></span>
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
        <div class="stat-card red">
            <div class="stat-label">Deauth Frames</div>
            <div class="stat-value" id="deauth-total">0</div>
        </div>
        <div class="stat-card red">
            <div class="stat-label">Deauth Attackers</div>
            <div class="stat-value" id="deauth-active">0</div>
        </div>
    </div>
    
    <div class="main-grid">
        <div class="card">
            <div class="card-header">🌐 Network Monitor <small style="color: var(--cyan); font-weight: normal;">(Auto-refresh: 1.5 seconds)</small></div>
            <table>
                <thead>
                    <tr>
                        <th>SSID</th>
                        <th>BSSID</th>
                        <th>Channel</th>
                        <th>Band</th>
                        <th>MACs</th>
                        <th>AI Confidence / Rate</th>
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
        const socket = io({ 
            transports: ['polling'],
            reconnection: true,
            reconnectionDelay: 1000
        });
        
        let previousNetworks = {}; 
        
        setInterval(() => {
            const now = new Date();
            document.getElementById('timestamp').innerText = now.toTimeString().split(' ')[0];
        }, 1000);
        
        socket.on('full_update', (data) => {
            const indicator = document.getElementById('update-flash');
            indicator.classList.add('flash');
            setTimeout(() => indicator.classList.remove('flash'), 500);
            
            if (data.target_ssid) {
                document.getElementById('target-ssid').innerText = data.target_ssid;
            }
            
            document.getElementById('total-pkts').innerText = data.stats.total.toLocaleString();
            document.getElementById('threat-count').innerText = data.stats.threats;
            document.getElementById('band-24').innerText = data.stats.band_24;
            document.getElementById('band-5').innerText = data.stats.band_5;
            document.getElementById('trusted-count').innerText = data.stats.trusted;
            document.getElementById('channel-count').innerText = data.stats.channels;
            document.getElementById('deauth-total').innerText  = (data.stats.deauth_total || 0).toLocaleString();
            document.getElementById('deauth-active').innerText = data.stats.deauth_active || 0;
            
            let rows = "";
            data.networks.forEach(n => {
                const confidence = n.confidence || 0;
                const confClass = confidence > 80 ? 'high' : confidence > 50 ? 'medium' : 'low';
                const prevType = previousNetworks[n.bssid];
                const rowChanged = prevType && prevType !== n.type_class;
                const changedClass = rowChanged ? ' row-changed' : '';
                const isUnmanaged = n.type === 'UNMANAGED';

                previousNetworks[n.bssid] = n.type_class;

                const isDeauth = n.type === 'DEAUTH ATTACK' || n.type === 'DEAUTH ENDED';
                const noConf = isUnmanaged;
                let confCell;
                if (isDeauth) {
                    if (n.type === 'DEAUTH ATTACK' && n.confidence > 0) {
                        const aiPart = (n.ai_conf > 0)
                            ? ` <span style="color:#ff8888;font-size:0.75rem;">AI ${n.ai_conf}%</span>`
                            : '';
                        confCell = `<span style="color:#ff4444;font-weight:700;font-size:0.85rem;">${n.confidence}/s</span>${aiPart}`;
                    } else {
                        const aiPart = (n.ai_conf > 0)
                            ? `<span style="color:#aa4444;font-size:0.8rem;">AI ${n.ai_conf}%</span>`
                            : `<span style="color:var(--text-secondary);font-size:0.8rem;">—</span>`;
                        confCell = aiPart;
                    }
                } else if (noConf) {
                    confCell = `<span style="color:var(--text-secondary);font-size:0.8rem;">—</span>`;
                } else {
                    confCell = `<div class="confidence-bar">
                           <div class="confidence-fill ${confClass}" style="width:${confidence}%"></div>
                       </div> ${confidence}%`;
                }

                rows += `<tr class="${n.type_class}${changedClass}">
                    <td><strong>${n.ssid}</strong></td>
                    <td><span class="mac-address">${n.bssid}</span></td>
                    <td><span class="channel-badge">CH ${n.channel}</span></td>
                    <td>${n.band}</td>
                    <td>${n.mac_count}</td>
                    <td>${confCell}</td>
                    <td><span class="badge ${n.badge_class}">${n.type}</span></td>
                </tr>`;
            });
            
            document.getElementById('net-table').innerHTML = rows || '<tr><td colspan="7" style="text-align:center; color: var(--text-secondary);">No networks detected</td></tr>';
            
            let alerts = "";
            data.alerts.forEach(a => {
                const alertType = a.type || 'unmanaged';
                alerts += `<div class="alert-item ${alertType}">
                    <span class="alert-time">[${a.time}]</span> ${a.msg}
                </div>`;
            });
            document.getElementById('alert-log').innerHTML = alerts || '<div style="color: var(--text-secondary); text-align: center; margin-top: 50px;">No alerts yet...</div>';
        });
        
        socket.on('connect', () => console.log('✅ Connected'));
        socket.on('disconnect', () => console.log('⚠️ Disconnected'));
    </script>
</body>
</html>
"""

# --- AI INFERENCE HELPERS ---

def load_model():
    """Load wireless_ids.pt checkpoint into state.model / state.scaler / state.feature_order."""
    if not os.path.exists(MODEL_PATH):
        print(f"{Fore.RED}[!] Model not found: {MODEL_PATH}{Style.RESET_ALL}")
        return
    checkpoint = torch.load(MODEL_PATH, map_location='cpu')

    # Infer input size and output classes from saved weights — immune to config changes
    input_size  = checkpoint['model_state_dict']['fc1.weight'].shape[1]
    num_classes = checkpoint['model_state_dict']['fc4.weight'].shape[0]   # 2 (old) or 3 (new)

    # modeltrain.py saves key "features"; older scripts used "feature_order"
    state.feature_order = (
        checkpoint.get('features') or
        checkpoint.get('feature_order') or
        [f'feat_{i}' for i in range(input_size)]
    )

    state.scaler = checkpoint['scaler']
    state.model  = WirelessIDS(input_size, num_classes=num_classes)
    state.model.load_state_dict(checkpoint['model_state_dict'])
    state.model.eval()

    class_desc = {2: "normal/evil_twin (binary)", 3: "normal/evil_twin/deauth (3-class)"}
    print(f"{Fore.GREEN}[+] Model loaded: {MODEL_PATH}")
    print(f"    input_size={input_size}  num_classes={num_classes}  ({class_desc.get(num_classes, str(num_classes))}){Style.RESET_ALL}")


def extract_features(pkt):
    wlan_fc_type      = int(getattr(pkt, 'type',    0))
    wlan_fc_subtype   = int(getattr(pkt, 'subtype', 0))
    wlan_fc_ds = wlan_fc_protected = wlan_fc_moredata = 0
    wlan_fc_frag = wlan_fc_retry = wlan_fc_pwrmgt     = 0

    if pkt.haslayer(Dot11):
        fc = int(pkt[Dot11].FCfield)
        wlan_fc_ds        = fc & 0x03
        wlan_fc_frag      = (fc >> 2) & 1
        wlan_fc_retry     = (fc >> 3) & 1
        wlan_fc_pwrmgt    = (fc >> 4) & 1
        wlan_fc_moredata  = (fc >> 5) & 1
        wlan_fc_protected = (fc >> 6) & 1

    radiotap_length = radiotap_datarate = 0
    radiotap_ts = radiotap_mactime = radiotap_signal = 0
    radiotap_ofdm = radiotap_cck   = 0

    if pkt.haslayer(RadioTap):
        rt = pkt[RadioTap]
        radiotap_length  = int(getattr(rt, 'len',           0) or 0)
        radiotap_datarate= float(getattr(rt, 'Rate',        0) or 0)
        radiotap_ts      = float(getattr(rt, 'Timestamp',   0) or 0)
        radiotap_mactime = float(getattr(rt, 'mac_timestamp',0) or 0)
        radiotap_signal  = float(getattr(rt, 'dBm_AntSignal',0) or 0)
        ch_flags         = int(getattr(rt, 'ChannelFlags',  0) or 0)
        radiotap_ofdm    = 1 if (ch_flags & 0x0040) else 0
        radiotap_cck     = 1 if (ch_flags & 0x0020) else 0

    return {
        'wlan_fc.type':                  wlan_fc_type,
        'wlan_fc.subtype':               wlan_fc_subtype,
        'wlan_fc.ds':                    wlan_fc_ds,
        'wlan_fc.protected':             wlan_fc_protected,
        'wlan_fc.moredata':              wlan_fc_moredata,
        'wlan_fc.frag':                  wlan_fc_frag,
        'wlan_fc.retry':                 wlan_fc_retry,
        'wlan_fc.pwrmgt':                wlan_fc_pwrmgt,
        'radiotap.length':               radiotap_length,
        'radiotap.datarate':             radiotap_datarate,
        'radiotap.timestamp.ts':         radiotap_ts,
        'radiotap.mactime':              radiotap_mactime,
        'radiotap.signal.dbm':           radiotap_signal,
        'radiotap.channel.flags.ofdm':   radiotap_ofdm,
        'radiotap.channel.flags.cck':    radiotap_cck,
        'frame.len':                     len(pkt),
    }


def run_inference(pkt):
    if state.model is None:
        return 0, 0.0
    feats    = extract_features(pkt)
    x        = np.array([[feats.get(f, 0) for f in state.feature_order]], dtype=np.float32)
    x_scaled = state.scaler.transform(x)
    with torch.no_grad():
        logits     = state.model(torch.FloatTensor(x_scaled))
        probs      = torch.softmax(logits, dim=1)
        label      = int(torch.argmax(probs, dim=1).item())
        confidence = float(probs[0][label].item() * 100)
    return label, confidence


# --- BACKEND ---

def setup_hardware():
    print(f"{Fore.CYAN}[*] Configuring Dual Monitoring (phy0 & phy1)...{Style.RESET_ALL}")
    cmd = f"""
    /etc/init.d/network stop;
    # 2.4GHz
    uci delete wireless.mon24 2>/dev/null;
    uci set wireless.mon24=wifi-iface; uci set wireless.mon24.device='radio0';
    uci set wireless.mon24.mode='monitor'; uci set wireless.mon24.ifname='{IFACE_24}';
    # 5GHz
    uci delete wireless.mon50 2>/dev/null;
    uci set wireless.mon50=wifi-iface; uci set wireless.mon50.device='radio1';
    uci set wireless.mon50.mode='monitor'; uci set wireless.mon50.ifname='{IFACE_50}';
    uci commit wireless; /etc/init.d/network start; sleep 5;
    ifconfig {IFACE_24} up; ifconfig {IFACE_50} up;
    """
    subprocess.run(['ssh', f'root@{OPENWRT_IP}', cmd], check=True, stderr=subprocess.DEVNULL)

def channel_hopper():
    ch_24 = [1, 6, 11]
    ch_50 = [36, 44, 149, 157]
    while True:
        for i in range(max(len(ch_24), len(ch_50))):
            c24 = ch_24[i % len(ch_24)]
            c50 = ch_50[i % len(ch_50)]
            # Single SSH round-trip sets both interfaces — halves channel-change latency
            subprocess.run(
                ['ssh', f'root@{OPENWRT_IP}',
                 f'iw dev {IFACE_24} set channel {c24}; iw dev {IFACE_50} set channel {c50}'],
                stderr=subprocess.DEVNULL
            )
            with state.lock:
                state.channel_stats.add(c24)
                state.channel_stats.add(c50)
            time.sleep(HOP_INTERVAL)

def get_channel(pkt):
    elt = pkt.getlayer(Dot11Elt)
    while elt:
        if elt.ID == 3 and elt.info:
            return int(elt.info[0])
        elt = elt.payload if isinstance(getattr(elt, 'payload', None), Dot11Elt) else None
    # Fallback: derive channel from Radiotap carrier frequency
    if pkt.haslayer(RadioTap):
        freq = int(getattr(pkt[RadioTap], 'ChannelFrequency', 0) or 0)
        if 2412 <= freq <= 2484:
            return (freq - 2407) // 5
        if 5170 <= freq <= 5825:
            return (freq - 5000) // 5
    return '?'


def sniffer_worker(iface, band_label):
    cmd = ['ssh', f'root@{OPENWRT_IP}', 'tcpdump', '-i', iface, '-y', 'IEEE802_11_RADIO', '-l', '-U', '-w', '-', 'type mgt subtype beacon']
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    reader = PcapReader(proc.stdout)

    for pkt in reader:
        if not pkt.haslayer(Dot11Elt): continue
        try:
            ssid = pkt[Dot11Elt].info.decode('utf-8', errors='ignore').strip()
            if not ssid: continue
            bssid = (pkt.addr3 or '').lower()
            if not bssid: continue

            # Channel extraction always needed; inference only for FreeWiFi
            channel   = get_channel(pkt)
            is_target = (ssid == TARGET_SSID)
            if is_target:
                label, confidence = run_inference(pkt)
                # Beacon frames cannot be deauth frames — if 3-class model returns
                # label=2 on a beacon, it is a misclassification; treat as normal (0).
                if label == 2:
                    label = 0
            else:
                label, confidence = 0, 0.0   # UNMANAGED — no model needed
            now = time.time()

            with state.lock:
                state.total_packets += 1
                is_new = bssid not in state.mac_registry

                # EMA smoothing: blend new prediction into running evil-probability.
                # New BSSIDs start at 0.5 (neutral) — avoids one wrong first packet
                # locking the AP as trusted before enough evidence accumulates.
                if is_new:
                    evil_prob     = 0.5 + (0.5 if label == 1 else -0.5) * EVIL_EMA_ALPHA
                    was_evil_last = False
                else:
                    old_prob      = state.mac_registry[bssid]['evil_prob']
                    was_evil_last = state.mac_registry[bssid].get('is_evil', False)
                    evil_prob     = EVIL_EMA_ALPHA * (1.0 if label == 1 else 0.0) + (1 - EVIL_EMA_ALPHA) * old_prob

                # ── RULE 0: Explicitly trusted BSSID — always safe ────────────
                # Force evil_prob near zero so no other rule can flip it.
                if is_target and TRUSTED_BSSIDS and bssid in TRUSTED_BSSIDS:
                    evil_prob = min(evil_prob, 0.05)

                # ── RULE 1: Unknown BSSID broadcasting TARGET_SSID ────────────
                # If TRUSTED_BSSIDS is configured and this BSSID is NOT in it,
                # any FreeWiFi beacon from it is almost certainly an Evil Twin.
                elif is_target and TRUSTED_BSSIDS and bssid not in TRUSTED_BSSIDS:
                    evil_prob = max(evil_prob, 0.90)

                # ── RULE 2: Duplicate SSID heuristic (no TRUSTED_BSSIDS set) ──
                # If another BSSID is already broadcasting TARGET_SSID and we
                # have no explicit trust list, the new one is suspected evil.
                # Guard: skip if this BSSID is already known-trusted.
                elif is_new and is_target and not TRUSTED_BSSIDS:
                    other_targets = [
                        b for b, e in state.mac_registry.items()
                        if e['ssid'] == TARGET_SSID and b != bssid
                    ]
                    if other_targets:
                        evil_prob = max(evil_prob, 0.85)

                if was_evil_last:
                    is_evil = is_target and (evil_prob >= SAFE_THRESHOLD)
                else:
                    is_evil = is_target and (evil_prob >= EVIL_THRESHOLD)

                # Alert on NEW BSSID appearance or status change
                prev_is_evil = state.mac_registry[bssid].get('is_evil', None) if not is_new else None
                status_changed = (not is_new) and (prev_is_evil != is_evil)
                display_conf = round(confidence)

                state.mac_registry[bssid] = {
                    'ssid':       ssid,
                    'band':       band_label,
                    'ch':         channel,
                    'label':      label,
                    'evil_prob':  evil_prob,
                    'is_evil':    is_evil,
                    'confidence': display_conf,
                    'last_seen':  now,
                }

                if is_new or status_changed:
                    alert_type = "evil-twin" if is_evil else ("trusted" if is_target else "unmanaged")
                    conf_str   = f"  conf={confidence:.1f}%" if is_target else ""
                    prefix     = "[NEW]" if is_new else "[STATUS CHANGE]"
                    state.alerts.insert(0, {
                        "time": datetime.now().strftime("%H:%M:%S"),
                        "msg":  f"{prefix} [{band_label}] CH {channel} | {alert_type.upper()}: {ssid} ({bssid}){conf_str}",
                        "type": alert_type
                    })
        except: continue

def deauth_sniffer_worker(iface, band_label):
    """Capture deauth frames and track rate per source MAC (attacker)."""
    cmd = ['ssh', f'root@{OPENWRT_IP}', 'tcpdump', '-i', iface, '-y', 'IEEE802_11_RADIO',
           '-l', '-U', '-w', '-', 'type mgt subtype deauth']
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    reader = PcapReader(proc.stdout)

    for pkt in reader:
        if not pkt.haslayer(Dot11):
            continue
        try:
            src  = pkt[Dot11].addr2 or 'unknown'   # injector / spoofed AP MAC
            dst  = pkt[Dot11].addr1 or 'broadcast'  # victim client
            ch   = get_channel(pkt)
            now  = time.time()

            ai_label, ai_conf = run_inference(pkt)
            deauth_ai_conf = min(round(ai_conf), 99) if ai_label == 2 else 0

            with state.lock:
                state.deauth_total += 1
                if src not in state.deauth_registry:
                    state.deauth_registry[src] = []
                state.deauth_registry[src].append(now)
                state.deauth_registry[src] = [
                    t for t in state.deauth_registry[src] if now - t <= DEAUTH_WINDOW
                ]
                rate = len(state.deauth_registry[src]) / DEAUTH_WINDOW

                # Two-tier rate gating: track all sources above ALERT threshold, but only mark active attackers above MIN_RATE.
                prev = state.deauth_attackers.get(src)
                already_tracked = prev is not None

                if (already_tracked and rate >= DEAUTH_MIN_RATE) or \
                   (not already_tracked and rate >= DEAUTH_RATE_ALERT):
                    prev = prev or {}
                    # EMA smoothing so the AI% varies naturally rather than locking
                    prev_ai   = prev.get('ai_conf', deauth_ai_conf)
                    smooth_ai = round(DEAUTH_AI_EMA * deauth_ai_conf +
                                      (1 - DEAUTH_AI_EMA) * prev_ai)
                    state.deauth_attackers[src] = {
                        'src':       src,
                        'dst':       dst,
                        'rate':      rate,
                        'peak_rate': max(rate, prev.get('peak_rate', 0)),
                        'band':      band_label,
                        'ch':        ch if ch != '?' else prev.get('ch', '?'),
                        'last_seen': now,
                        'active':    True,
                        'ai_conf':   smooth_ai,
                    }

                if rate >= DEAUTH_RATE_ALERT:
                    last_alert_key = f'deauth_alerted_{src}'
                    last_t = state.deauth_registry.get(last_alert_key, 0)
                    if now - last_t > 5:
                        state.deauth_registry[last_alert_key] = now
                        state.alerts.insert(0, {
                            "time": datetime.now().strftime("%H:%M:%S"),
                            "msg":  f"[DEAUTH ATTACK] [{band_label}] src={src} dst={dst} rate={rate:.1f}/s",
                            "type": "evil-twin",
                        })
        except Exception:
            continue


def emit_worker():
    while True:
        time.sleep(0.5)
        networks, threats, trusted = [], 0, 0
        now = time.time()

        with state.lock:
            # ── Prune BSSIDs not seen within STALE_TIMEOUT seconds ──
            stale = [b for b, e in state.mac_registry.items()
                     if now - e['last_seen'] > STALE_TIMEOUT]
            for b in stale:
                del state.mac_registry[b]

            # ── One row per BSSID ──
            for bssid, entry in state.mac_registry.items():
                is_target = (entry['ssid'] == TARGET_SSID)
                is_evil   = entry.get('is_evil', False)

                if is_evil:     threats += 1
                elif is_target: trusted += 1

                networks.append({
                    "ssid":        entry['ssid'],
                    "bssid":       bssid,
                    "mac_count":   1,
                    "type":        "EVIL-TWIN" if is_evil else ("TRUSTED"    if is_target else "UNMANAGED"),
                    "type_class":  "type-evil-twin" if is_evil else ("type-trusted" if is_target else "type-unmanaged"),
                    "badge_class": "evil-twin"     if is_evil else ("trusted"      if is_target else "unmanaged"),
                    "channel":     entry['ch'],
                    "band":        entry['band'],
                    "confidence":  entry['confidence'] if is_target else None,
                    "sort_key":    0 if is_evil else (1 if is_target else 2),
                })

            # Add deauth attacker rows — keep visible for DEAUTH_HOLD_SECS after last frame
            stale_deauth = [s for s, e in state.deauth_attackers.items()
                            if now - e['last_seen'] > DEAUTH_HOLD_SECS]
            for s in stale_deauth:
                del state.deauth_attackers[s]

            for src, entry in state.deauth_attackers.items():
                elapsed   = now - entry['last_seen']
                still_active = elapsed < DEAUTH_WINDOW * 2
                cur_rate  = entry['rate'] if still_active else 0.0
                peak_rate = entry['peak_rate']

                if still_active:
                    label_text = f"DEAUTH {cur_rate:.1f}/s"
                    row_class  = "type-deauth"
                    badge      = "deauth"
                else:
                    ago = int(elapsed)
                    label_text = f"DEAUTH ENDED ({ago}s ago, peak {peak_rate:.1f}/s)"
                    row_class  = "type-deauth-ended"
                    badge      = "deauth-ended"

                networks.append({
                    "ssid":       label_text,
                    "bssid":      src,
                    "mac_count":  "→ " + (entry['dst'][:17] if entry['dst'] != 'broadcast' else 'BROADCAST'),
                    "type":       "DEAUTH ATTACK" if still_active else "DEAUTH ENDED",
                    "type_class": row_class,
                    "badge_class": badge,
                    "channel":    entry.get('ch', '?'),
                    "band":       entry['band'],
                    "confidence": round(cur_rate, 1) if still_active else 0,
                    "ai_conf":    entry.get('ai_conf', 0),
                    "deauth_rate": True,
                    "sort_key":   -1 if still_active else -0.5,
                })
                if still_active and cur_rate >= DEAUTH_RATE_ALERT:
                    threats += 1

            snapshot_total    = state.total_packets
            snapshot_channels = len(state.channel_stats)
            snapshot_alerts   = state.alerts[:20]
            snapshot_deauth   = state.deauth_total
            # Active deauth sources: those with frames in the last DEAUTH_WINDOW seconds
            now2 = time.time()
            active_deauth = sum(
                1 for k, v in state.deauth_registry.items()
                if not k.startswith('deauth_alerted_') and
                   isinstance(v, list) and
                   any(now2 - t <= DEAUTH_WINDOW for t in v)
            )

        # Emit outside the lock to avoid blocking the sniffer threads
        socketio.emit('full_update', {
            "target_ssid": TARGET_SSID,
            "stats": {
                "total":         snapshot_total,
                "threats":       threats,
                "trusted":       trusted,
                "band_24":       sum(1 for n in networks if n['band'] == "2.4GHz"),
                "band_5":        sum(1 for n in networks if n['band'] == "5GHz"),
                "channels":      snapshot_channels,
                "deauth_total":  snapshot_deauth,
                "deauth_active": active_deauth,
            },
            "networks": sorted(networks, key=lambda x: x['sort_key']),
            "alerts":    snapshot_alerts,
        })

@app.route('/')
def index(): return render_template_string(DASHBOARD_HTML)

if __name__ == '__main__':
    load_model()
    setup_hardware()
    threading.Thread(target=channel_hopper,  daemon=True).start()
    threading.Thread(target=sniffer_worker,        args=(IFACE_24, "2.4GHz"), daemon=True).start()
    threading.Thread(target=sniffer_worker,        args=(IFACE_50, "5GHz"),   daemon=True).start()
    threading.Thread(target=deauth_sniffer_worker, args=(IFACE_24, "2.4GHz"), daemon=True).start()
    threading.Thread(target=deauth_sniffer_worker, args=(IFACE_50, "5GHz"),   daemon=True).start()
    threading.Thread(target=emit_worker,           daemon=True).start()
    socketio.run(app, host='0.0.0.0', port=5000, allow_unsafe_werkzeug=True)


