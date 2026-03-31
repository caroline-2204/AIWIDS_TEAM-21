#!/usr/bin/env python3
"""
===============================================================================
AI-WIDS LIVE DETECTION - PROBABILITY COLUMN UPDATE
===============================================================================
"""

import json
import time
import threading
import subprocess
from collections import defaultdict, deque
from datetime import datetime

import numpy as np
import torch
import torch.nn as nn
from scapy.all import Dot11, Dot11Elt, PcapReader
from flask import Flask, render_template_string, render_template
from flask_socketio import SocketIO
import colorama
from colorama import Fore, Style, Back

colorama.init(autoreset=True)

# ===========================
# CONFIGURATION & STATE
# ===========================
OPENWRT_IP = "192.168.32.55"
INTERFACE = "phy0-mon0"
PRINT_INTERVAL = 2
ALERT_HISTORY_LIMIT = 50

class GlobalState:
    def __init__(self):
        self.ssid_map = defaultdict(set)
        self.bssid_to_ssid = {}
        self.packet_count = defaultdict(int)
        self.alerts = deque(maxlen=ALERT_HISTORY_LIMIT)
        self.net_confidence = defaultdict(float) # Stores max raw evil probability
        self.stats = {
            'total_packets': 0, 'normal_packets': 0, 'evil_twin_packets': 0,
            'alerts_count': 0, 'mobile_hotspots': 0, 'unique_ssids': 0,
            'unique_bssids': 0, 'conflict_ssids': 0,
        }
        self.lock = threading.Lock()

state = GlobalState()

# ===========================
# NEURAL NETWORK
# ===========================
# TODO: Import from train_model.py
class EvilTwinDetector(nn.Module):
    def __init__(self, input_size):
        super().__init__()
        self.fc1 = nn.Linear(input_size, 128)
        self.fc2 = nn.Linear(128, 64)
        self.fc3 = nn.Linear(64, 32)
        self.fc4 = nn.Linear(32, 2)
        self.relu = nn.ReLU()
        self.dropout = nn.Dropout(0.3)

    def forward(self, x):
        x = self.relu(self.fc1(x))
        x = self.dropout(x)
        x = self.relu(self.fc2(x))
        x = self.dropout(x)
        x = self.relu(self.fc3(x))
        return self.fc4(x)

# ===========================
# HELPERS
# ===========================
def is_mobile(bssid):
    if not bssid or len(bssid) < 8: return False
    bssid = bssid.lower()
    # Check randomized MAC bit or common mobile OUIs
    try:
        if int(bssid[:2], 16) & 0x02: return True
    except: pass
    return bssid[1] in ['2', '6', 'a', 'e']

def safe_decode_ssid(raw):
    try:
        ssid = raw.decode('utf-8', errors='ignore').replace('\x00', '').strip()
        return ssid if (ssid and ssid != "UNKNOWN") else None
    except: return None

# TODO: Replace with function imported from extract_features.py
def extract_features(pkt, deauth_buffer, beacon_buffer):
    """Parses 802.11 packets into features for the AI model."""
    f = {'frame_length': len(bytes(pkt))}
    f['frame_type'] = pkt.type if pkt.haslayer(Dot11) else 0
    f['frame_subtype'] = pkt.subtype if pkt.haslayer(Dot11) else 0
    is_beacon = int(pkt.haslayer(Dot11) and pkt.type == 0 and pkt.subtype == 8)
    is_deauth = int(pkt.haslayer(Dot11) and pkt.type == 0 and pkt.subtype == 12)
    f.update({'is_mgmt': int(pkt.haslayer(Dot11) and pkt.type == 0), 'is_beacon': is_beacon, 'is_deauth': is_deauth})
    
    ssid, bssid = None, pkt.addr3 or pkt.addr2 if pkt.haslayer(Dot11) else None
    if is_beacon and pkt.haslayer(Dot11Elt):
        elt = pkt.getlayer(Dot11Elt)
        while elt:
            if getattr(elt, 'ID', None) == 0:
                ssid = safe_decode_ssid(getattr(elt, 'info', None))
                break
            elt = elt.payload.getlayer(Dot11Elt)
    f['ssid'], f['bssid'] = ssid, bssid
    deauth_buffer.append(is_deauth); beacon_buffer.append(is_beacon)
    f['deauth_rate'] = sum(deauth_buffer) / max(1, len(deauth_buffer)) * 10
    f['beacon_rate'] = sum(beacon_buffer) / max(1, len(beacon_buffer)) * 10
    return f

# ===========================
# WEB DASHBOARD (RESTORED FULL UI)
# ===========================
app = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins='*', async_mode='threading')

DASHBOARD_HTML = """

"""

@app.route('/')
def index(): return render_template('dashboard.html')

# ===========================
# LOGIC & WORKER
# ===========================
def dashboard_worker():
    """Calculates network status and confidence scores for the UI."""
    while True:
        time.sleep(PRINT_INTERVAL)
        with state.lock:
            networks = []
            for ssid, bssids in state.ssid_map.items():
                evil_p = float(state.net_confidence.get(ssid, 0.0))
                conflict = len(bssids) > 1
                
                # Classification
                if conflict: net_type = 'EVIL-TWIN (Conflict)'
                elif evil_p >= 0.5: net_type = 'EVIL-TWIN (ML)'
                elif any(is_mobile(b) for b in bssids): net_type = 'MOBILE'
                else: net_type = 'NORMAL'

                # Confidence Logic: Ensure normal networks show high confidence in being safe
                if evil_p >= 0.5 or conflict:
                    confidence = 100.0 if conflict else (evil_p * 100)
                else:
                    confidence = (1.0 - evil_p) * 100
                    
                networks.append({
                    'ssid': ssid,
                    'type': net_type,
                    'evil_prob': evil_p * 100,
                    'confidence': confidence
                })
            
            networks.sort(key=lambda n: ('EVIL' not in n['type'], -n['confidence']))
            state.stats['unique_ssids'] = len(state.ssid_map)
            socketio.emit('stats', state.stats)
            socketio.emit('networks', networks)

def main():
    # Load Model
    checkpoint = torch.load('../data/models/wireless_ids.pt', map_location='cpu')
    model = EvilTwinDetector(checkpoint['scaler'].n_features_in_)
    model.load_state_dict(checkpoint['model_state_dict'])
    model.eval()
    scaler, feature_order = checkpoint['scaler'], checkpoint.get('feature_order', list(range(10)))

    # Start Threads
    threading.Thread(target=dashboard_worker, daemon=True).start()
    threading.Thread(target=lambda: socketio.run(app, host='0.0.0.0', port=5001, log_output=False), daemon=True).start()

    # Packet Capture
    cmd = ['ssh', f'root@{OPENWRT_IP}', 'tcpdump', '-i', INTERFACE, '-w', '-', '-s', '0', 'not', 'port', '22']
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    reader = PcapReader(proc.stdout)
    
    deauth_buf, beacon_buf, alerts_seen = deque(maxlen=20), deque(maxlen=20), set()
    
    for pkt in reader:
        if not pkt.haslayer(Dot11): continue
        f = extract_features(pkt, deauth_buf, beacon_buf)
        if not f['ssid'] or not f['bssid']: continue
            
        with state.lock:
            state.ssid_map[f['ssid']].add(f['bssid'])
            state.stats['total_packets'] += 1
            
            # ML Prediction
            try:
                x = scaler.transform(np.array([f.get(k, 0) for k in feature_order]).reshape(1, -1))
                with torch.no_grad():
                    out = model(torch.FloatTensor(x))
                    evil_p = torch.softmax(out, dim=1)[0][1].item()
                    state.net_confidence[f['ssid']] = max(state.net_confidence.get(f['ssid'], 0.0), evil_p)
                
                if evil_p >= 0.5 or len(state.ssid_map[f['ssid']]) > 1:
                    state.stats['evil_twin_packets'] += 1
                else:
                    state.stats['normal_packets'] += 1
            except: pass

            # Alert Triggers
            if f['ssid'] not in alerts_seen and (state.net_confidence[f['ssid']] > 0.8 or len(state.ssid_map[f['ssid']]) > 1):
                alert = {'type': 'THREAT DETECTED', 'ssid': f['ssid'], 'time': datetime.now().strftime('%H:%M:%S')}
                socketio.emit('alert', alert)
                alerts_seen.add(f['ssid'])

if __name__ == '__main__':
    main()
