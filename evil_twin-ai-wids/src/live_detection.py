#!/usr/bin/env python3
"""
live_detection.py
Production-ready AI-WIDS Evil Twin + Mobile Hotspot Detection
"""

import torch
import torch.nn as nn
from scapy.all import PcapReader, Dot11
import numpy as np
import sys
import time
from collections import defaultdict, deque

# ----------------------------
# ML Model
# ----------------------------
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

# ----------------------------
# Feature extraction
# ----------------------------
def extract_features(pkt, deauth_buffer, beacon_buffer):
    features = {}
    features['frame_length'] = len(bytes(pkt))
    features['frame_type'] = pkt.type if pkt.haslayer(Dot11) else 0
    features['frame_subtype'] = pkt.subtype if pkt.haslayer(Dot11) else 0

    is_mgmt = int(pkt.haslayer(Dot11) and pkt.type == 0)
    is_beacon = int(pkt.haslayer(Dot11) and pkt.type == 0 and pkt.subtype == 8)
    is_deauth = int(pkt.haslayer(Dot11) and pkt.type == 0 and pkt.subtype == 12)

    features['is_mgmt'] = is_mgmt
    features['is_beacon'] = is_beacon
    features['is_deauth'] = is_deauth

    ssid = pkt.info.decode(errors='ignore') if is_beacon else ''
    bssid = pkt.addr3 if pkt.haslayer(Dot11) else None
    features['ssid'] = ssid if ssid else "UNKNOWN"
    features['bssid'] = bssid

    deauth_buffer.append(is_deauth)
    beacon_buffer.append(is_beacon)
    features['deauth_rate'] = sum(deauth_buffer)/len(deauth_buffer)*10
    features['beacon_rate'] = sum(beacon_buffer)/len(beacon_buffer)*10

    return features

# ----------------------------
# Mobile hotspot OUIs (common)
# ----------------------------
MOBILE_OUIS = [
    "f6:55:a8",  # example iPhone
    "ee:55:a8",  # example Android
    "fa:c6:f7",  # example Android
]

def is_mobile_hotspot(bssid):
    if bssid:
        prefix = bssid.lower()[:8]
        return prefix in MOBILE_OUIS
    return False

# ----------------------------
# Main
# ----------------------------
if __name__ == "__main__":
    checkpoint = torch.load("../data/model/wireless_ids.pt", map_location='cpu')
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    model = EvilTwinDetector(checkpoint['scaler'].n_features_in_).to(device)
    model.load_state_dict(checkpoint['model_state_dict'])
    model.eval()
    scaler = checkpoint['scaler']

    print("AI-WIDS Evil Twin + Mobile Hotspot Detection\n")

    DEAUTH_WINDOW = 20
    BEACON_WINDOW = 20
    PRINT_INTERVAL = 5
    deauth_buffer = deque(maxlen=DEAUTH_WINDOW)
    beacon_buffer = deque(maxlen=BEACON_WINDOW)

    ssid_bssid_map = defaultdict(set)
    ssid_packet_count = defaultdict(int)
    reported_alerts = set()  # avoid repeated alerts
    last_summary_time = time.time()

    FEATURE_ORDER = checkpoint['feature_order'] if 'feature_order' in checkpoint else [
        # fallback
        'frame_length','frame_type','frame_subtype','is_mgmt','is_beacon','is_deauth','deauth_rate','ssid_length','beacon_rate'
    ]

    reader = PcapReader(sys.stdin.buffer)

    for pkt in reader:
        if not pkt.haslayer(Dot11):
            continue

        features = extract_features(pkt, deauth_buffer, beacon_buffer)
        ssid = features['ssid']
        bssid = features['bssid']

        # Track packets
        if bssid:
            ssid_bssid_map[ssid].add(bssid)
            ssid_packet_count[(ssid, bssid)] += 1

        # ML prediction
        try:
            feature_array = np.array([features.get(f,0) for f in FEATURE_ORDER]).reshape(1,-1)
            feature_scaled = scaler.transform(feature_array)
            with torch.no_grad():
                output = model(torch.FloatTensor(feature_scaled).to(device))
                prob = torch.softmax(output, dim=1)
                pred = torch.argmax(prob, dim=1).item()
                confidence = prob[0][pred].item()
            label = "EVIL TWIN" if pred==1 else "NORMAL"
        except Exception:
            label = "NORMAL"
            confidence = 0.0

        # Detect conflicts
        conflict = len(ssid_bssid_map[ssid]) > 1

        # Only report new alerts
        alert_key = (ssid, bssid, label, conflict)
        if alert_key not in reported_alerts:
            rules = []
            if conflict:
                rules.append("SSID_CONFLICT")
            if is_mobile_hotspot(bssid):
                rules.append("MOBILE_HOTSPOT")
            if label == "EVIL TWIN":
                rules.append("EVIL_TWIN_ML")
            if rules:
                print(f"\n🚨 ALERT → SSID: {ssid} | BSSID: {bssid}")
                print(f"   ML: {confidence:.2f} | RULES: {rules}")
            reported_alerts.add(alert_key)

        # Periodic summary
        now = time.time()
        if now - last_summary_time > PRINT_INTERVAL:
            print("\n📊 NETWORK SUMMARY")
            print(f"{'SSID':20} {'Packets':>7} {'BSSIDs':>7} {'Type':>12}")
            print("-"*55)
            for s, bset in ssid_bssid_map.items():
                pkt_count = sum(ssid_packet_count[(s,b)] for b in bset)
                net_type = "SUSPICIOUS" if len(bset)>1 else "MOBILE_HOTSPOT" if any(is_mobile_hotspot(b) for b in bset) else "NORMAL"
                print(f"{s:20} {pkt_count:7} {len(bset):7} {net_type:>12}")
            last_summary_time = now
