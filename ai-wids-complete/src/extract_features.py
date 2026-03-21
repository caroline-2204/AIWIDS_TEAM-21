#!/usr/bin/env python3
"""
extract_features.py
Convert PCAP files to AWID3-style CSV features for Evil Twin detection
Input: ../data/raw/normal/*.pcap, data/raw/attack/*.pcap
Output: ../data/processed/Features.csv
Features: 35 AWID3-style + Evil Twin features
"""

import os
import sys
from pathlib import Path
import pandas as pd
from collections import defaultdict
from scapy.all import rdpcap, Dot11, Dot11Elt, IP, TCP, UDP, ARP, DNS, DHCP

# Global counters for attack indicators
DEAUTH_COUNTER = defaultdict(int)
BEACON_COUNTER = defaultdict(int)
SSID_BY_BSSID = defaultdict(list)

def extract_awid3_features(pkt):
    """Extract 35 AWID3-style features + Evil Twin features"""
    features = {}

    # Frame info
    features['frame_length'] = len(pkt)
    features['frame_type'] = pkt.type if pkt.haslayer(Dot11) else 0
    features['frame_subtype'] = pkt.subtype if pkt.haslayer(Dot11) else 0

    # 802.11 Management frames (Evil Twin detection)
    if pkt.haslayer(Dot11):
        features['is_mgmt'] = 1 if pkt.type == 0 else 0
        features['is_beacon'] = 1 if pkt.type == 0 and pkt.subtype == 8 else 0
        features['is_deauth'] = 1 if pkt.type == 0 and pkt.subtype == 12 else 0

        bssid = pkt.addr2 or '00:00:00:00:00:00'
        if features['is_deauth']:
            DEAUTH_COUNTER[bssid] += 1
            features['deauth_rate'] = DEAUTH_COUNTER[bssid]
            features['packet_rate'] = BEACON_COUNTER[bssid] + DEAUTH_COUNTER[bssid]
        else:
            features['deauth_rate'] = 0

        #if features['is_beacon'] and pkt.haslayer(Dot11Elt):
        #    ssid = pkt[Dot11Elt].info.decode(errors='ignore')
        #    features['ssid'] = ssid
        if features['is_beacon'] and pkt.haslayer(Dot11Elt):
            ssid = pkt[Dot11Elt].info.decode(errors='ignore')
            features['ssid'] = ssid          
            # New features
            features['ssid_length'] = len(ssid)
            BEACON_COUNTER[bssid] += 1
            features['beacon_rate'] = BEACON_COUNTER[bssid]
            SSID_BY_BSSID[bssid].append(ssid)
            features['ssid_conflict'] = len(set(SSID_BY_BSSID[bssid]))
        else:
            features['ssid'] = ''
            features['ssid_length'] = 0
            features['beacon_rate'] = 0
        
        if hasattr(pkt, 'dBm_AntSignal'):
            features['signal_strength'] = pkt.dBm_AntSignal
        else:
            features['signal_strength'] = 0


    # L2/L3 features (AWID3 style)
    features['protocol_type'] = pkt.type if pkt.haslayer(Dot11) else 0
    features['service'] = 0  # Simplified
    features['flag_number'] = 0
    features['src_bytes'] = 0
    features['dst_bytes'] = 0

    if pkt.haslayer(IP):
        features['src_bytes'] = len(pkt[IP].payload)
        features['dst_bytes'] = len(pkt[IP].payload)
        features['protocol'] = pkt[IP].proto
        features['src_port'] = pkt[TCP].sport if pkt.haslayer(TCP) else 0
        features['dst_port'] = pkt[TCP].dport if pkt.haslayer(TCP) else 0

    # Simplified AWID3 features (full list would be 155+)
    features['count'] = 0
    features['srv_count'] = 0
    features['serror_rate'] = 0
    features['srv_serror_rate'] = 0
    features['rerror_rate'] = 0
    features['srv_rerror_rate'] = 0
    features['same_srv_rate'] = 0
    features['diff_srv_rate'] = 0
    features['srv_diff_host_rate'] = 0
    features['dst_host_count'] = 0
    features['dst_host_srv_count'] = 0
    features['dst_host_same_srv_rate'] = 0
    features['dst_host_diff_srv_rate'] = 0
    features['dst_host_same_src_port_rate'] = 0
    features['dst_host_srv_diff_host_rate'] = 0
    features['dst_host_serror_rate'] = 0
    features['dst_host_srv_serror_rate'] = 0
    features['dst_host_rerror_rate'] = 0
    features['dst_host_srv_rerror_rate'] = 0

    return features

if __name__ == "__main__":
    normal_pcaps = Path("../data/raw/normal").glob("*.pcap")
    attack_pcaps = Path("../data/raw/attack").glob("*.pcap")

    all_features = []

    for pcap_file in list(normal_pcaps) + list(attack_pcaps):
        print(f"Processing {pcap_file}...")
        pkts = rdpcap(str(pcap_file))
        label = "normal" if "normal" in str(pcap_file) else "evil_twin"

        for pkt in pkts:
            features = extract_awid3_features(pkt)
            features['label'] = label
            all_features.append(features)

    df = pd.DataFrame(all_features)
    df.to_csv("../data/processed/Features.csv", index=False)
    print(f"✅ Features.csv created: {len(df)} rows, {len(df.columns)} columns")

