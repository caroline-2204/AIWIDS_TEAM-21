#!/usr/bin/env python3
import os
import pandas as pd
from scapy.all import rdpcap, Dot11, Dot11Elt
from tqdm import tqdm

TARGET_SSID = "FreeWiFi"

def extract_features():
    all_data = []
    
    for category in ['normal', 'attack']:
        path = f"../data/raw/{category}"
        files = [f for f in os.listdir(path) if f.endswith('.pcap')]
        
        for f_name in files:
            print(f"Processing {f_name}...")
            pkts = rdpcap(f"{path}/{f_name}")
            
            for pkt in tqdm(pkts):
                if not pkt.haslayer(Dot11): continue
                
                # Get SSID
                ssid = None
                if pkt.haslayer(Dot11Elt) and pkt.type == 0:
                    try:
                        ssid = pkt[Dot11Elt].info.decode('utf-8', errors='ignore')
                    except: pass

                # FEATURE MAPPING
                feat = {
                    'frame_len': len(pkt),
                    'is_beacon': 1 if pkt.subtype == 8 else 0,
                    'is_deauth': 1 if pkt.subtype == 12 else 0,
                    'signal': getattr(pkt, 'dBm_AntSignal', 0)
                }

                # TARGETED LABELING
                if category == 'attack' and ssid == TARGET_SSID:
                    feat['label'] = 1  # Evil Twin
                else:
                    feat['label'] = 0  # Trusted OR Unmanaged
                
                all_data.append(feat)

    df = pd.DataFrame(all_data)
    os.makedirs("../data/processed", exist_ok=True)
    df.to_csv("../data/processed/Features.csv", index=False)
    print("✓ Features.csv created.")

if __name__ == "__main__":
    extract_features()
