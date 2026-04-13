#!/usr/bin/env python3
import argparse
import os
from pathlib import Path
import pandas as pd
from scapy.all import rdpcap, Dot11, RadioTap, Dot11Elt, Packet, Raw
from tqdm import tqdm                        


def extract_features(pkt: Packet):
    wlan_fc_ds = 0
    wlan_fc_protected = 0
    wlan_fc_moredata = 0
    wlan_fc_frag = 0
    wlan_fc_retry = 0
    wlan_fc_pwrmgt = 0
    radiotap_length = 0
    radiotap_datarate = 0
    radiotap_timestamp_ts = 0
    radiotap_mactime = 0
    radiotap_signal_dbm = 0
    radiotap_channel_flags_ofdm = 0
    radiotap_channel_flags_cck = 0

    frame_len = len(pkt)

    wlan_fc_type = int(getattr(pkt, "type", 0))
    wlan_fc_subtype = int(getattr(pkt, "subtype", 0))

    # Wlan Layer
    if pkt.haslayer(Dot11): # Wlan Layer
        fc = int(pkt[Dot11].FCfield)
        wlan_fc_frag = (fc >> 2) # wlan.fc.frag is 3th bit
        wlan_fc_retry = (fc >> 3) & 1 # wlan.fc.retry is 4th bit
        wlan_fc_pwrmgt = (fc >> 4) & 1 # wlan.fc.pwrmgt is 5rd bit
        wlan_fc_moredata = (fc >> 5) & 1 # wlan.fc.moredata is 6th bit
        wlan_fc_protected = (fc >> 6) & 1 # wlan.fc.protected is 7th bit
        wlan_fc_ds = (fc & 0x03) # wlan.fc.ds is 1st & 2nd bit

    if pkt.haslayer(RadioTap):
        radiotap = pkt[RadioTap]
        radiotap_length = getattr(radiotap, 'len', 0)
        radiotap_datarate = getattr(radiotap, 'Rate', 0)
        radiotap_timestamp_ts = getattr(radiotap, 'Timestamp', 0)
        radiotap_mactime = getattr(radiotap, 'mac_timestamp', 0)
        radiotap_signal_dbm = getattr(radiotap, 'dBm_AntSignal', 0)
        radiotap_channel_flags = int(getattr(radiotap, 'ChannelFlags', 0))
        radiotap_channel_flags_ofdm = 1 if (radiotap_channel_flags & 0x0040) else 0 # OFDM flag is 7th bit
        radiotap_channel_flags_cck = 1 if (radiotap_channel_flags & 0x0020) else 0 # CCK flag is 6th bit


    features = {
        "wlan_fc.type": wlan_fc_type,
        "wlan_fc.subtype": wlan_fc_subtype,
        "wlan_fc.ds": wlan_fc_ds,
        "wlan_fc.protected": wlan_fc_protected,
        "wlan_fc.moredata": wlan_fc_moredata,
        "wlan_fc.frag": wlan_fc_frag,
        "wlan_fc.retry": wlan_fc_retry,
        "wlan_fc.pwrmgt": wlan_fc_pwrmgt,
        "radiotap.length": radiotap_length,
        "radiotap.datarate": radiotap_datarate,
        "radiotap.timestamp.ts": radiotap_timestamp_ts,
        "radiotap.mactime": radiotap_mactime,
        "radiotap.signal.dbm": radiotap_signal_dbm,
        "radiotap.channel.flags.ofdm": radiotap_channel_flags_ofdm,
        "radiotap.channel.flags.cck": radiotap_channel_flags_cck,
        "frame.len": frame_len,
    }

    return features

def parse_args():
    parser = argparse.ArgumentParser(description="Extract AWID3-style features from PCAP files.")
    parser.add_argument("--normal-dir", default="../data/raw/normal", help="Directory containing normal PCAP files.")
    parser.add_argument("--attack-dir", default="../data/raw/attack", help="Directory containing attack PCAP files.")
    parser.add_argument("--output", default="../data/processed/Features.csv", help="Output CSV file path.")
    parser.add_argument("--target-ssid", default="FreeWiFi", help="SSID considered as evil twin attack traffic.")
    parser.add_argument("--count", type=int, default=-1, help="Max packets to read per PCAP (-1 = all).")
    return parser.parse_args()

if __name__ == "__main__":
    args = parse_args()
    target_ssid = args.target_ssid

    all_data = []

    for category, path in [('normal', args.normal_dir), ('attack', args.attack_dir)]:
        files = [f for f in os.listdir(path) if f.endswith('.pcap')]

        for file in files:
            print(f"Processing {file}...")
            pkts = rdpcap(os.path.join(path, file), count=args.count)

            for pkt in tqdm(pkts):
                if not pkt.haslayer(Dot11):
                    continue

                ssid = None
                if pkt.haslayer(Dot11Elt) and pkt.type == 0:
                    try:
                        ssid = pkt[Dot11Elt].info.decode('utf-8', errors='ignore')
                    except Exception:
                        pass

                features = extract_features(pkt)
                if category == 'attack' and ssid == target_ssid:
                    features['label'] = 1  # Evil Twin
                else:
                    features['label'] = 0  # Trusted OR Unmanaged

                all_data.append(features)

    df = pd.DataFrame(all_data)
    df.to_csv(args.output, index=False)
    print(f"Saved {len(df)} rows to {args.output}")

