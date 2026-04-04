#!/usr/bin/env python3
"""
===============================================================================
AI-WIDS Feature Extraction Module
===============================================================================
Purpose: Convert PCAP files to AWID3-style CSV features for Evil Twin detection
Input:   ../data/raw/normal/*.pcap, ../data/raw/attack/*.pcap
Output:  ../data/processed/Features.csv
===============================================================================
"""

import os
import sys
from pathlib import Path
import pandas as pd
from pyshark import FileCapture
from pyshark.packet.packet import Packet
import argparse

def extract_awid3_features(pkt: Packet):
    """
    Extract features from a packet in AWID3 style. Missing features are filled with 0.
    """

    wlan_fc_type = 0
    wlan_fc_subtype = 0
    wlan_fc_ds = 0
    wlan_fc_protected = 0
    wlan_fc_moredata = 0
    wlan_fc_frag = 0
    wlan_fc_retry = 0
    wlan_fc_pwrmgt = 0
    wlan_radio_phy = 0
    wlan_radio_datarate = 0
    wlan_radio_duration = 0
    wlan_radio_signal_dbm = 0
    wlan_radio_start_tsf = 0
    wlan_radio_end_tsf = 0
    wlan_radio_timestamp = 0
    wlan_radio_channel = 0
    wlan_radio_frequency = 0
    radiotap_length = 0
    radiotap_datarate = 0
    radiotap_timestamp_ts = 0
    radiotap_mactime = 0
    radiotap_channel_flags_ofdm = 0
    radiotap_channel_flags_cck = 0

    frame_len = int(getattr(pkt.frame_info, "len", "0"))
    frame_time_relative = float(getattr(pkt.frame_info, "time_relative", "0"))

    if hasattr(pkt, "wlan"):
        wlan = pkt.wlan

        # Extract frame control type field
        fc_tree = getattr(wlan, "fc_tree", None)
        wlan_fc_type = int(getattr(fc_tree, "type", "0") or 0)

        # Extract frame control subtype field
        wlan_fc_subtype = int(getattr(fc_tree, "subtype", "0") or 0)

        # Extract frame flags
        flags_tree = getattr(fc_tree, "flags_tree", None)

        wlan_fc_protected = int(getattr(flags_tree, "protected", "0"))
        wlan_fc_moredata = int(getattr(flags_tree, "moredata", "0"))
        wlan_fc_retry = int(getattr(flags_tree, "retry","0"))
        wlan_fc_frag = int(getattr(flags_tree, "frag","0"))

        wlan_fc_ds = int(getattr(wlan, "ds", "0"))
        wlan_fc_pwrmgt = int(getattr(wlan, "pwrmgt", "0"))
    
    if hasattr(pkt, "wlan_radio"):
        wlan_radio_phy = int(getattr(pkt.wlan_radio, "phy", "0"))
        wlan_radio_datarate = int(getattr(pkt.wlan_radio, "data_rate", "0"))
        wlan_radio_duration = int(getattr(pkt.wlan_radio, "duration", "0"))
        wlan_radio_signal_dbm = int(getattr(pkt.wlan_radio, "signal_dbm", "0"))
        wlan_radio_start_tsf = int(getattr(pkt.wlan_radio, "start_tsf", "0"))
        wlan_radio_end_tsf = int(getattr(pkt.wlan_radio, "end_tsf", "0"))
        wlan_radio_timestamp = int(getattr(pkt.wlan_radio, "timestamp", "0"))
        wlan_radio_channel = int(getattr(pkt.wlan_radio, "channel", "0"))
        wlan_radio_frequency = int(getattr(pkt.wlan_radio, "frequency", "0"))
    
    if hasattr(pkt, "radiotap"):
        radiotap_length = int(getattr(pkt.radiotap, "length", "0"))
        radiotap_datarate = int(getattr(pkt.radiotap, "datarate", "0"))
        radiotap_timestamp_ts = int(getattr(pkt.radiotap, "timestamp_ts", "0"))
        radiotap_mactime = int(getattr(pkt.radiotap, "mactime", "0"))
        radiotap_channel_flags_ofdm = int(getattr(pkt.radiotap, "channel_flags_ofdm", "0"))
        radiotap_channel_flags_cck = int(getattr(pkt.radiotap, "channel_flags_cck", "0"))

    features = {
        "wlan_fc.type": wlan_fc_type,
        "wlan_fc.subtype": wlan_fc_subtype,
        "wlan_fc.ds": wlan_fc_ds,
        "wlan_fc.protected": wlan_fc_protected,
        "wlan_fc.moredata": wlan_fc_moredata,
        "wlan_fc.frag": wlan_fc_frag,
        "wlan_fc.retry": wlan_fc_retry,
        "wlan_fc.pwrmgt": wlan_fc_pwrmgt,
        "wlan_radio.phy": wlan_radio_phy,
        "wlan_radio.data_rate": wlan_radio_datarate,
        "wlan_radio.duration": wlan_radio_duration,
        "wlan_radio.signal_dbm": wlan_radio_signal_dbm,
        "wlan_radio.start_tsf": wlan_radio_start_tsf,
        "wlan_radio.end_tsf": wlan_radio_end_tsf,
        "wlan_radio.timestamp": wlan_radio_timestamp,
        "wlan_radio.channel": wlan_radio_channel,
        "wlan_radio.frequency": wlan_radio_frequency,
        "radiotap.length": radiotap_length,
        "radiotap.datarate": radiotap_datarate,
        "radiotap.timestamp.ts": radiotap_timestamp_ts,
        "radiotap.mactime": radiotap_mactime,
        "radiotap.channel.flags.ofdm": radiotap_channel_flags_ofdm,
        "radiotap.channel.flags.cck": radiotap_channel_flags_cck,
        "frame.len": frame_len,
        "frame.time_relative": frame_time_relative,
    }


    return features

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Extract AWID3-style features from PCAP files")
    parser.add_argument("pcap_file", help="Path to PCAP file")
    parser.add_argument("--filter", default="", help="Display filter for attack frames")
    parser.add_argument("--label", default="attack", help="Label for attack frames")
    parser.add_argument("--output", default="../data/processed/Features.csv", help="Output CSV file for features")
    args = parser.parse_args()
    
    pcap_file = args.pcap_file
    atttack_conditions = args.filter
    attack_label = args.label
    output_csv = args.output

    all_features = []
    attack_frame_numbers = []

    
    print(f"Processing {pcap_file}...")
    if atttack_conditions:
        attacks = FileCapture(
            input_file=str(pcap_file),          # Convert Path object to string
            use_json=True,                       # Use JSON parsing for speed
            include_raw=False,                   # Don't store raw packet data
            keep_packets=False,                  # Don't keep packets in memory
            only_summaries=False,                # Parse full packet details
            display_filter=atttack_conditions    # Filter for attack frames
        )
        
        attack_frames = [pkt.frame_info.number for pkt in attacks]
        attack_frame_numbers = set(attack_frames)
        print(f"Identified {len(attack_frame_numbers)} attack frames based on filter: {atttack_conditions}")
    else:
        print("No attack filter provided, all frames will be labeled as normal.")
    pkts = FileCapture(
        input_file=str(pcap_file),          # Convert Path object to string
        use_json=True,                       # Use JSON parsing for speed
        include_raw=False,                   # Don't store raw packet data
        keep_packets=False,                  # Don't keep packets in memory
        only_summaries=False,                # Parse full packet details
        )

    for pkt in pkts:
        features = extract_awid3_features(pkt)
        if pkt.frame_info.number in attack_frame_numbers:
            features["label"] = attack_label
        else:
            features["label"] = "normal"

        all_features.append(features)

    df = pd.DataFrame(all_features)
    df.to_csv(output_csv, index=False)
    print(f"Features extracted and saved to {output_csv}")

