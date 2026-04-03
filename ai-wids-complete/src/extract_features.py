#!/usr/bin/env python3
"""
===============================================================================
AI-WIDS Feature Extraction Module - IMPROVED VERSION
===============================================================================
Purpose: Convert PCAP files to AWID3-style CSV features for Evil Twin detection
Input:   ../data/raw/normal/*.pcap, ../data/raw/attack/*.pcap
Output:  ../data/processed/Features.csv
"""


# ===========================
# IMPORTS
# ===========================
import os                                    # For file system operations
import sys                                   # For system-level functions
from pathlib import Path                     # For cross-platform path handling
from pyshark import FileCapture
from pyshark.packet.packet import Packet
import pandas as pd                          # For DataFrame creation and CSV export
from scapy.all import rdpcap, Dot11, Dot11Elt, IP, TCP, UDP, ARP, DNS, DHCP  # Packet parsing
from tqdm import tqdm                        # For progress bars
import time                                  # For timing operations
import colorama                              # For colored console output
from colorama import Fore, Style, Back       # Color constants
colorama.init(autoreset=True)        

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
        wlan_radio_datarate = float(getattr(pkt.wlan_radio, "data_rate", "0"))
        wlan_radio_duration = int(getattr(pkt.wlan_radio, "duration", "0"))
        wlan_radio_signal_dbm = int(getattr(pkt.wlan_radio, "signal_dbm", "0"))
        wlan_radio_start_tsf = int(getattr(pkt.wlan_radio, "start_tsf", "0"))
        wlan_radio_end_tsf = int(getattr(pkt.wlan_radio, "end_tsf", "0"))
        wlan_radio_timestamp = int(getattr(pkt.wlan_radio, "timestamp", "0"))
        wlan_radio_channel = int(getattr(pkt.wlan_radio, "channel", "0")) 
        wlan_radio_frequency = int(getattr(pkt.wlan_radio, "frequency", "0"))
    
    if hasattr(pkt, "radiotap"):
        radiotap_length = int(getattr(pkt.radiotap, "length", "0"))
        radiotap_datarate = float(getattr(pkt.radiotap, "datarate", "0"))
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

    # Print header with styling
    print(f"\n{Back.BLUE}{Fore.WHITE} AI-WIDS FEATURE EXTRACTION {Style.RESET_ALL}\n")

    # ===========================
    # STEP 1: LOCATE PCAP FILES
    # ===========================
    print(f"{Fore.CYAN}[1/4] Locating PCAP files...{Style.RESET_ALL}")
    # Find all normal traffic PCAPs
    normal_pcaps = list(Path("../data/raw/normal").glob("*.pcap"))  # Convert generator to list
    print(f"  ✓ Normal PCAPs: {Fore.GREEN}{len(normal_pcaps)}{Style.RESET_ALL}")
    # Find all attack traffic PCAPs
    attack_pcaps = list(Path("../data/raw/attack").glob("*.pcap"))  # Convert generator to list
    print(f"  ✓ Attack PCAPs: {Fore.GREEN}{len(attack_pcaps)}{Style.RESET_ALL}")
    # Total files to process
    total_files = len(normal_pcaps) + len(attack_pcaps)
    print(f"  ✓ Total files: {Fore.YELLOW}{total_files}{Style.RESET_ALL}\n")

    # ===========================
    # STEP 2: PROCESS PCAP FILES
    # ===========================
    print(f"{Fore.CYAN}[2/4] Processing PCAP files...{Style.RESET_ALL}")
    all_features = []                        # List to store all feature dictionaries
    start_time = time.time()                 # Record start time for performance tracking
    # Combine normal and attack PCAPs
    all_pcaps = list(normal_pcaps) + list(attack_pcaps)
    # Process each PCAP file with progress bar
    for pcap_idx, pcap_file in enumerate(all_pcaps, 1):
        # Determine label (normal or evil_twin)
        label = "normal" if "normal" in str(pcap_file) else "evil_twin"
        # Display current file being processed
        print(f"  [{pcap_idx}/{total_files}] {Fore.YELLOW}{pcap_file.name}{Style.RESET_ALL} ({label})")
        # Read all packets from PCAP file
        pkts = FileCapture(
        input_file=str(pcap_file),          # Convert Path object to string
        use_json=True,                       # Use JSON parsing for speed
        include_raw=False,                   # Don't store raw packet data
        keep_packets=False,                  # Don't keep packets in memory
        only_summaries=False,                # Parse full packet details
        )

        # Process each packet with progress bar
        for pkt_idx, pkt in enumerate(tqdm(pkts, desc="    Extracting", unit="pkt", leave=False)):
            # Extract features from this packet
            features = extract_awid3_features(pkt)
            # Add label (normal or evil_twin)
            features['label'] = label         # Ground truth for supervised learning
            # Add to master list
            all_features.append(features)     # Append feature dict to list

    # Calculate processing time
    elapsed = time.time() - start_time        # Total seconds elapsed
    print(f"  ✓ Processed {Fore.GREEN}{len(all_features)}{Style.RESET_ALL} packets in {Fore.YELLOW}{elapsed:.2f}s{Style.RESET_ALL}\n")

    # ===========================
    # STEP 3: CREATE DATAFRAME
    # ===========================
    print(f"{Fore.CYAN}[3/4] Creating DataFrame...{Style.RESET_ALL}")

    # Convert list of dictionaries to pandas DataFrame
    df = pd.DataFrame(all_features)           # Each row is a packet, each column is a feature

    print(f"  ✓ Rows: {Fore.GREEN}{len(df)}{Style.RESET_ALL}")
    print(f"  ✓ Features: {Fore.GREEN}{len(df.columns)}{Style.RESET_ALL}")
    print(f"  ✓ Normal: {Fore.GREEN}{len(df[df['label']=='normal'])}{Style.RESET_ALL}")
    print(f"  ✓ Evil Twin: {Fore.RED}{len(df[df['label']=='evil_twin'])}{Style.RESET_ALL}\n")

    # ===========================
    # STEP 4: SAVE TO CSV
    # ===========================
    print(f"{Fore.CYAN}[4/4] Saving to CSV...{Style.RESET_ALL}")

    output_path = "../data/processed/Features.csv"  # Output file path
    df.to_csv(output_path, index=False)       # Save DataFrame to CSV (no index column)

    # Get file size
    file_size = os.path.getsize(output_path) / (1024*1024)  # Convert bytes to MB

    print(f"  ✓ Saved: {Fore.GREEN}{output_path}{Style.RESET_ALL}")
    print(f"  ✓ Size: {Fore.YELLOW}{file_size:.2f} MB{Style.RESET_ALL}\n")

    # Display summary statistics
    print(f"{Back.GREEN}{Fore.BLACK} EXTRACTION COMPLETE {Style.RESET_ALL}")
    print(f"\n{Fore.GREEN}Next: ./train_model.py{Style.RESET_ALL}\n")
