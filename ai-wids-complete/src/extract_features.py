#!/usr/bin/env python3
"""
===============================================================================
AI-WIDS Feature Extraction Module - IMPROVED VERSION
===============================================================================
Purpose: Convert PCAP files to AWID3-style CSV features for Evil Twin detection
Input:   ../data/raw/normal/*.pcap, ../data/raw/attack/*.pcap
Output:  ../data/processed/Features.csv
Features: 40+ AWID3-style + Evil Twin-specific features
===============================================================================
"""

# ===========================
# IMPORTS
# ===========================
import os                                    # For file system operations
import sys                                   # For system-level functions
from pathlib import Path                     # For cross-platform path handling
import pandas as pd                          # For DataFrame creation and CSV export
from collections import defaultdict          # For auto-initializing dictionaries
from scapy.all import rdpcap, Dot11, Dot11Elt, IP, TCP, UDP, ARP, DNS, DHCP  # Packet parsing
from tqdm import tqdm                        # For progress bars
import time                                  # For timing operations
import colorama                              # For colored console output
from colorama import Fore, Style, Back       # Color constants
colorama.init(autoreset=True)                # Initialize colorama with auto-reset

# ===========================
# GLOBAL TRACKING DICTIONARIES
# ===========================
# Track deauthentication frames per BSSID (Base Station ID)
DEAUTH_COUNTER = defaultdict(int)            # Key: BSSID, Value: deauth count
# Track beacon frames per BSSID
BEACON_COUNTER = defaultdict(int)            # Key: BSSID, Value: beacon count
# Track SSIDs associated with each BSSID (for Evil Twin detection)
SSID_BY_BSSID = defaultdict(list)            # Key: BSSID, Value: list of SSIDs
# Track packet rates for temporal analysis
PACKET_TIMESTAMPS = defaultdict(list)        # Key: BSSID, Value: list of timestamps

# ===========================
# FEATURE EXTRACTION FUNCTION
# ===========================
def extract_awid3_features(pkt, pkt_idx, total_pkts):
    """
    Extract 40+ AWID3-style features + Evil Twin features from a single packet

    Args:
        pkt (scapy.packet.Packet): The packet to analyze
        pkt_idx (int): Current packet index (for progress tracking)
        total_pkts (int): Total packets to process

    Returns:
        dict: Feature dictionary with 40+ key-value pairs
    """

    # Initialize empty feature dictionary
    features = {}                            # Will hold all extracted features

    # ===========================
    # BASIC FRAME FEATURES
    # ===========================
    features['frame_length'] = len(pkt)                        # Total packet size in bytes
    features['frame_type'] = pkt.type if pkt.haslayer(Dot11) else 0       # 802.11 frame type (0=mgmt, 1=ctrl, 2=data)
    features['frame_subtype'] = pkt.subtype if pkt.haslayer(Dot11) else 0 # Frame subtype (e.g., 8=beacon, 12=deauth)

    # ===========================
    # 802.11 MANAGEMENT FRAMES (Evil Twin Detection Core)
    # ===========================
    if pkt.haslayer(Dot11):                  # Check if packet is 802.11 WiFi frame
        # Management frame detection (type=0)
        features['is_mgmt'] = 1 if pkt.type == 0 else 0        # 1 if management frame, 0 otherwise
        # Beacon frame detection (type=0, subtype=8)
        features['is_beacon'] = 1 if pkt.type == 0 and pkt.subtype == 8 else 0    # APs broadcast beacons
        # Deauthentication frame detection (type=0, subtype=12)
        features['is_deauth'] = 1 if pkt.type == 0 and pkt.subtype == 12 else 0   # Attackers send deauth floods
        # Extract BSSID (AP MAC address)
        bssid = pkt.addr2 or '00:00:00:00:00:00'               # Address 2 is transmitter (AP)

        # ===========================
        # DEAUTH ATTACK INDICATORS
        # ===========================
        if features['is_deauth']:            # If this is a deauth frame
            DEAUTH_COUNTER[bssid] += 1                         # Increment deauth count for this AP
            features['deauth_rate'] = DEAUTH_COUNTER[bssid]    # Store cumulative deauth count
            # Calculate combined packet rate (beacons + deauths)
            features['packet_rate'] = BEACON_COUNTER[bssid] + DEAUTH_COUNTER[bssid]
        else:                                # Not a deauth frame
            features['deauth_rate'] = 0                        # No deauth activity

        # ===========================
        # BEACON & SSID ANALYSIS (Evil Twin Core Detection)
        # ===========================
        if features['is_beacon'] and pkt.haslayer(Dot11Elt):  # If beacon with IE tags
            # Extract SSID (network name) from beacon
            ssid = pkt[Dot11Elt].info.decode(errors='ignore')  # Decode SSID bytes to string
            features['ssid'] = ssid                            # Store SSID name
            # SSID length (suspicious if empty or very long)
            features['ssid_length'] = len(ssid)                # Character count
            # Increment beacon counter for this AP
            BEACON_COUNTER[bssid] += 1                         # Track beacon rate
            features['beacon_rate'] = BEACON_COUNTER[bssid]    # Store cumulative beacon count
            # Track SSID-BSSID mappings for Evil Twin detection
            SSID_BY_BSSID[bssid].append(ssid)                  # Add this SSID to BSSID's list
            # **EVIL TWIN INDICATOR**: Multiple BSSIDs using same SSID
            features['ssid_conflict'] = len(set(SSID_BY_BSSID[bssid]))  # Unique SSIDs per BSSID

        else:                                # Not a beacon frame
            features['ssid'] = ''                              # No SSID present
            features['ssid_length'] = 0                        # Zero length
            features['beacon_rate'] = 0                        # No beacon activity
            features['ssid_conflict'] = 0                      # No conflict detected

        # ===========================
        # SIGNAL STRENGTH (RF Analysis)
        # ===========================
        if hasattr(pkt, 'dBm_AntSignal'):    # If signal strength is captured
            features['signal_strength'] = pkt.dBm_AntSignal    # Store dBm value (-30 to -90 typical)
        else:                                # Signal strength not available
            features['signal_strength'] = 0                    # Default to 0

    else:                                    # Not an 802.11 frame
        # Set all WiFi-specific features to 0
        features['is_mgmt'] = 0
        features['is_beacon'] = 0
        features['is_deauth'] = 0
        features['deauth_rate'] = 0
        features['beacon_rate'] = 0
        features['ssid'] = ''
        features['ssid_length'] = 0
        features['ssid_conflict'] = 0
        features['signal_strength'] = 0
        features['packet_rate'] = 0

    # ===========================
    # L2/L3 PROTOCOL FEATURES (AWID3 Style)
    # ===========================
    features['protocol_type'] = pkt.type if pkt.haslayer(Dot11) else 0  # 802.11 protocol type
    features['service'] = 0                  # Service field (simplified for this version)
    features['flag_number'] = 0              # Flag count (simplified)
    features['src_bytes'] = 0                # Source payload bytes
    features['dst_bytes'] = 0                # Destination payload bytes

    # ===========================
    # IP LAYER ANALYSIS
    # ===========================
    if pkt.haslayer(IP):                     # If packet has IP layer
        features['src_bytes'] = len(pkt[IP].payload)           # Payload size from source
        features['dst_bytes'] = len(pkt[IP].payload)           # Payload size to destination
        features['protocol'] = pkt[IP].proto                   # IP protocol (6=TCP, 17=UDP, etc.)
        # TCP-specific features
        features['src_port'] = pkt[TCP].sport if pkt.haslayer(TCP) else 0  # Source port number
        features['dst_port'] = pkt[TCP].dport if pkt.haslayer(TCP) else 0  # Dest port number
    else:                                    # No IP layer
        features['protocol'] = 0                               # No protocol
        features['src_port'] = 0                               # No source port
        features['dst_port'] = 0                               # No dest port

    # ===========================
    # AWID3 STATISTICAL FEATURES (Simplified)
    # ===========================
    # Connection statistics (simplified - full AWID3 has 155+ features)
    features['count'] = 0                    # Connection count in time window
    features['srv_count'] = 0                # Service count
    features['serror_rate'] = 0              # SYN error rate
    features['srv_serror_rate'] = 0          # Service SYN error rate
    features['rerror_rate'] = 0              # REJ error rate
    features['srv_rerror_rate'] = 0          # Service REJ error rate
    features['same_srv_rate'] = 0            # Same service rate
    features['diff_srv_rate'] = 0            # Different service rate
    features['srv_diff_host_rate'] = 0       # Service different host rate

    # Destination host statistics
    features['dst_host_count'] = 0           # Dest host connection count
    features['dst_host_srv_count'] = 0       # Dest host service count
    features['dst_host_same_srv_rate'] = 0   # Same service rate
    features['dst_host_diff_srv_rate'] = 0   # Different service rate
    features['dst_host_same_src_port_rate'] = 0   # Same source port rate
    features['dst_host_srv_diff_host_rate'] = 0   # Service different host rate
    features['dst_host_serror_rate'] = 0     # SYN error rate
    features['dst_host_srv_serror_rate'] = 0 # Service SYN error rate
    features['dst_host_rerror_rate'] = 0     # REJ error rate
    features['dst_host_srv_rerror_rate'] = 0 # Service REJ error rate

    return features                          # Return complete feature dictionary

# ===========================
# MAIN EXECUTION BLOCK
# ===========================
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
        pkts = rdpcap(str(pcap_file))        # Returns list of packet objects

        # Process each packet with progress bar
        for pkt_idx, pkt in enumerate(tqdm(pkts, desc="    Extracting", unit="pkt", leave=False)):
            # Extract features from this packet
            features = extract_awid3_features(pkt, pkt_idx, len(pkts))
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
