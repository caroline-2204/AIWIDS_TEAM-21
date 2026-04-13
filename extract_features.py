#!/usr/bin/env python3
"""
===============================================================================
AI-WIDS Feature Extraction Module
===============================================================================
Converts PCAP files into AWID3-style CSV features for model training.

Supported labels (inferred from folder name):
  data/raw/normal/   → label = "normal"
  data/raw/attack/   → label = "evil_twin"
  data/raw/deauth/   → label = "deauth"

Output: data/processed/Features.csv
===============================================================================
"""

import os
import sys
import time
from pathlib import Path

import pandas as pd
from colorama import Back, Fore, Style, init
from pyshark import FileCapture
from pyshark.packet.packet import Packet
from tqdm import tqdm

init(autoreset=True)


def get_label(pcap_path: str) -> str:
    """Infer ground-truth label from the folder the PCAP sits in."""
    path = pcap_path.lower()
    if "deauth" in path:
        return "deauth"
    if "attack" in path or "evil" in path:
        return "evil_twin"
    return "normal"


def safe_int(val, default=0) -> int:
    try:
        return int(val)
    except Exception:
        return default


def safe_float(val, default=0.0) -> float:
    try:
        return float(val)
    except Exception:
        return default


def extract_awid3_features(pkt: Packet) -> dict:
    """
    Extract AWID3-style features from a single pyshark packet.
    Missing fields default to 0 so every row has the same columns.
    """
    # Frame-level
    frame_len = safe_int(getattr(getattr(pkt, "frame_info", None), "len", 0))
    frame_time_relative = safe_float(getattr(getattr(pkt, "frame_info", None), "time_relative", 0))

    # 802.11 frame control
    wlan_fc_type = wlan_fc_subtype = wlan_fc_ds = 0
    wlan_fc_protected = wlan_fc_moredata = wlan_fc_frag = 0
    wlan_fc_retry = wlan_fc_pwrmgt = 0

    if hasattr(pkt, "wlan"):
        wlan = pkt.wlan
        fc_tree = getattr(wlan, "fc_tree", None)
        wlan_fc_type = safe_int(getattr(fc_tree, "type", 0))
        wlan_fc_subtype = safe_int(getattr(fc_tree, "subtype", 0))
        flags_tree = getattr(fc_tree, "flags_tree", None)
        wlan_fc_protected = safe_int(getattr(flags_tree, "protected", 0))
        wlan_fc_moredata = safe_int(getattr(flags_tree, "moredata", 0))
        wlan_fc_retry = safe_int(getattr(flags_tree, "retry", 0))
        wlan_fc_frag = safe_int(getattr(flags_tree, "frag", 0))
        wlan_fc_ds = safe_int(getattr(wlan, "ds", 0))
        wlan_fc_pwrmgt = safe_int(getattr(wlan, "pwrmgt", 0))

    # Radio layer
    wlan_radio_phy = wlan_radio_duration = wlan_radio_signal_dbm = 0
    wlan_radio_datarate = 0.0

    if hasattr(pkt, "wlan_radio"):
        r = pkt.wlan_radio
        wlan_radio_phy = safe_int(getattr(r, "phy", 0))
        wlan_radio_datarate = safe_float(getattr(r, "data_rate", 0))
        wlan_radio_duration = safe_int(getattr(r, "duration", 0))
        wlan_radio_signal_dbm = safe_int(getattr(r, "signal_dbm", 0))

    # Radiotap
    radiotap_length = radiotap_timestamp_ts = radiotap_mactime = 0
    radiotap_datarate = 0.0
    radiotap_channel_flags_ofdm = radiotap_channel_flags_cck = 0

    if hasattr(pkt, "radiotap"):
        rt = pkt.radiotap
        radiotap_length = safe_int(getattr(rt, "length", 0))
        radiotap_datarate = safe_float(getattr(rt, "datarate", 0))
        radiotap_timestamp_ts = safe_int(getattr(rt, "timestamp_ts", 0))
        radiotap_mactime = safe_int(getattr(rt, "mactime", 0))
        radiotap_channel_flags_ofdm = safe_int(getattr(rt, "channel_flags_ofdm", 0))
        radiotap_channel_flags_cck = safe_int(getattr(rt, "channel_flags_cck", 0))

    return {
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
        "radiotap.length": radiotap_length,
        "radiotap.datarate": radiotap_datarate,
        "radiotap.timestamp.ts": radiotap_timestamp_ts,
        "radiotap.mactime": radiotap_mactime,
        "radiotap.channel.flags.ofdm": radiotap_channel_flags_ofdm,
        "radiotap.channel.flags.cck": radiotap_channel_flags_cck,
        "frame.len": frame_len,
        "frame.time_relative": frame_time_relative,
    }


def process_pcap(pcap_path: Path, label: str) -> list[dict]:
    """Process a single PCAP file and return a list of feature dicts."""
    rows = []
    try:
        cap = FileCapture(
            input_file=str(pcap_path),
            use_json=True,
            include_raw=False,
            keep_packets=False,
            only_summaries=False,
        )
        for pkt in tqdm(cap, desc=f"    {pcap_path.name}", unit="pkt", leave=False):
            features = extract_awid3_features(pkt)
            features["label"] = label
            rows.append(features)
    except Exception as e:
        print(f"  {Fore.RED}Error reading {pcap_path.name}: {e}{Style.RESET_ALL}")
    return rows


if __name__ == "__main__":
    print(f"\n{Back.BLUE}{Fore.WHITE} AI-WIDS FEATURE EXTRACTION {Style.RESET_ALL}\n")

    # Locate PCAPs across all three label folders
    folders = {
        "normal":     Path("../data/raw/normal"),
        "evil_twin":  Path("../data/raw/attack"),
        "deauth":     Path("../data/raw/deauth"),
    }

    pcap_files = []
    for label, folder in folders.items():
        found = list(folder.glob("*.pcap")) if folder.exists() else []
        print(f"  {label:12s}: {Fore.GREEN}{len(found)}{Style.RESET_ALL} PCAP(s) in {folder}")
        for p in found:
            pcap_files.append((p, label))

    if not pcap_files:
        print(f"\n{Fore.RED}No PCAP files found. Run the capture scripts first.{Style.RESET_ALL}")
        sys.exit(1)

    print(f"\n  Total files: {Fore.YELLOW}{len(pcap_files)}{Style.RESET_ALL}\n")

    # Process
    print(f"{Fore.CYAN}Processing PCAP files...{Style.RESET_ALL}")
    all_features = []
    start = time.time()

    for i, (pcap_path, label) in enumerate(pcap_files, 1):
        print(f"  [{i}/{len(pcap_files)}] {Fore.YELLOW}{pcap_path.name}{Style.RESET_ALL} → {label}")
        rows = process_pcap(pcap_path, label)
        all_features.extend(rows)

    elapsed = time.time() - start
    print(f"\n  ✓ Extracted {Fore.GREEN}{len(all_features)}{Style.RESET_ALL} packets in {elapsed:.1f}s\n")

    # Build DataFrame
    df = pd.DataFrame(all_features)
    print(f"{Fore.CYAN}Dataset summary:{Style.RESET_ALL}")
    print(f"  Rows:     {Fore.GREEN}{len(df)}{Style.RESET_ALL}")
    print(f"  Columns:  {Fore.GREEN}{len(df.columns)}{Style.RESET_ALL}")
    for lbl, cnt in df["label"].value_counts().items():
        print(f"  {lbl:12s}: {Fore.YELLOW}{cnt}{Style.RESET_ALL}")

    # Save
    os.makedirs("../data/processed", exist_ok=True)
    out_path = "../data/processed/Features.csv"
    df.to_csv(out_path, index=False)
    size_mb = os.path.getsize(out_path) / (1024 * 1024)
    print(f"\n  ✓ Saved: {Fore.GREEN}{out_path}{Style.RESET_ALL} ({size_mb:.2f} MB)")

    # Save 500-row sample for repo
    sample_path = "../data/processed/Features_sample.csv"
    df.sample(min(500, len(df)), random_state=42).to_csv(sample_path, index=False)
    print(f"  ✓ Saved: {Fore.GREEN}{sample_path}{Style.RESET_ALL} (500-row sample)")

    print(f"\n{Back.GREEN}{Fore.BLACK} EXTRACTION COMPLETE {Style.RESET_ALL}")
    print(f"\n{Fore.GREEN}Next: python src/train_model.py{Style.RESET_ALL}\n")
