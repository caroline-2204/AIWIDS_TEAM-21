#!/usr/bin/env python3
"""
===============================================================================
AI-WIDS AWID3 Dataset Converter
===============================================================================
Converts a raw AWID3 CSV/PCAP into the same feature format used by the WIDS
model, enabling benchmarking against the public AWID3 dataset.

Usage:
    python awid3_to_features.py --input /path/to/awid3.pcap --out ../data/processed/awid3_features.csv
    python awid3_to_features.py --input /path/to/awid3.csv  --out ../data/processed/awid3_features.csv
===============================================================================
"""

import subprocess
import sys
import argparse
import os
import pandas as pd


AWID3_FIELDS = [
    "frame.encap_type",
    "frame.len",
    "frame.number",
    "frame.time",
    "frame.time_delta",
    "frame.time_delta_displayed",
    "frame.time_epoch",
    "frame.time_relative",
    "radiotap.channel.flags.cck",
    "radiotap.channel.flags.ofdm",
    "radiotap.channel.freq",
    "radiotap.datarate",
    "radiotap.dbm_antsignal",
    "radiotap.length",
    "radiotap.mactime",
    "radiotap.present.tsft",
    "radiotap.rxflags",
    "radiotap.timestamp.ts",
    "radiotap.vendor_oui",
    "wlan.duration",
    "wlan.analysis.kck",
    "wlan.analysis.kek",
    "wlan.bssid",
    "wlan.country_info.fnm",
    "wlan.country_info.code",
    "wlan.da",
    "wlan.fc.ds",
    "wlan.fc.frag",
    "wlan.fc.order",
    "wlan.fc.moredata",
    "wlan.fc.protected",
    "wlan.fc.pwrmgt",
    "wlan.fc.type",
    "wlan.fc.retry",
    "wlan.fc.subtype",
    "wlan.fcs.bad_checksum",
    "wlan.fixed.beacon",
    "wlan.fixed.capabilities.ess",
    "wlan.fixed.capabilities.ibss",
    "wlan.fixed.reason_code",
    "wlan.fixed.timestamp",
    "wlan.ra",
    "wlan_radio.duration",
    "wlan.rsn.ie.pmkid",
    "wlan.sa",
    "wlan.seq",
    "wlan.ssid",
    "wlan.ta",
    "wlan.tag",
    "wlan.tag.length",
    "wlan_radio.channel",
    "wlan_radio.data_rate",
    "wlan_radio.phy",
    "wlan_radio.signal_dbm",
    "wlan_radio.start_tsf",
    "wlan_radio.timestamp",
]


def extract_pcap(file_path: str, out_path: str, fields: list = None) -> None:
    """Extract fields from a PCAP using tshark and save to CSV."""
    if fields is None:
        fields = AWID3_FIELDS

    field_args = []
    for f in fields:
        field_args += ["-e", f]

    cmd = [
        "tshark",
        "-r", file_path,
        "-T", "fields",
        "-E", "header=y",
        "-E", "separator=,",
        "-E", "quote=d",
        "-E", "occurrence=f",
    ] + field_args

    print(f"Running tshark on {file_path}...")
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        with open(out_path, "w") as f:
            f.write(result.stdout)
        print(f"✓ Saved: {out_path}")
    except subprocess.CalledProcessError as e:
        print(f"tshark error: {e.stderr}")
        sys.exit(1)
    except FileNotFoundError:
        print("tshark not found. Install with: sudo apt install tshark")
        sys.exit(1)


def convert_awid3_csv(input_csv: str, out_path: str) -> None:
    """
    Reformat an existing AWID3 CSV to match the feature columns used by
    the WIDS model. Unmapped columns are dropped; missing columns are set to 0.
    """
    # Column mapping: AWID3 name → our feature name
    rename_map = {
        "frame.len":              "frame.len",
        "frame.time_relative":    "frame.time_relative",
        "wlan.fc.type":           "wlan_fc.type",
        "wlan.fc.subtype":        "wlan_fc.subtype",
        "wlan.fc.ds":             "wlan_fc.ds",
        "wlan.fc.protected":      "wlan_fc.protected",
        "wlan.fc.moredata":       "wlan_fc.moredata",
        "wlan.fc.frag":           "wlan_fc.frag",
        "wlan.fc.retry":          "wlan_fc.retry",
        "wlan.fc.pwrmgt":         "wlan_fc.pwrmgt",
        "wlan_radio.phy":         "wlan_radio.phy",
        "wlan_radio.data_rate":   "wlan_radio.data_rate",
        "wlan_radio.duration":    "wlan_radio.duration",
        "wlan_radio.signal_dbm":  "wlan_radio.signal_dbm",
        "radiotap.length":        "radiotap.length",
        "radiotap.datarate":      "radiotap.datarate",
        "radiotap.timestamp.ts":  "radiotap.timestamp.ts",
        "radiotap.mactime":       "radiotap.mactime",
        "radiotap.channel.flags.ofdm": "radiotap.channel.flags.ofdm",
        "radiotap.channel.flags.cck":  "radiotap.channel.flags.cck",
        "Label":                  "label",
        "label":                  "label",
    }

    df = pd.read_csv(input_csv, low_memory=False)
    df = df.rename(columns=rename_map)

    # Normalise label values to match training labels
    if "label" in df.columns:
        df["label"] = df["label"].astype(str).str.lower().str.strip()
        df["label"] = df["label"].replace({
            "normal":    "normal",
            "0":         "normal",
            "flooding":  "deauth",
            "deauth":    "deauth",
            "evil_twin": "evil_twin",
            "eviltwin":  "evil_twin",
        })
        # Drop rows with unknown labels
        known = {"normal", "evil_twin", "deauth"}
        df = df[df["label"].isin(known)]

    df = df.fillna(0)
    os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
    df.to_csv(out_path, index=False)
    print(f"✓ Converted {len(df)} rows → {out_path}")
    print(f"  Label distribution:\n{df['label'].value_counts().to_string()}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Convert AWID3 data to WIDS feature format")
    parser.add_argument("--input",  required=True, help="Input PCAP or CSV file")
    parser.add_argument("--out",    default="../data/processed/awid3_features.csv", help="Output CSV path")
    parser.add_argument("--format", choices=["pcap", "csv"], default=None,
                        help="Input format (auto-detected from extension if omitted)")
    args = parser.parse_args()

    fmt = args.format or ("csv" if args.input.endswith(".csv") else "pcap")

    if fmt == "csv":
        convert_awid3_csv(args.input, args.out)
    else:
        extract_pcap(args.input, args.out)
