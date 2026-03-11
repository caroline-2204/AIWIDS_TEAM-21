#!/usr/bin/env python3
"""
pcap_to_features.py

Parse PCAP files and extract network features for machine learning training.
Supports both 802.11 (WiFi) frames and IP-level traffic.

Usage:
    python pcap_to_features.py --normal data/raw/normal*.pcap \
                               --attack data/raw/attack*.pcap \
                               --output data/processed/features.csv
"""

# Standard library imports for file handling and command-line arguments
import argparse
from pathlib import Path
from typing import List

# Third-party imports for data processing and packet parsing
import pandas as pd  # DataFrame operations for tabular data
import pyshark       # Wrapper around tshark for PCAP parsing


def parse_pcap(
    pcap_path: Path,
    label: str,
    display_filter: str = "",
    limit: int = 0,
) -> pd.DataFrame:
    """
    Parse a single PCAP file into a DataFrame of network features.

    Args:
        pcap_path: Path to the .pcap or .pcapng file
        label: Classification label ("normal" or "attack")
        display_filter: Optional Wireshark-style display filter
        limit: Maximum number of packets to parse (0 = all)

    Returns:
        pandas DataFrame with one row per packet containing extracted features
    """
    # Print status message to inform user of parsing progress
    print(f"[*] Parsing {pcap_path} (label={label})")

    # Initialize pyshark FileCapture object to read the PCAP file
    # use_json=True enables faster JSON-based parsing mode
    # include_raw=False reduces memory usage by not storing raw packet bytes
    # keep_packets=False allows garbage collection of processed packets
    capture = pyshark.FileCapture(
        input_file=str(pcap_path),          # Convert Path object to string
        use_json=True,                       # Use JSON parsing for speed
        include_raw=False,                   # Don't store raw packet data
        display_filter=display_filter or None,  # Apply optional filter
        keep_packets=False,                  # Don't keep packets in memory
        only_summaries=False,                # Parse full packet details
    )

    # Initialize empty list to store feature dictionaries for each packet
    rows = []
    # Initialize packet counter
    count = 0

    # Iterate through each packet in the capture file
    for pkt in capture:
        # Check if we've reached the packet limit (if specified)
        if limit and count >= limit:
            break  # Stop processing if limit reached

        # --- Extract base frame length ---
        try:
            # Get the packet length attribute (total bytes)
            frame_len = int(getattr(pkt, "length", 0))
        except Exception:
            # If extraction fails, default to 0
            frame_len = 0

        frame_num = int(getattr(pkt, "number", 0) or 0)

        # --- Initialize WiFi / 802.11 fields with default values ---
        # Frame control type (0=management, 1=control, 2=data)
        fc_type = 0
        # Frame control subtype (varies by type: beacon, probe, auth, etc.)
        fc_subtype = 0
        # Retry flag (1 if packet is retransmission)
        retry = 0
        # More data flag (1 if more fragments follow)
        more_data = 0
        # Source MAC address
        src = "unknown"
        # Destination MAC address
        dst = "unknown"
        # Basic Service Set Identifier (AP MAC address)
        bssid = "unknown"
        # Received Signal Strength Indicator (dBm)
        rssi = -100

        fc_protected = 0
        duration = 0
        seq_num = 0


        # Try to extract WiFi-specific fields if WLAN layer exists
        try:
            # Check if packet has an 802.11 (WLAN) layer
            if hasattr(pkt, "wlan"):
                # Get the WLAN layer object
                wlan = pkt.wlan

                # Extract frame control type field
                fc_tree = getattr(wlan, "fc_tree", None)


                fc_type = int(getattr(fc_tree, "type", "0") or 0)

                # Extract frame control subtype field
                fc_subtype = int(getattr(fc_tree, "subtype", "0") or 0)

                
                # Extract frame protected flag
                flags_tree = getattr(fc_tree, "flags_tree", None)

                fc_protected = int(getattr(flags_tree, "protected", "0"))   # 1 if encrypted, 0 if not

                # NAV Duration 
                duration = int(getattr(wlan, "duration", "0"))

                # Sequence Number
                seq_num = int(getattr(wlan, "seq"))

                # Get frame control flags as string
                # flags = getattr(wlan, "fc", "") or ""

                # Parse retry flag from flags string
                retry = int(getattr(flags_tree, "retry","0"))

                # Parse more_data flag from flags string
                more_data = int(getattr(flags_tree, "moredata","0"))

                # Extract source address (transmitter MAC)
                src = getattr(wlan, "sa", "unknown")

                # Extract destination address (receiver MAC)
                dst = getattr(wlan, "da", "unknown")

                # Extract BSSID (access point MAC address)
                bssid = getattr(wlan, "bssid", "unknown")

        except Exception:
            # If any WiFi field extraction fails, use defaults
            pass

        channel = 0
        data_rate = 0

        try:
            if hasattr(pkt, "wlan_radio"):
                wlan_radio = pkt.wlan_radio

                channel = getattr(wlan_radio, "channel")
                data_rate = getattr(wlan_radio, "data_rate")

                # Try to extract signal strength if available
                if hasattr(wlan, "signal_dbm"): # Still unknown
                    try:
                        # Convert signal strength to integer dBm value
                        rssi = int(wlan.signal_dbm)
                    except Exception:
                        # If conversion fails, use default weak signal
                        rssi = -100
        except Exception:
            pass

        # --- Initialize IP/TCP/UDP fields with default values ---
        # IP protocol number (6=TCP, 17=UDP, 1=ICMP, etc.)
        ip_proto = 0
        # Source IP address
        src_ip = "0.0.0.0"
        # Destination IP address
        dst_ip = "0.0.0.0"
        # Source port number (for TCP/UDP)
        src_port = 0
        # Destination port number (for TCP/UDP)
        dst_port = 0
        # TCP flags bitmap (SYN=0x02, ACK=0x10, RST=0x04, FIN=0x01, etc.)
        tcp_flags = 0

        # Try to extract IP-level fields if IP layer exists
        try:
            # Check if packet has an IP layer (IPv4)
            if hasattr(pkt, "ip"):
                # Get the IP layer object
                ip_layer = pkt.ip

                # Extract source IP address
                src_ip = getattr(ip_layer, "src", "0.0.0.0")

                # Extract destination IP address
                dst_ip = getattr(ip_layer, "dst", "0.0.0.0")

                # Extract IP protocol number
                ip_proto = int(getattr(ip_layer, "proto", "0") or 0)

            # Check if packet has a transport layer (TCP/UDP)
            if pkt.transport_layer:
                # Get transport layer name (e.g., "TCP" or "UDP")
                t_layer_name = pkt.transport_layer.lower()

                # Get the transport layer object by name
                t_layer = getattr(pkt, t_layer_name, None)

                # If transport layer exists, extract port numbers
                if t_layer is not None:
                    # Extract source port number
                    src_port = int(getattr(t_layer, "srcport", "0") or 0)

                    # Extract destination port number
                    dst_port = int(getattr(t_layer, "dstport", "0") or 0)

                    # If this is TCP, extract TCP flags
                    if t_layer_name == "tcp":
                        # Get TCP flags as string (e.g., "SYN, ACK")
                        flags_str = getattr(t_layer, "flags", "")

                        # Convert to lowercase for case-insensitive matching
                        flags_str = flags_str.lower()

                        # Build TCP flags bitmap by checking for each flag
                        # FIN = 0x01
                        tcp_flags |= 0x01 if "fin" in flags_str else 0
                        # SYN = 0x02
                        tcp_flags |= 0x02 if "syn" in flags_str else 0
                        # ACK = 0x10
                        tcp_flags |= 0x10 if "ack" in flags_str else 0
                        # RST = 0x04
                        tcp_flags |= 0x04 if "rst" in flags_str else 0
        except Exception:
            # If any IP/transport field extraction fails, use defaults
            pass

        # Create a dictionary containing all extracted features for this packet
        row = dict(
            frame_number=frame_num,   # Frame number for filtering
            frame_len=frame_len,      # Total packet size in bytes
            fc_type=fc_type,          # WiFi frame type
            fc_subtype=fc_subtype,    # WiFi frame subtype
            fc_protected=fc_protected,# Is protected
            duration=duration,        # Packet Duration
            seq_num=seq_num,          # Sequence Number
            channel=channel,          # Radio Channel
            data_rate=data_rate,      # Data Rate
            retry=retry,              # WiFi retry flag
            more_data=more_data,      # WiFi more data flag
            src=src,                  # Source MAC address
            dst=dst,                  # Destination MAC address
            bssid=bssid,              # Access point BSSID
            rssi=rssi,                # Signal strength
            ip_proto=ip_proto,        # IP protocol number
            src_ip=src_ip,            # Source IP address
            dst_ip=dst_ip,            # Destination IP address
            src_port=src_port,        # Source port
            dst_port=dst_port,        # Destination port
            tcp_flags=tcp_flags,      # TCP flags bitmap
            label=label,              # Classification label
        )

        # Append this packet's features to the list
        rows.append(row)

        # Increment packet counter
        count += 1

        # Print progress update every 500 packets
        if count % 500 == 0:
            print(f"    Parsed {count} packets...")

    # Close the packet capture file to free resources
    capture.close()

    # Convert list of dictionaries to pandas DataFrame
    df = pd.DataFrame(rows)

    # Print completion message with row count
    print(f"[*] Finished {pcap_path}: {len(df)} rows")

    # Return the DataFrame
    return df


def parse_multiple(
    pcaps: List[Path],
    label: str,
    display_filter: str,
    limit: int
) -> pd.DataFrame:
    """
    Parse multiple PCAP files with the same label.

    Args:
        pcaps: List of Path objects pointing to PCAP files
        label: Classification label for all files
        display_filter: Optional Wireshark display filter
        limit: Packet limit per file

    Returns:
        Combined DataFrame with all packets from all files
    """
    # Initialize empty list to store DataFrames
    dfs = []

    # Parse each PCAP file individually
    for p in pcaps:
        # Parse this PCAP and add resulting DataFrame to list
        dfs.append(parse_pcap(p, label=label, display_filter=display_filter, limit=limit))

    # If no DataFrames were created, return empty DataFrame
    if not dfs:
        return pd.DataFrame()

    # Concatenate all DataFrames vertically (stack rows)
    # ignore_index=True creates new sequential index
    return pd.concat(dfs, ignore_index=True)


def main():
    """Main entry point for the script."""
    # Create argument parser for command-line interface
    parser = argparse.ArgumentParser(
        description="Convert PCAP files to CSV feature table for ML training."
    )

    # Add argument for normal traffic PCAP files (optional, multiple files)
    parser.add_argument(
        "--normal",
        nargs="*",  # Accept zero or more values
        help="List of normal traffic PCAP files"
    )

    # Add argument for attack traffic PCAP files (optional, multiple files)
    parser.add_argument(
        "--attack",
        nargs="*",  # Accept zero or more values
        help="List of attack traffic PCAP files"
    )

    # Add argument for output CSV file path
    parser.add_argument(
        "--output",
        type=str,
        default="data/processed/wifi_features.csv",
        help="Output CSV file path (default: data/processed/wifi_features.csv)"
    )

    # Add argument for optional Wireshark display filter
    parser.add_argument(
        "--display-filter",
        type=str,
        default="",
        help="Wireshark display filter (e.g., 'wlan.fc.type==0')"
    )

    # Add argument for packet limit per file
    parser.add_argument(
        "--limit",
        type=int,
        default=0,
        help="Maximum packets per PCAP file (0 = unlimited)"
    )

    # Parse command-line arguments
    args = parser.parse_args()

    # Initialize list to hold all DataFrames (normal + attack)
    all_dfs = []

    # Process normal traffic PCAPs if provided
    if args.normal:
        # Convert string paths to Path objects
        norm_paths = [Path(p) for p in args.normal]

        # Parse all normal PCAPs with label="normal"
        df_n = parse_multiple(
            norm_paths,
            label="normal",
            display_filter=args.display_filter,
            limit=args.limit
        )

        # Add normal traffic DataFrame to list
        all_dfs.append(df_n)

    # Process attack traffic PCAPs if provided
    if args.attack:
        # Convert string paths to Path objects
        atk_paths = [Path(p) for p in args.attack]

        # Parse all attack PCAPs with label="attack"
        df_a = parse_multiple(
            atk_paths,
            label="attack",
            display_filter=args.display_filter,
            limit=args.limit
        )

        # Add attack traffic DataFrame to list
        all_dfs.append(df_a)

    # Check if any PCAPs were provided
    if not all_dfs:
        # Print error message and exit
        print("[!] No PCAPs provided. Use --normal and/or --attack arguments.")
        return

    # Combine all DataFrames (normal + attack) into single DataFrame
    df_all = pd.concat(all_dfs, ignore_index=True)

    # Print summary statistics
    print(f"\n[*] Combined rows: {len(df_all)}")
    print(df_all["label"].value_counts())  # Show count of each label

    # Create output directory if it doesn't exist
    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    # Write DataFrame to CSV file
    df_all.to_csv(out_path, index=False)

    # Print success message
    print(f"[+] Wrote {out_path}")


# If this script is run directly (not imported), execute main()
if __name__ == "__main__":
    main()
