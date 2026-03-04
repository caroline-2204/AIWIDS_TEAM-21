#!/usr/bin/env python3
"""
unifi_remote_sniffer.py

Live packet sniffer for UniFi U6+ AP with real-time intrusion detection.

Connects to U6+ via SSH, captures packets from specified interface,
extracts features, and sends to inference API for classification.

Usage:
    python unifi_remote_sniffer.py --ap-ip 192.168.1.20 \
                                    --interface br0 \
                                    --server-url http://localhost:8000
"""

# Standard library imports
import argparse
import subprocess  # For SSH connection
import sys  # For system exit
import time  # For timestamps
from datetime import datetime  # For formatted timestamps

# Third-party imports
import requests  # For HTTP requests to inference API
from scapy.all import PcapReader, IP, TCP, UDP, Dot11  # Packet parsing

# ANSI color codes for terminal output
class Colors:
    """Terminal color codes for pretty printing."""
    GREEN = '\033[92m'  # Green for normal traffic
    RED = '\033[91m'    # Red for attack traffic
    YELLOW = '\033[93m' # Yellow for warnings
    BLUE = '\033[94m'   # Blue for info
    RESET = '\033[0m'   # Reset to default


def extract_features(pkt) -> dict:
    """
    Extract features from a packet for classification.

    Args:
        pkt: Scapy packet object

    Returns:
        dict: Feature dictionary matching training schema
    """
    # Initialize default feature values
    features = {
        "frame_len": 0,
        "fc_type": 0,
        "fc_subtype": 0,
        "retry": 0,
        "more_data": 0,
        "src": "unknown",
        "dst": "unknown",
        "bssid": "unknown",
        "rssi": -100,
        "ip_proto": 0,
        "src_ip": "0.0.0.0",
        "dst_ip": "0.0.0.0",
        "src_port": 0,
        "dst_port": 0,
        "tcp_flags": 0,
    }

    # --- Extract frame length ---
    try:
        # Get total packet length
        features["frame_len"] = len(pkt)
    except Exception:
        pass

    # --- Extract WiFi (802.11) features if present ---
    if pkt.haslayer(Dot11):
        # Get Dot11 (WiFi) layer
        dot11 = pkt.getlayer(Dot11)

        try:
            # Extract frame control type
            features["fc_type"] = dot11.type

            # Extract frame control subtype
            features["fc_subtype"] = dot11.subtype

            # Extract retry flag from frame control flags
            features["retry"] = 1 if dot11.FCfield & 0x08 else 0

            # Extract more data flag from frame control flags
            features["more_data"] = 1 if dot11.FCfield & 0x20 else 0

            # Extract MAC addresses
            features["src"] = dot11.addr2 if dot11.addr2 else "unknown"
            features["dst"] = dot11.addr1 if dot11.addr1 else "unknown"
            features["bssid"] = dot11.addr3 if dot11.addr3 else "unknown"

            # Note: RSSI not available in all packet captures
            # Would need radiotap header for signal strength
        except Exception:
            pass

    # --- Extract IP features if present ---
    if pkt.haslayer(IP):
        # Get IP layer
        ip_layer = pkt.getlayer(IP)

        try:
            # Extract source IP address
            features["src_ip"] = ip_layer.src

            # Extract destination IP address
            features["dst_ip"] = ip_layer.dst

            # Extract IP protocol number
            features["ip_proto"] = ip_layer.proto
        except Exception:
            pass

    # --- Extract TCP features if present ---
    if pkt.haslayer(TCP):
        # Get TCP layer
        tcp_layer = pkt.getlayer(TCP)

        try:
            # Extract source port
            features["src_port"] = tcp_layer.sport

            # Extract destination port
            features["dst_port"] = tcp_layer.dport

            # Build TCP flags bitmap
            flags = tcp_layer.flags
            tcp_flags = 0
            tcp_flags |= 0x01 if 'F' in str(flags) else 0  # FIN
            tcp_flags |= 0x02 if 'S' in str(flags) else 0  # SYN
            tcp_flags |= 0x04 if 'R' in str(flags) else 0  # RST
            tcp_flags |= 0x10 if 'A' in str(flags) else 0  # ACK
            features["tcp_flags"] = tcp_flags
        except Exception:
            pass

    # --- Extract UDP features if present ---
    elif pkt.haslayer(UDP):
        # Get UDP layer
        udp_layer = pkt.getlayer(UDP)

        try:
            # Extract source port
            features["src_port"] = udp_layer.sport

            # Extract destination port
            features["dst_port"] = udp_layer.dport
        except Exception:
            pass

    # Return feature dictionary
    return features


def send_to_api(features: dict, server_url: str, timeout: int = 2) -> dict:
    """
    Send features to inference API and get prediction.

    Args:
        features (dict): Feature dictionary
        server_url (str): Base URL of inference server
        timeout (int): Request timeout in seconds

    Returns:
        dict: API response with prediction and confidence
    """
    try:
        # Construct predict endpoint URL
        url = f"{server_url}/predict"

        # Send POST request with JSON payload
        response = requests.post(
            url,
            json=features,  # Features as JSON body
            timeout=timeout  # Timeout to prevent hanging
        )

        # Raise exception for HTTP errors (4xx, 5xx)
        response.raise_for_status()

        # Parse and return JSON response
        return response.json()

    except requests.exceptions.Timeout:
        # Request timed out
        return {"error": "API timeout"}

    except requests.exceptions.ConnectionError:
        # Could not connect to API
        return {"error": "Connection error"}

    except Exception as e:
        # Other error
        return {"error": str(e)}


def print_detection(result: dict, features: dict, alert_threshold: float):
    """
    Print detection result with color coding.

    Args:
        result (dict): API response
        features (dict): Packet features
        alert_threshold (float): Confidence threshold for alerts
    """
    # Get current timestamp
    timestamp = datetime.now().strftime("%H:%M:%S")

    # Extract source and destination
    src = features.get("src_ip", features.get("src", "unknown"))
    dst = features.get("dst_ip", features.get("dst", "unknown"))

    # Check if API returned an error
    if "error" in result:
        print(f"{Colors.YELLOW}[{timestamp}] API Error: {result['error']}{Colors.RESET}")
        return

    # Get prediction label and confidence
    label = result.get("label", "unknown")
    confidence_attack = result.get("confidence_attack", 0.0)
    confidence_normal = result.get("confidence_normal", 0.0)

    # Determine if this is an alert (attack with high confidence)
    is_alert = (label == "attack" and confidence_attack >= alert_threshold)

    # Choose color based on result
    if is_alert:
        # High-confidence attack: RED with ALERT prefix
        color = Colors.RED
        prefix = "[ALERT!]"
        conf_str = f"ATTACK: {confidence_attack:.2f}"
    elif label == "attack":
        # Low-confidence attack: YELLOW with warning
        color = Colors.YELLOW
        prefix = "[WARN ]"
        conf_str = f"Attack: {confidence_attack:.2f}"
    else:
        # Normal traffic: GREEN with OK prefix
        color = Colors.GREEN
        prefix = "[OK   ]"
        conf_str = f"Normal: {confidence_normal:.2f}"

    # Print formatted detection line
    print(f"{color}{prefix} [{timestamp}] {src:15} → {dst:15} ({conf_str}){Colors.RESET}")


def main():
    """Main entry point for live sniffer."""
    # Create argument parser
    parser = argparse.ArgumentParser(
        description="Live packet sniffer for UniFi AP with real-time IDS."
    )

    # Add argument for AP IP address
    parser.add_argument(
        "--ap-ip",
        type=str,
        required=True,
        help="IP address of UniFi U6+ AP"
    )

    # Add argument for AP SSH username
    parser.add_argument(
        "--ap-user",
        type=str,
        default="ubnt",
        help="SSH username for AP (default: ubnt)"
    )

    # Add argument for capture interface
    parser.add_argument(
        "--interface",
        type=str,
        default="br0",
        help="Interface to capture on (default: br0)"
    )

    # Add argument for inference server URL
    parser.add_argument(
        "--server-url",
        type=str,
        default="http://localhost:8000",
        help="Inference server URL (default: http://localhost:8000)"
    )

    # Add argument for alert threshold
    parser.add_argument(
        "--alert-threshold",
        type=float,
        default=0.7,
        help="Confidence threshold for alerts (default: 0.7)"
    )

    # Add argument for packet limit
    parser.add_argument(
        "--limit",
        type=int,
        default=0,
        help="Stop after N packets (0 = unlimited)"
    )

    # Add argument for verbose mode
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Print detailed feature info"
    )

    # Parse arguments
    args = parser.parse_args()

    # Print startup banner
    print("="*70)
    print(" "*20 + "AI-WIDS Live Sniffer")
    print("="*70)
    print(f"AP Address:      {args.ap_ip}")
    print(f"Interface:       {args.interface}")
    print(f"Inference API:   {args.server_url}")
    print(f"Alert Threshold: {args.alert_threshold}")
    print("="*70)

    # Test API connection
    print(f"\n{Colors.BLUE}[*] Testing inference API connection...{Colors.RESET}")
    try:
        # Send health check request
        health_response = requests.get(f"{args.server_url}/health", timeout=5)
        health_data = health_response.json()

        # Check if model is loaded
        if not health_data.get("model_loaded", False):
            print(f"{Colors.RED}[!] Error: Model not loaded on inference server{Colors.RESET}")
            sys.exit(1)

        print(f"{Colors.GREEN}[+] API connection successful{Colors.RESET}")
        print(f"    Model type: {health_data.get('model_type', 'unknown')}")
        print(f"    Device: {health_data.get('device', 'unknown')}")

    except Exception as e:
        print(f"{Colors.RED}[!] Error connecting to API: {e}{Colors.RESET}")
        print(f"{Colors.YELLOW}[!] Make sure inference server is running{Colors.RESET}")
        sys.exit(1)

    # Start SSH capture subprocess
    print(f"\n{Colors.BLUE}[*] Starting packet capture via SSH...{Colors.RESET}")

    # Build SSH command
    # tcpdump options:
    #   -i: interface to capture
    #   -U: unbuffered output (important for piping)
    #   -w -: write to stdout
    ssh_cmd = [
        "ssh",
        f"{args.ap_user}@{args.ap_ip}",
        f"tcpdump -i {args.interface} -U -w -"
    ]

    try:
        # Start SSH subprocess
        # stdout=PIPE: capture stdout for reading
        # stderr=PIPE: capture stderr to suppress tcpdump messages
        proc = subprocess.Popen(
            ssh_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )

        print(f"{Colors.GREEN}[+] Capture started{Colors.RESET}")
        print(f"{Colors.BLUE}[*] Monitoring traffic (Ctrl+C to stop)...{Colors.RESET}")
        print()

        # Create PcapReader from subprocess stdout
        # This reads packets as they're captured
        pcap = PcapReader(proc.stdout)

        # Packet counter
        count = 0

        # Process packets
        for pkt in pcap:
            # Check packet limit
            if args.limit and count >= args.limit:
                print(f"\n{Colors.BLUE}[*] Reached packet limit ({args.limit}){Colors.RESET}")
                break

            # Extract features from packet
            features = extract_features(pkt)

            # Print verbose info if requested
            if args.verbose:
                print(f"\nPacket {count + 1}:")
                for k, v in features.items():
                    print(f"  {k}: {v}")

            # Send to inference API
            result = send_to_api(features, args.server_url)

            # Print detection result
            print_detection(result, features, args.alert_threshold)

            # Increment counter
            count += 1

    except KeyboardInterrupt:
        # User pressed Ctrl+C
        print(f"\n\n{Colors.BLUE}[*] Capture stopped by user{Colors.RESET}")
        print(f"{Colors.BLUE}[*] Total packets processed: {count}{Colors.RESET}")

    except Exception as e:
        # Handle other errors
        print(f"\n{Colors.RED}[!] Error: {e}{Colors.RESET}")

    finally:
        # Clean up subprocess
        try:
            proc.terminate()  # Send SIGTERM
            proc.wait(timeout=5)  # Wait for clean shutdown
        except Exception:
            proc.kill()  # Force kill if needed


# Entry point
if __name__ == "__main__":
    main()
