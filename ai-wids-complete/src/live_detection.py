#!/usr/bin/env python3  
# Shebang to tell the OS to execute this script using Python 3
"""  # Open module docstring
===============================================================================  # Decorative header for docstring
AI-WIDS LIVE DETECTION - IMPROVED & COMMENTED VERSION  # Title of the script
===============================================================================  # Decorative divider
FIXES APPLIED:  # Section detailing fixes
1. Fixed confidence percentage logic to accurately reflect Normal vs. Evil Twin certainty.  # Explanation of confidence fix
2. Integrated ML predictions properly into the web dashboard display.  # Explanation of dashboard fix
3. Converted HTML block to string concatenation to allow line-by-line Python comments.  # Explanation of formatting fix
===============================================================================  # Decorative footer for docstring
"""  # Close module docstring

# ===========================  # Section header for imports
# IMPORTS  # Label for imports section
# ===========================  # Section footer for imports
import json  # Import json for parsing and formatting JSON data
import time  # Import time for tracking intervals and timestamps
import threading  # Import threading to run the dashboard and packet capture simultaneously
import subprocess  # Import subprocess to execute tcpdump command line utility
from collections import defaultdict, deque  # Import efficient data structures for state tracking
from datetime import datetime  # Import datetime for human-readable alert timestamps

import numpy as np  # Import numpy for numerical array manipulation used in ML features
import torch  # Import PyTorch for running the neural network inference
import torch.nn as nn  # Import PyTorch neural network modules
from scapy.all import Dot11, Dot11Elt, PcapReader  # Import Scapy components for Wi-Fi packet parsing
from flask import Flask, render_template_string  # Import Flask for serving the web dashboard
from flask_socketio import SocketIO  # Import SocketIO for real-time dashboard updates
import colorama  # Import colorama for cross-platform terminal text coloring
from colorama import Fore, Style, Back  # Import specific colorama components for terminal styling

colorama.init(autoreset=True)  # Initialize colorama to automatically reset styles after each print

# ===========================  # Section header for configuration
# CONFIGURATION  # Label for configuration section
# ===========================  # Section footer for configuration
OPENWRT_IP = "192.168.32.55"  # IP address of the OpenWrt router running tcpdump
INTERFACE = "phy0-mon0"  # The wireless interface configured in monitor mode
PRINT_INTERVAL = 2  # How often (in seconds) the dashboard worker processes network stats
ALERT_HISTORY_LIMIT = 50  # Maximum number of recent alerts to keep in memory
NET_HISTORY_LIMIT = 200  # Maximum number of network history records to track

# ===========================  # Section header for OUI database
# EXPANDED MOBILE DEVICE OUI DATABASE  # Label for OUI database
# ===========================  # Section footer for OUI database
MOBILE_OUIS = [  # List containing MAC address prefixes (OUIs) known to belong to mobile devices
    "02:00:00", "06:00:00", "0a:00:00", "0e:00:00",  # Common locally administered MAC ranges
    "12:00:00", "16:00:00", "1a:00:00", "1e:00:00",  # Additional locally administered MAC ranges
    "f6:55:a8", "ee:55:a8", "fa:c6:f7", "fe:55:a8",  # Specific Apple/Android randomized MAC prefixes
    "f2:55:a8", "ea:55:a8", "e6:55:a8", "e2:55:a8",  # More randomized mobile prefixes
    "92:74:fb", "a2:74:fb", "b2:74:fb", "c2:74:fb",  # Additional known mobile hotspot OUIs
    "82:74:fb", "72:74:fb", "62:74:fb", "52:74:fb",  # Continued list of mobile hotspot OUIs
    "34:02:86", "44:4e:1a", "64:a2:f9", "78:f7:be",  # Hardcoded manufacturer OUIs for smartphones
    "ac:5f:3e", "e8:50:8b", "f8:d0:ac",  # Additional smartphone manufacturer OUIs
    "34:80:b3", "50:8f:4c", "74:23:44", "78:02:f8",  # Further smartphone manufacturer OUIs
    "c4:0b:cb", "f8:a4:5f",  # More known smartphone prefixes
    "00:9a:cd", "18:31:bf", "20:47:ed", "54:25:ea",  # Legacy and modern mobile device prefixes
    "a4:d5:78", "c8:85:50",  # Common mobile vendor MACs
    "38:d5:7a", "ac:37:43",  # Additional mobile vendor MACs
    "f4:f5:24", "f8:cf:c5",  # Final set of known mobile OUIs
]  # Close the list of mobile OUIs

# ===========================  # Section header for global state
# GLOBAL STATE  # Label for global state section
# ===========================  # Section footer for global state
class GlobalState:  # Define a class to hold thread-safe global variables
    def __init__(self):  # Initialize the GlobalState instance
        self.ssid_map = defaultdict(set)  # Dictionary mapping an SSID to a set of observed BSSIDs (MACs)
        self.bssid_to_ssid = {}  # Dictionary mapping a BSSID directly back to its SSID
        self.packet_count = defaultdict(int)  # Dictionary tracking the number of packets per (SSID, BSSID) pair
        self.alerts = deque(maxlen=ALERT_HISTORY_LIMIT)  # Double-ended queue storing recent security alerts
        self.network_history = deque(maxlen=NET_HISTORY_LIMIT)  # Double-ended queue for network state snapshots
        self.net_confidence = defaultdict(float)  # Dictionary tracking the highest ML threat probability per SSID
        self.stats = {  # Dictionary holding cumulative statistics for the dashboard
            'total_packets': 0,  # Counter for total processed Wi-Fi packets
            'normal_packets': 0,  # Counter for packets classified as normal
            'evil_twin_packets': 0,  # Counter for packets classified as evil twin
            'alerts_count': 0,  # Counter for the total number of generated alerts
            'mobile_hotspots': 0,  # Counter for detected mobile hotspot packets
            'unique_ssids': 0,  # Counter for the number of unique network names seen
            'unique_bssids': 0,  # Counter for the number of unique access point MACs seen
            'conflict_ssids': 0,  # Counter for SSIDs broadcasting from multiple BSSIDs
        }  # Close the stats dictionary
        self.lock = threading.Lock()  # Mutex lock to prevent race conditions across threads
        self.last_update = time.time()  # Timestamp of the last processed packet

state = GlobalState()  # Instantiate the global state object

# ===========================  # Section header for neural network
# NEURAL NETWORK  # Label for neural network section
# ===========================  # Section footer for neural network
class EvilTwinDetector(nn.Module):  # Define the PyTorch neural network class inheriting from nn.Module
    def __init__(self, input_size):  # Initialize the model layers
        super().__init__()  # Call the parent class constructor
        self.fc1 = nn.Linear(input_size, 128)  # First fully connected layer: input to 128 neurons
        self.fc2 = nn.Linear(128, 64)  # Second fully connected layer: 128 to 64 neurons
        self.fc3 = nn.Linear(64, 32)  # Third fully connected layer: 64 to 32 neurons
        self.fc4 = nn.Linear(32, 2)  # Output layer: 32 to 2 neurons (Normal vs. Evil Twin)
        self.relu = nn.ReLU()  # ReLU activation function for non-linearity
        self.dropout = nn.Dropout(0.3)  # Dropout layer to prevent model overfitting (30% probability)

    def forward(self, x):  # Define the forward pass of the network
        x = self.relu(self.fc1(x))  # Pass input through fc1 and apply ReLU
        x = self.dropout(x)  # Apply dropout to the first layer's output
        x = self.relu(self.fc2(x))  # Pass through fc2 and apply ReLU
        x = self.dropout(x)  # Apply dropout to the second layer's output
        x = self.relu(self.fc3(x))  # Pass through fc3 and apply ReLU
        return self.fc4(x)  # Return the raw logits from the output layer


# ===========================  # Section header for helper functions
# HELPER FUNCTIONS  # Label for helper functions section
# ===========================  # Section footer for helper functions
def is_mobile(bssid):  # Function to determine if a MAC address belongs to a mobile device
    if not bssid or len(bssid) < 8:  # Check if the BSSID is empty or too short to analyze
        return False  # Return False if invalid
    bssid = bssid.lower()  # Convert BSSID to lowercase for consistent matching
    prefix_8 = bssid[:8]  # Extract the first 8 characters (OUI)
    if prefix_8 in MOBILE_OUIS:  # Check if the exact OUI matches the known database
        return True  # Return True if it's a known mobile OUI
    try:  # Start a try block to handle hex conversion errors safely
        first_val = int(bssid[:2], 16)  # Convert the first octet of the MAC to an integer
        if first_val & 0x02:  # Check the U/L bit to see if it's a locally administered (randomized) MAC
            return True  # Return True if it's a randomized MAC (typical for mobile hotspots)
    except Exception:  # Catch any parsing errors
        pass  # Ignore the error and continue checks
    if bssid[1] in ['2', '6', 'a', 'e']:  # Secondary check for locally administered MAC character
        return True  # Return True if the second character indicates local administration
    return False  # Return False if no mobile indicators are found


def is_valid_ssid(ssid):  # Function to filter out junk or empty SSIDs
    if not ssid:  # Check if the SSID string is None or empty
        return False  # Reject empty SSIDs
    if ssid == "UNKNOWN":  # Check if the SSID is the placeholder "UNKNOWN"
        return False  # Reject the "UNKNOWN" placeholder
    if ssid.strip() == "":  # Check if the SSID consists only of whitespace
        return False  # Reject whitespace-only SSIDs
    if all(c == '\x00' for c in ssid):  # Check if the SSID is composed entirely of null bytes
        return False  # Reject null-byte SSIDs
    return True  # Return True if the SSID passes all validity checks


def safe_decode_ssid(raw):  # Function to safely decode raw packet bytes into an SSID string
    if raw is None:  # Check if the raw input is None
        return None  # Return None if no raw data is provided
    try:  # Start a try block to handle decoding errors
        ssid = raw.decode('utf-8', errors='ignore') if isinstance(raw, (bytes, bytearray)) else str(raw)  # Decode bytes to UTF-8, ignoring errors
    except Exception:  # Catch catastrophic decoding failures
        return None  # Return None if decoding completely fails
    ssid = ssid.replace('\x00', '').strip()  # Strip null bytes and whitespace from the edges
    return ssid if is_valid_ssid(ssid) else None  # Return the cleaned SSID if valid, else None


def get_device_name(bssid):  # Function to return a human-readable device category
    if not bssid:  # Check if the BSSID is missing
        return 'UNKNOWN'  # Return 'UNKNOWN' category
    return 'Mobile Hotspot' if is_mobile(bssid) else 'Router/AP'  # Return 'Mobile Hotspot' or 'Router/AP' based on MAC


def extract_features(pkt, deauth_buffer, beacon_buffer):  # Function to extract ML features from a single packet
    features = {}  # Initialize an empty dictionary for the features
    features['frame_length'] = len(bytes(pkt))  # Feature: Calculate the byte length of the packet
    features['frame_type'] = pkt.type if pkt.haslayer(Dot11) else 0  # Feature: Extract 802.11 frame type (Management, Control, Data)
    features['frame_subtype'] = pkt.subtype if pkt.haslayer(Dot11) else 0  # Feature: Extract 802.11 frame subtype (e.g., Beacon, Probe)
    is_beacon = int(pkt.haslayer(Dot11) and pkt.type == 0 and pkt.subtype == 8)  # Boolean check if packet is a Beacon frame
    is_deauth = int(pkt.haslayer(Dot11) and pkt.type == 0 and pkt.subtype == 12)  # Boolean check if packet is a Deauthentication frame
    features['is_mgmt'] = int(pkt.haslayer(Dot11) and pkt.type == 0)  # Feature: 1 if management frame, 0 otherwise
    features['is_beacon'] = is_beacon  # Feature: 1 if beacon, 0 otherwise
    features['is_deauth'] = is_deauth  # Feature: 1 if deauth, 0 otherwise
    ssid = None  # Initialize SSID variable
    bssid = None  # Initialize BSSID variable
    if pkt.haslayer(Dot11):  # Proceed if the packet has an 802.11 layer
        bssid = pkt.addr3 or pkt.addr2  # Extract the BSSID (usually Address 3, fallback to Address 2)
        if is_beacon and pkt.haslayer(Dot11Elt):  # Check if it's a beacon with 802.11 Information Elements
            elt = pkt.getlayer(Dot11Elt)  # Get the first Information Element
            while elt is not None:  # Loop through all Information Elements
                if getattr(elt, 'ID', None) == 0:  # Check if the element ID is 0 (which denotes an SSID element)
                    ssid = safe_decode_ssid(getattr(elt, 'info', None))  # Safely extract and decode the SSID name
                    break  # Stop searching once the SSID is found
                elt = elt.payload.getlayer(Dot11Elt)  # Move to the next Information Element in the payload
    features['ssid'] = ssid if is_valid_ssid(ssid) else None  # Assign valid SSID to features dictionary
    features['bssid'] = bssid  # Assign BSSID to features dictionary
    deauth_buffer.append(is_deauth)  # Append the deauth status to the rolling buffer
    beacon_buffer.append(is_beacon)  # Append the beacon status to the rolling buffer
    features['deauth_rate'] = sum(deauth_buffer) / max(1, len(deauth_buffer)) * 10  # Feature: Calculate recent deauth rate
    features['beacon_rate'] = sum(beacon_buffer) / max(1, len(beacon_buffer)) * 10  # Feature: Calculate recent beacon rate
    return features  # Return the populated features dictionary

# ===========================  # Section header for web dashboard
# WEB DASHBOARD  # Label for web dashboard section
# ===========================  # Section footer for web dashboard
app = Flask(__name__)  # Initialize the Flask web application
app.config['SECRET_KEY'] = 'ai-wids-secret'  # Set the Flask secret key for session security
socketio = SocketIO(app, cors_allowed_origins='*', async_mode='threading')  # Initialize SocketIO for real-time WebSockets

DASHBOARD_HTML = (  # Start defining the HTML template as a concatenated tuple to allow Python comments
    "<!DOCTYPE html>\n"  # Declare the document type as HTML5
    "<html>\n"  # Open the root HTML tag
    "<head>\n"  # Open the head section for metadata
    "    <title>AI-WIDS Live Dashboard</title>\n"  # Set the webpage title
    "    <script src=\"https://cdn.socket.io/4.5.0/socket.io.min.js\"></script>\n"  # Import the Socket.IO client library
    "    <style>\n"  # Open the CSS style block
    "        * { margin: 0; padding: 0; box-sizing: border-box; }\n"  # Reset default margins and padding
    "        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #0a0e27; color: #eee; }\n"  # Set dark theme background and text color
    "        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 20px; text-align: center; }\n"  # Style the header with a purple gradient
    "        .header h1 { font-size: 2em; margin-bottom: 5px; }\n"  # Size the main header title
    "        .status-live { width: 12px; height: 12px; border-radius: 50%; background: #2ed573; display: inline-block; animation: pulse 2s infinite; }\n"  # Create a pulsing green 'live' indicator
    "        @keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.3; } }\n"  # Define the pulse animation keyframes
    "        .container { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; padding: 20px; max-width: 1400px; margin: 0 auto; }\n"  # Use CSS grid for a responsive layout
    "        .card { background: #1a1f3a; border-radius: 10px; padding: 20px; box-shadow: 0 4px 6px rgba(0,0,0,0.5); }\n"  # Style the individual dashboard panels
    "        .card h2 { color: #00d4ff; margin-bottom: 15px; border-bottom: 2px solid #00d4ff; padding-bottom: 10px; }\n"  # Style the card titles with a bottom border
    "        .stat-box { display: flex; justify-content: space-between; padding: 12px; background: #0f1729; border-radius: 5px; margin: 10px 0; }\n"  # Style the statistic rows
    "        .stat-label { color: #aaa; }\n"  # Dim the text color of statistic labels
    "        .stat-value { font-weight: bold; font-size: 1.3em; }\n"  # Emphasize the numerical statistic values
    "        .alert { background: #ff4757; color: white; padding: 15px; border-radius: 5px; margin: 10px 0; }\n"  # Style generic red alerts
    "        .alert-mobile { background: #ffa502; }\n"  # Override alert style for mobile hotspots to orange
    "        #alerts-list { max-height: 400px; overflow-y: auto; }\n"  # Make the alerts list scrollable
    "        table { width: 100%; border-collapse: collapse; }\n"  # Make tables take full width and collapse borders
    "        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #2c3e50; }\n"  # Style table cells with padding and bottom borders
    "        th { background: #0f1729; color: #00d4ff; font-weight: bold; }\n"  # Style table headers
    "        tr:hover { background: #0f1729; }\n"  # Add a hover effect to table rows
    "        .type-evil-twin { color: #ff4757; font-weight: bold; }\n"  # Color class for evil twin text (Red)
    "        .type-mobile { color: #ffa502; font-weight: bold; }\n"  # Color class for mobile text (Orange)
    "        .type-normal { color: #2ed573; }\n"  # Color class for normal network text (Green)
    "        .timestamp { color: #ddd; font-size: 0.85em; }\n"  # Style the timestamp text
    "        .muted { color: #9aa4bf; }\n"  # Define a muted text color class
    "    </style>\n"  # Close the CSS style block
    "</head>\n"  # Close the head section
    "<body>\n"  # Open the body section
    "    <div class=\"header\">\n"  # Open the header container
    "        <h1>🛡️ AI-WIDS Live Dashboard</h1>\n"  # Render the main dashboard title
    "        <p><span class=\"status-live\"></span> Real-time Evil Twin Detection</p>\n"  # Render the subtitle with the live pulsing dot
    "    </div>\n"  # Close the header container
    "    <div class=\"container\">\n"  # Open the main grid container
    "        <div class=\"card\">\n"  # Open the statistics card
    "            <h2>📊 Statistics</h2>\n"  # Render the statistics title
    "            <div class=\"stat-box\"><span class=\"stat-label\">Total Packets</span><span class=\"stat-value\" id=\"total\">0</span></div>\n"  # Row for total packets
    "            <div class=\"stat-box\"><span class=\"stat-label\">Normal</span><span class=\"stat-value\" style=\"color:#2ed573\" id=\"normal\">0</span></div>\n"  # Row for normal packets
    "            <div class=\"stat-box\"><span class=\"stat-label\">Evil Twin</span><span class=\"stat-value\" style=\"color:#ff4757\" id=\"evil\">0</span></div>\n"  # Row for evil twin packets
    "            <div class=\"stat-box\"><span class=\"stat-label\">Mobile Hotspots</span><span class=\"stat-value\" style=\"color:#ffa502\" id=\"mobile\">0</span></div>\n"  # Row for mobile hotspots
    "            <div class=\"stat-box\"><span class=\"stat-label\">Alerts</span><span class=\"stat-value\" style=\"color:#ff6348\" id=\"alerts\">0</span></div>\n"  # Row for alert counts
    "            <div class=\"stat-box\"><span class=\"stat-label\">Conflict SSIDs</span><span class=\"stat-value\" style=\"color:#ff9f43\" id=\"conflicts\">0</span></div>\n"  # Row for conflicting SSIDs
    "        </div>\n"  # Close the statistics card
    "        <div class=\"card\">\n"  # Open the recent alerts card
    "            <h2>🚨 Recent Alerts</h2>\n"  # Render the alerts title
    "            <div id=\"alerts-list\"></div>\n"  # Div container where alerts will be injected dynamically
    "        </div>\n"  # Close the recent alerts card
    "        <div class=\"card\" style=\"grid-column: span 2;\">\n"  # Open the networks table card spanning two columns
    "            <h2>🌐 Detected Networks</h2>\n"  # Render the table title
    "            <table>\n"  # Open the HTML table
    "                <thead>\n"  # Open table headers
    "                    <tr>\n"  # Open header row
    "                        <th>SSID</th>\n"  # Header column for network name
    "                        <th>Packets</th>\n"  # Header column for packet count
    "                        <th>BSSIDs</th>\n"  # Header column for BSSID count
    "                        <th>Type</th>\n"  # Header column for classification type
    "                        <th>Confidence (%)</th>\n"  # Header column for confidence percentage
    "                    </tr>\n"  # Close header row
    "                </thead>\n"  # Close table headers
    "                <tbody id=\"networks\"></tbody>\n"  # Table body where network data will be injected dynamically
    "            </table>\n"  # Close the HTML table
    "        </div>\n"  # Close the networks table card
    "    </div>\n"  # Close the main grid container
    "    <script>\n"  # Open the JavaScript block
    "        const socket = io();\n"  # Initialize the Socket.IO connection
    "        let lastStats = null;\n"  # Variable to cache the last received statistics
    "        let lastNetworks = [];\n"  # Variable to cache the last received network list
    "        let lastAlertCount = 0;\n"  # Variable to track the number of alerts received
    "        let lastRefresh = Date.now();\n"  # Timestamp of the last successful refresh/ping
    "        function renderStats(data) {\n"  # Define JS function to update the DOM with new stats
    "            document.getElementById('total').textContent = data.total_packets ?? 0;\n"  # Update total packets element
    "            document.getElementById('normal').textContent = data.normal_packets ?? 0;\n"  # Update normal packets element
    "            document.getElementById('evil').textContent = data.evil_twin_packets ?? 0;\n"  # Update evil twin packets element
    "            document.getElementById('mobile').textContent = data.mobile_hotspots ?? 0;\n"  # Update mobile hotspots element
    "            document.getElementById('alerts').textContent = data.alerts_count ?? 0;\n"  # Update alerts count element
    "            document.getElementById('conflicts').textContent = data.conflict_ssids ?? 0;\n"  # Update conflicts count element
    "        }\n"  # Close renderStats function
    "        function renderNetworks(data) {\n"  # Define JS function to render the network table
    "            const tbody = document.getElementById('networks');\n"  # Select the table body element
    "            tbody.innerHTML = data.map(net => {\n"  # Map over the incoming network array to create table rows
    "                const baseType = String(net.type || '').split(' ')[0].toLowerCase();\n"  # Extract the base type (e.g., 'evil-twin' from 'EVIL-TWIN (ML)') for CSS classing
    "                return `<tr>\n"  # Open table row literal
    "                    <td>${net.ssid}</td>\n"  # Insert SSID data
    "                    <td>${net.packets}</td>\n"  # Insert packet count data
    "                    <td>${net.bssids}</td>\n"  # Insert BSSID count data
    "                    <td class=\"type-${baseType}\">${net.type}</td>\n"  # Insert formatted Type data with the dynamic CSS class
    "                    <td>${Number(net.confidence || 0).toFixed(1)}%</td>\n"  # Insert parsed and formatted Confidence percentage
    "                </tr>`;\n"  # Close table row literal
    "            }).join('');\n"  # Join array of HTML strings and inject into table body
    "        }\n"  # Close renderNetworks function
    "        function renderAlert(data) {\n"  # Define JS function to render new alerts
    "            const div = document.getElementById('alerts-list');\n"  # Select the alerts list container
    "            const alert = document.createElement('div');\n"  # Create a new div element for the alert
    "            alert.className = data.is_mobile ? 'alert alert-mobile' : 'alert';\n"  # Assign the correct CSS class based on alert type
    "            alert.innerHTML = `<strong>${data.type}</strong><br>SSID: ${data.ssid}<br>BSSID: ${data.bssid}<br><span class=\"timestamp\">${data.time}</span>`;\n"  # Populate the alert content with HTML
    "            div.insertBefore(alert, div.firstChild);\n"  # Insert the new alert at the top of the list
    "            while (div.children.length > 50) div.lastChild.remove();\n"  # Keep only the newest 50 alerts in the DOM to prevent memory bloat
    "        }\n"  # Close renderAlert function
    "        socket.on('connect', () => {\n"  # Listen for the WebSocket connection event
    "            if (lastStats) renderStats(lastStats);\n"  # Re-render stats if they exist in cache upon reconnection
    "            if (lastNetworks.length) renderNetworks(lastNetworks);\n"  # Re-render networks if they exist in cache
    "        });\n"  # Close connect listener
    "        socket.on('stats', (data) => {\n"  # Listen for incoming 'stats' socket events
    "            lastStats = data;\n"  # Cache the received stats
    "            renderStats(data);\n"  # Call render function to update UI
    "        });\n"  # Close stats listener
    "        socket.on('networks', (data) => {\n"  # Listen for incoming 'networks' socket events
    "            lastNetworks = data;\n"  # Cache the received network array
    "            renderNetworks(data);\n"  # Call render function to update the table
    "        });\n"  # Close networks listener
    "        socket.on('alert', (data) => {\n"  # Listen for incoming 'alert' socket events
    "            lastAlertCount += 1;\n"  # Increment local alert counter
    "            renderAlert(data);\n"  # Call render function to display new alert
    "        });\n"  # Close alert listener
    "        setInterval(() => {\n"  # Set an interval to run a keep-alive ping
    "            if (Date.now() - lastRefresh > 15000) {\n"  # Check if no refresh happened in 15 seconds
    "                socket.emit('client_ping', {time: Date.now()});\n"  # Send a ping to the server
    "                lastRefresh = Date.now();\n"  # Update the refresh timestamp
    "            }\n"  # Close if condition
    "        }, 5000);\n"  # Run the interval every 5 seconds
    "    </script>\n"  # Close the JavaScript block
    "</body>\n"  # Close the body section
    "</html>\n"  # Close the HTML document
)  # End of the DASHBOARD_HTML tuple

@app.route('/')  # Define the Flask route for the root URL
def index():  # Function handling the root route
    return render_template_string(DASHBOARD_HTML)  # Render and return the HTML string we defined above


# ===========================  # Section header for auto updates
# DASHBOARD AUTO-UPDATES  # Label for auto updates section
# ===========================  # Section footer for auto updates
def dashboard_worker():  # Define the background worker thread for dashboard updates
    while True:  # Start an infinite loop to periodically send updates
        time.sleep(PRINT_INTERVAL)  # Pause execution for the defined interval
        with state.lock:  # Acquire the thread lock to safely read global state
            networks = []  # Initialize an empty list for the current network snapshot
            conflict_count = 0  # Initialize a counter for SSIDs with conflicts
            for ssid, bssids in state.ssid_map.items():  # Iterate over all known SSIDs and their mapped BSSIDs
                if not ssid:  # Skip if the SSID is somehow empty
                    continue  # Move to the next iteration
                total_pkts = sum(state.packet_count.get((ssid, b), 0) for b in bssids)  # Sum up packets for all BSSIDs under this SSID
                conflict = len(bssids) > 1  # Boolean flag true if multiple MACs broadcast the same SSID
                if conflict:  # Check if a conflict exists
                    conflict_count += 1  # Increment the global conflict counter
                
                # FIX: Implement correct Confidence logic referencing ML state
                evil_prob = float(state.net_confidence.get(ssid, 0.0))  # Retrieve the maximum Evil Twin probability logged for this SSID
                is_ml_evil = evil_prob >= 0.5  # Determine if the ML model classified this as evil (probability >= 50%)
                
                if conflict:  # Determine type: First priority is deterministic MAC conflict
                    net_type = 'EVIL-TWIN (Conflict)'  # Label explicitly as a conflict
                    confidence = 100.0  # Conflict is a 100% deterministic rule
                elif is_ml_evil:  # Second priority is ML Model prediction
                    net_type = 'EVIL-TWIN (ML)'  # Label explicitly as an ML detection
                    confidence = round(evil_prob * 100.0, 1)  # Confidence is exactly the evil probability
                elif any(is_mobile(b) for b in bssids):  # Third priority is mobile hotspot OUI match
                    net_type = 'MOBILE'  # Label as a mobile device
                    confidence = 100.0  # Known OUI is a deterministic rule
                else:  # Fallback: Network appears normal
                    net_type = 'NORMAL'  # Label as normal
                    confidence = round((1.0 - evil_prob) * 100.0, 1)  # Confidence is how sure we are it's NOT evil (1 - evil_prob)
                    
                networks.append({  # Append the calculated network data to the snapshot list
                    'ssid': ssid,  # The network SSID
                    'packets': total_pkts,  # Total associated packets
                    'bssids': len(bssids),  # Number of BSSIDs broadcasting this SSID
                    'type': net_type,  # The resolved network classification
                    'confidence': confidence,  # The resolved percentage confidence
                })  # Close network dictionary
                state.network_history.append({  # Add snapshot to the long-term history deque
                    'time': datetime.now().strftime('%H:%M:%S'),  # Current formatted timestamp
                    'ssid': ssid,  # The network SSID
                    'type': net_type,  # The resolved classification
                    'confidence': confidence,  # The resolved confidence
                    'bssids': len(bssids),  # Number of BSSIDs
                    'packets': total_pkts,  # Total packet count
                })  # Close history dictionary
            networks.sort(key=lambda n: (n['type'] not in ['EVIL-TWIN (Conflict)', 'EVIL-TWIN (ML)'], -n['confidence'], -n['packets']))  # Sort list putting evil twins first, then by confidence and packet volume
            state.stats['unique_ssids'] = len(state.ssid_map)  # Update stat: Total unique SSIDs
            state.stats['unique_bssids'] = len(state.bssid_to_ssid)  # Update stat: Total unique BSSIDs
            state.stats['conflict_ssids'] = conflict_count  # Update stat: Total conflicting SSIDs
            socketio.emit('stats', dict(state.stats))  # Emit the updated stats dictionary via WebSocket
            socketio.emit('networks', networks)  # Emit the updated networks list via WebSocket


def build_alert(alert_type, ssid, bssid, is_mobile_device):  # Function to generate standardized alert payloads
    return {  # Return the constructed alert dictionary
        'type': alert_type,  # The classification of the alert (e.g., ML_DETECTION)
        'ssid': ssid,  # The offending SSID
        'bssid': bssid,  # The offending BSSID
        'is_mobile': is_mobile_device,  # Boolean flag if it's a mobile device
        'time': datetime.now().strftime('%H:%M:%S'),  # Time the alert was generated
    }  # Close alert dictionary


# ===========================  # Section header for main detection loop
# MAIN DETECTION  # Label for main detection section
# ===========================  # Section footer for main detection
def main():  # Define the main application entry point
    print(f"\n{Back.BLUE}{Fore.WHITE} AI-WIDS LIVE DETECTION - IMPROVED VERSION {Style.RESET_ALL}\n")  # Print the stylized application header
    print(f"{Fore.CYAN}[1/3] Loading model...{Style.RESET_ALL}")  # Print status: loading ML model
    checkpoint = torch.load('../data/model/wireless_ids.pt', map_location='cpu')  # Load the saved PyTorch model checkpoint to the CPU
    model = EvilTwinDetector(checkpoint['scaler'].n_features_in_)  # Initialize the model class using input size from the loaded scaler
    model.load_state_dict(checkpoint['model_state_dict'])  # Load the trained weights into the model
    model.eval()  # Set the model to evaluation mode (disables dropout layers)
    scaler = checkpoint['scaler']  # Extract the StandardScaler for data normalization
    feature_order = checkpoint.get('feature_order', list(range(10)))  # Extract the ordered list of features expected by the model
    print(f"  ✓ Loaded\n")  # Print status: loading complete
    print(f"{Fore.CYAN}[2/3] Starting dashboard...{Style.RESET_ALL}")  # Print status: starting web server
    print(f"  ✓ URL: {Fore.GREEN}http://localhost:5000{Style.RESET_ALL}\n")  # Print the local URL for the dashboard
    threading.Thread(target=dashboard_worker, daemon=True).start()  # Launch the dashboard worker in a background daemon thread
    threading.Thread(target=lambda: socketio.run(app, host='0.0.0.0', port=5000, debug=False, use_reloader=False, log_output=False), daemon=True).start()  # Launch Flask/SocketIO server in a background daemon thread
    time.sleep(2)  # Wait 2 seconds for the server and threads to initialize
    print(f"{Fore.CYAN}[3/3] Starting capture...{Style.RESET_ALL}")  # Print status: starting packet capture
    print(f"  ✓ OpenWrt: {Fore.YELLOW}{OPENWRT_IP}{Style.RESET_ALL}")  # Print the target router IP
    print(f"  ✓ Interface: {Fore.YELLOW}{INTERFACE}{Style.RESET_ALL}\n")  # Print the target router interface
    print(f"{Fore.GREEN}📡 Monitoring... (Ctrl+C to stop){Style.RESET_ALL}\n")  # Print final ready status instructions
    deauth_buf = deque(maxlen=20)  # Initialize a rolling buffer for tracking deauth rates
    beacon_buf = deque(maxlen=20)  # Initialize a rolling buffer for tracking beacon rates
    alerts_seen = set()  # Initialize a set to track already-triggered alerts and prevent spam
    cmd = ['ssh', f'root@{OPENWRT_IP}', 'tcpdump', '-i', INTERFACE, '-w', '-', '-s', '0', 'not', 'port', '22']  # Define the SSH/tcpdump command to stream packets
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)  # Execute the command, reading stdout and hiding stderr
    reader = PcapReader(proc.stdout)  # Wrap the stdout stream in Scapy's PcapReader for parsing
    for pkt in reader:  # Iterate over each packet captured from the stream
        if not pkt.haslayer(Dot11):  # Skip the packet if it does not contain an 802.11 Wi-Fi layer
            continue  # Move to the next packet
        features = extract_features(pkt, deauth_buf, beacon_buf)  # Extract ML features into a dictionary
        ssid = features['ssid']  # Retrieve the parsed SSID from features
        bssid = features['bssid']  # Retrieve the parsed BSSID from features
        if not ssid or not bssid:  # Skip if either SSID or BSSID is missing
            continue  # Move to the next packet
        with state.lock:  # Acquire thread lock to safely update global stats
            state.ssid_map[ssid].add(bssid)  # Map the BSSID to the SSID in the global map
            state.bssid_to_ssid[bssid] = ssid  # Map the SSID back to the BSSID
            state.packet_count[(ssid, bssid)] += 1  # Increment the specific packet counter for this pair
            state.stats['total_packets'] += 1  # Increment the global total packet counter
            is_mobile_device = is_mobile(bssid)  # Determine if the BSSID belongs to a mobile device
            if is_mobile_device:  # Check the mobile boolean
                state.stats['mobile_hotspots'] += 1  # Increment the global mobile packet counter
            evil_prob = 0.0  # Initialize evil twin probability to 0
            pred = 0  # Initialize binary prediction to 0 (normal)
            conf = 0.0  # Initialize raw confidence score
            try:  # Start a try block for ML model inference
                x = np.array([features.get(k, 0) for k in feature_order], dtype=float).reshape(1, -1)  # Construct numpy array of features using defined order
                x = scaler.transform(x)  # Normalize the features using the loaded scaler
                with torch.no_grad():  # Disable gradient calculation for faster inference
                    out = model(torch.FloatTensor(x))  # Run the normalized features through the neural network
                    prob = torch.softmax(out, dim=1)  # Apply softmax to get probability distributions
                    evil_prob = float(prob[0][1].item())  # Extract probability of class 1 (Evil Twin)
                    normal_prob = float(prob[0][0].item())  # Extract probability of class 0 (Normal)
                    pred = 1 if evil_prob >= normal_prob else 0  # Predict class 1 if evil prob is higher
                    conf = evil_prob if pred == 1 else normal_prob  # Store the highest probability as raw confidence
            except Exception:  # Catch any inference errors (e.g., missing features)
                pass  # Ignore and leave probabilities at default 0
            state.net_confidence[ssid] = max(state.net_confidence.get(ssid, 0.0), evil_prob)  # Store the highest seen evil probability for this SSID
            conflict = len(state.ssid_map[ssid]) > 1  # Flag if there's a BSSID conflict on this SSID
            if pred == 1 or conflict:  # Check if model predicts evil or a conflict exists
                state.stats['evil_twin_packets'] += 1  # Increment global evil twin packet counter
            else:  # If no evil indicators
                state.stats['normal_packets'] += 1  # Increment global normal packet counter
            key = (ssid, bssid)  # Define a unique tuple key for this specific access point instance
            if key not in alerts_seen:  # Check if we haven't already alerted on this instance
                rules = []  # Initialize an empty list of triggered rules
                if conflict:  # If MAC conflict exists
                    rules.append('SSID_CONFLICT')  # Add conflict rule to list
                if is_mobile_device:  # If identified as mobile
                    rules.append('MOBILE_HOTSPOT')  # Add mobile rule to list
                if pred == 1:  # If ML model predicts evil
                    rules.append('ML_DETECTION')  # Add ML rule to list
                if rules:  # If any rules were triggered
                    alert_msg = ' + '.join(rules)  # Join the rules into a single string message
                    alert = build_alert(alert_msg, ssid, bssid, is_mobile_device)  # Build the alert dictionary payload
                    state.alerts.appendleft(alert)  # Add the alert to the front of the rolling queue
                    state.stats['alerts_count'] += 1  # Increment total alert counter
                    alerts_seen.add(key)  # Mark this specific SSID/BSSID pair as alerted to prevent spam
                    socketio.emit('alert', alert)  # Push the new alert to the web dashboard via WebSocket
                    color = Fore.MAGENTA if is_mobile_device else Fore.RED  # Choose magenta text for mobile, red for evil
                    print(f"{color}🚨 {alert_msg}{Style.RESET_ALL}")  # Print the alert type to the terminal
                    print(f"  SSID: {ssid}")  # Print the offending SSID
                    print(f"  BSSID: {bssid}")  # Print the offending MAC address
                    print(f"  Device: {get_device_name(bssid)}")  # Print the categorized device type
                    print(f"  Confidence: {conf:.3f}\n")  # Print the raw confidence score locally
            state.last_update = time.time()  # Record the timestamp of this successfully processed packet

if __name__ == '__main__':  # Ensure this block only runs if the script is executed directly (not imported)
    try:  # Start the main try block to handle graceful shutdown
        main()  # Call the main application function
    except KeyboardInterrupt:  # Catch a Ctrl+C user interrupt
        print(f"\n{Fore.YELLOW}Stopped{Style.RESET_ALL}\n")  # Safely print a stopped message to the terminal and exit
