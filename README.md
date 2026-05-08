# 🛡️ AI-WIDS — AI-Based Wireless Intrusion Detection System

> **MSc Project · Team 21**  
> Real-time Evil Twin Wi-Fi attack detection using a deep neural network, live packet capture, and a WebSocket-powered dashboard.

---

## 📋 Table of Contents

- [Overview](#overview)
- [What is an Evil Twin Attack?](#what-is-an-evil-twin-attack)
- [Deauthentication Attacks](#deauthentication-attacks)
- [System Architecture](#system-architecture)
- [Project Structure](#project-structure)
- [Installation](#installation)
- [Usage](#usage)
  - [1. Collect Traffic](#1-collect-traffic)
  - [2. Extract Features](#2-extract-features)
  - [3. Train the Model](#3-train-the-model)
  - [4. Run Live Detection](#4-run-live-detection)
- [Evil Twin Attack Setup Guide](#evil-twin-attack-setup-guide)
- [Quick Deployment](#quick-deployment)
- [Feature Set](#feature-set-awid3-style--evil-twin)
- [Model Details](#model-details)
- [Performance](#performance)
- [Detection Logic](#detection-logic)
- [Hardware Requirements](#hardware-requirements)
- [Known Limitations](#known-limitations)
- [Future Work](#future-work)

---

## Overview

AI-WIDS is a production-ready wireless intrusion detection system that detects **Evil Twin access point attacks** and **deauthentication attacks** in real time. It combines:

- **Deterministic rules** — SSID/BSSID conflict detection, OUI fingerprinting, and deauth frame analysis
- **Deep learning inference** — a 4-layer PyTorch neural network trained on 13 core AWID3-style Wi-Fi features (extracted from 23 raw packet attributes)
- **Live capture** — packet streaming via SSH from an OpenWrt router using `tcpdump`
- **Web dashboard** — Flask + SocketIO real-time alert interface

A pre-trained model (`wireless_ids.pt`) is included so the system can run live detection immediately without retraining.

---

## What is an Evil Twin Attack?

An Evil Twin attack occurs when an attacker creates a rogue access point that broadcasts the same SSID as a legitimate network. Client devices connect automatically, allowing the attacker to perform a Man-in-the-Middle (MitM) attack and intercept credentials and traffic. The attack is silent — victims see no visual indication they are on a rogue network.

Traditional detection relies on static MAC allowlists, which are trivially bypassed by MAC spoofing. AI-WIDS addresses this with per-packet machine learning inference that detects anomalous beacon patterns, deauthentication floods, and SSID conflicts regardless of MAC address.

---

## Deauthentication Attacks

A **Deauthentication (Deauth) attack** is a denial-of-service attack where an attacker floods legitimate wireless clients and access points with deauthentication frames, forcing them to disconnect from the network. This attack is often used as a precursor to Evil Twin attacks, as it causes clients to reconnect and can redirect them to a rogue AP.

### How Deauth Attacks Work

1. **Attacker sends spoofed frames** — Deauth frames are sent with spoofed source MAC addresses (from either the AP or legitimate clients)
2. **Clients disconnect** — Upon receiving a deauth frame, clients disconnect from the legitimate network
3. **Forced reconnection** — Clients search for available networks and may connect to an Evil Twin if present
4. **Credential harvesting** — If an Evil Twin is active, the reconnecting client may provide credentials to the rogue AP

### Deauth Frame Details

**802.11 Management Frame:**

- **Frame Type:** Management (0x00)
- **Subtype:** Deauthentication (0x0C)
- **Reason Code** — Specifies the disconnection reason (common values: 1, 2, 3, 5, 8, 15)
- **Source Address** — Spoofed to appear from AP or client
- **Destination Address** — Broadcast (ff:ff:ff:ff:ff:ff) or unicast

### AI-WIDS Deauth Detection

The system detects deauth attacks by:

1. **Frame counting** — Monitoring the frequency of deauth frames over time windows
   - Normal: ~0-2 deauth frames per 5-second window
   - Attack: 10+ deauth frames per 5-second window

2. **Anomaly scoring** — Flagging unusual deauth patterns:
   - Rapid bursts from single source
   - Broadcast deauth floods
   - Deauth targeting multiple clients simultaneously

3. **ML feature integration** — The DNN incorporates:
   - `deauth_rate` — Rate of deauth frames in sliding window
   - `wlan.reason` — Deauth reason codes (extracted features)
   - `wlan.fc.subtype` — Frame subtype to identify management frames

### Dataset Collection

Deauthentication attack PCAPs are captured and stored in `data/raw/attack/deauth/`. To generate deauth traffic:

```bash
cd scripts
./inject_deauth.sh
```

This script uses tools like `aireplay-ng` or custom packet injection to flood target APs/clients with deauth frames while capturing the traffic via OpenWrt's monitor interface.

### Expected Deauth Patterns

| Pattern                           | Characteristics                        | Detection                                          |
| --------------------------------- | -------------------------------------- | -------------------------------------------------- |
| **Normal**                        | 0-2 deauth/5s                          | Reason codes 3, 8 (legitimate disconnection)       |
| **Flood Attack**                  | 20+ deauth/5s                          | Rapid bursts, spoofed MACs, broadcast targets      |
| **Targeted Deauth**               | 10-15 deauth/5s                        | Specific client targets, high reason code variance |
| **Combined (Deauth + Evil Twin)** | Deauth followed by conflicting beacons | Temporal correlation with SSID conflicts           |

---

## System Architecture

```
┌─────────────────────┐     SSH/tcpdump      ┌──────────────────────┐
│  Ubiquiti U6+       │ ──────────────────►  │  Linux Mint Server   │
│  OpenWrt Router     │                      │  192.168.32.10       │
│  192.168.32.55      │                      │  PCAP storage        │
│  phy0-mon0 (2.4GHz) │                      └──────────┬───────────┘
│  phy1-mon0 (5GHz)   │                                 │
└─────────────────────┘                                 ▼
                                           ┌────────────────────────┐
                                           │  Feature Extractor     │
                                           │  Scapy + RadioTap      │
                                           │  23 raw → 13 core      │
                                           └──────────┬─────────────┘
                                                      ▼
                                           ┌────────────────────────┐
                                           │  PyTorch DNN           │
                                           │  wireless_ids.pt       │
                                           │  Normal/Evil/Deauth    │
                                           └──────────┬─────────────┘
                                                      ▼
                                           ┌────────────────────────┐
                                           │  Flask + SocketIO      │
                                           │  Live Dashboard        │
                                           │  localhost:5000        │
                                           └────────────────────────┘
```

**Network Setup:**

```
U6+ OpenWrt Router (192.168.32.55)
  ↓ br-lan (monitor mode)
Linux Mint Server (192.168.32.10)
  ├── data/raw/normal/*.pcap
  ├── data/raw/attack/eviltwin/*.pcap
  ├── data/raw/attack/deauth/*.pcap
  ├── data/processed/Features.csv
  └── data/models/wireless_ids.pt
```

**Lab Setup:**

- **AP Phone** → Hotspot: "FreeWiFi" (Ch1, 2.4GHz) — Legitimate AP
- **ET Phone** → Hotspot: "FreeWiFi" (Ch1, 2.4GHz) — Evil Twin AP
- **Phone A/B** → Clients connecting to FreeWiFi

---

## Project Structure

```
ai-wids-complete/
├── data/
│   ├── raw/
│   │   ├── normal/                          # Normal traffic PCAPs
│   │   ├── attack/
│   │   │   ├── eviltwin/                    # Evil Twin attack PCAPs
│   │   │   └── deauth/                      # Deauthentication attack PCAPs
│   │   └── old/                             # Legacy captures
│   ├── processed/
│   │   └── Features.csv                     # Generated features dataset
│   └── models/
│       └── wireless_ids.pt                  # Pre-trained model (included)
├── results/
│   ├── training_dashboard.png               # Training metrics visualization
│   └── system_diagram.jpg
├── scripts/
│   ├── normal_traffic.sh                    # Capture normal traffic via OpenWrt
│   ├── evil_twin.traffic.sh                 # Capture Evil Twin attack traffic
│   ├── evil_twin_normal_traffic.sh
│   ├── inject_deauth.sh                     # Deauth injection script
│   └── normal_traffic.sh
├── src/
│   ├── extract_features.py                  # PCAP → AWID3-style CSV features
│   ├── train_model.py                       # Train the DNN, save model
│   ├── live_detection.py                    # Real-time inference + Flask dashboard
│   ├── datacollect.py                       # Automated data collection
│   ├── utils/
│   │   └── __init__.py
│   └── socket.io.min.js                     # WebSocket library
├── notebooks/
│   └── test.ipynb                           # Jupyter notebook for testing
├── logs/                                    # Training/detection logs
├── requirements.txt                         # Python dependencies
└── README.md
```

---

## Installation

### Prerequisites

- Python 3.9+
- An OpenWrt-capable router with `tcpdump` installed (for live detection)
- SSH access to the router from the capture server

### 1. Clone the repository

```bash
git clone https://github.com/your-org/AIWIDS_TEAM-21.git
cd AIWIDS_TEAM-21/ai-wids-complete
```

### 2. Install Python dependencies

```bash
pip install -r requirements.txt
```

### 3. Install tcpdump on the OpenWrt router

```bash
ssh root@192.168.32.55 "opkg update && opkg install tcpdump"
```

### 4. Enable monitor mode on the router interface

```bash
ssh root@192.168.32.55 "iw dev phy0-mon0 set monitor none"
```

---

## Usage

### 1. Collect Traffic

Run the capture scripts from the `scripts/` directory. Each script SSHs into the OpenWrt router and streams packets back via `tcpdump`.

**Normal traffic (5 minutes per capture, 2.4GHz + 5GHz):**

```bash
cd scripts
chmod +x normal_traffic.sh
./normal_traffic.sh
```

The script pauses between captures for you to set up the test devices. Follow the on-screen prompts. Output: `data/raw/normal/*.pcap`

**Evil Twin attack traffic:**

```bash
chmod +x evil_twin.traffic.sh
./evil_twin.traffic.sh
```

Before running, set up the lab:

1. **AP Phone** — enable a hotspot named `FreeWiFi` on Channel 1 (2.4GHz)
2. **ET Phone** — enable a hotspot named `FreeWiFi` on Channel 1 (2.4GHz)
3. **Phone A/B** — connect to the `FreeWiFi` network and browse normally

Output: `data/raw/attack/*.pcap`

---

### 2. Extract Features

Convert raw PCAPs to the AWID3-style feature CSV used for training:

```bash
cd src
python extract_features.py <input_pcap> --label normal
python extract_features.py <input_pcap> --label evil_twin
```

Output: `data/processed/Features.csv` — 35+ features per packet including frame type, beacon rate, deauth rate, SSID conflict flags, protocol metadata, and OUI information.

---

### 3. Train the Model

```bash
cd src
python train_model.py
```

This will:

- Load `data/processed/Features.csv`
- Balance the dataset via minority class upsampling
- Normalise features with `StandardScaler`
- Train a 4-layer feedforward neural network for 50 epochs
- Save the model to `data/models/wireless_ids.pt`
- Save a training dashboard PNG to `results/training_dashboard.png`

> **Note:** A pre-trained model is already included at `data/models/wireless_ids.pt`. You only need to retrain if you collect new data.

Expected output:

```
Epoch 01: Loss 0.4821 | Train Acc 89.34% | Val Acc 88.12%
...
Epoch 50: Loss 0.0234 | Train Acc 97.52% | Val Acc 97.48%
✓ Model saved: ../data/models/wireless_ids.pt
```

---

### 4. Run Live Detection

```bash
cd src
python live_detection.py
```

This will:

1. Load the trained model from `data/models/wireless_ids.pt`
2. Start the Flask dashboard at `http://localhost:5000`
3. SSH into the OpenWrt router and begin streaming packets
4. Classify each packet in real time and push alerts to the dashboard

Open `http://localhost:5000` in a browser to view live detections.

**Example terminal output:**

```
🚨 ML_DETECTION + SSID_CONFLICT
  SSID: FreeWiFi
  BSSID: f6:55:a8:12:34:56
  Device: Mobile Hotspot
  Confidence: 0.982

[NORMAL]     Conf: 0.971 | Deauth: 0 | Beacon: 1
[EVIL TWIN]  Conf: 0.964 | Deauth: 1 | Beacon: 0
```

---

## Evil Twin Attack Setup Guide

This section details how to configure your test lab to generate Evil Twin attack traffic.

### Legitimate AP (AP Phone)

- **Hotspot Name:** `FreeWiFi`
- **Channel:** 1 (2.4GHz)
- **Clients:** Phone A and/or Phone B connect and browse normally
- **Keep running** during both capture windows

### Evil Twin AP (ET Phone)

- **Hotspot Name:** `FreeWiFi` (exactly the same SSID)
- **Channel:** 1 (2.4GHz)
- **Clients:** Phone A and/or Phone B will alternate between APs
- **Enable just before Evil Twin capture window**

### Capture Router (U6+ OpenWrt, 192.168.32.55)

- **Monitor Interface:** `br-lan` in monitor mode
- **tcpdump command:** Streams 802.11 beacon, data, and deauth frames
- **SSH Server:** 192.168.32.10 (Linux Mint) receives packets via SSH tunnel
- **Duration:** ~5-10 minutes per capture, depending on traffic volume

### Traffic Pattern

| Phase        | Legitimate AP | Evil Twin AP | Clients            | Capture                           | Notes                                    |
| ------------ | ------------- | ------------ | ------------------ | --------------------------------- | ---------------------------------------- |
| 1. Normal    | ✓ On          | ✗ Off        | Browse             | `data/raw/normal/*.pcap`          | Baseline traffic, no attacks             |
| 2. Evil Twin | ✓ On          | ✓ On         | Browse + Switching | `data/raw/attack/eviltwin/*.pcap` | Conflicting beacons from multiple BSSIDs |
| 3. Deauth    | ✓ On          | ✗ Off        | Disconnecting      | `data/raw/attack/deauth/*.pcap`   | High-frequency deauth frame floods       |

The DNN learns to distinguish between:

- **Normal:** Single AP beacon, normal client associations, minimal deauth frames
- **Evil Twin:** Conflicting beacons from multiple BSSIDs with same SSID
- **Deauth Attack:** High-frequency deauthentication frames causing client disconnections

---

## Quick Deployment

For rapid setup and testing, execute the full pipeline in sequence:

```bash
# 1. Setup OpenWrt router (one-time)
ssh root@192.168.32.55 "opkg update && opkg install tcpdump"

# 2. Setup lab devices
# - AP Phone: Enable "FreeWiFi" hotspot on Channel 1 (2.4GHz)
# - ET Phone: Enable "FreeWiFi" hotspot on Channel 1 (2.4GHz)
# - Phone A/B: Connect to FreeWiFi and browse normally

# 3. Collect traffic data
cd scripts
./normal_traffic.sh              # Follow prompts for 5-10 minutes
./evil_twin.traffic.sh           # Follow prompts for 5-10 minutes

# 4. Extract features and train model
cd ../src
python extract_features.py \
  --normal-dir ../data/raw/normal \
  --evil-twin-dir ../data/raw/attack/eviltwin \
  --deauth-dir ../data/raw/attack/deauth \
  --output ../data/processed/Features.csv \
  --target-ssid FreeWiFi

python train_model.py

# 5. Run live detection
python live_detection.py
# Open http://localhost:5000 in browser
```

---

## Feature Set (AWID3-Style + Evil Twin)

The `extract_features.py` script extracts **23 raw features** and one derived feature per packet from PCAP files using **Scapy** (packet parsing) and **RadioTap headers** (hardware metadata). However, only **13 features** are used for training and inference after removing data-leakage columns.

### Raw Extraction (23 Features)

**802.11 Frame Control Features (8 features):**

- `wlan.fc.type` — Frame type: 0=management, 1=control, 2=data
- `wlan.fc.subtype` — Subtype within frame type (0–15); 12 = Deauthentication
- `wlan.fc.ds` — To/From Distribution System bits (0–3)
- `wlan.fc.protected` — Protected Frame flag (WEP/WPA encryption): 0 or 1
- `wlan.fc.moredata` — More Data buffered at AP: 0 or 1
- `wlan.fc.frag` — More Fragments flag: 0 or 1
- `wlan.fc.retry` — Retry (retransmission) flag: 0 or 1
- `wlan.fc.pwrmgt` — Power Management flag (client sleep state): 0 or 1

**MAC Addresses (3 features) — Encoded as 48-bit integers:**

- `wlan.sa` — Source Address (addr3 in Dot11 layer): integer representation of MAC
- `wlan.ta` — Transmitter Address (addr2): may differ from source due to bridging
- `wlan.ra` — Receiver Address (addr1): frame destination

**Sequencing & Destination (2 features):**

- `wlan.seq` — Sequence number (0–4095 from SC field): detects replay/retransmission
- `wlan.da` — Destination Address
- `wlan.da_is_broadcast` — Broadcast flag: 1 if addr1 = ff:ff:ff:ff:ff:ff (deauth floods use broadcast)

**RadioTap Physical Layer (7 features):**

- `radiotap.length` — RadioTap header length (typically 18–36 bytes)
- `radiotap.datarate` — Data rate (0.5 Mbps units): 1, 2, 5.5, 11, 6, 9, 12, 18, 24, 36, 48, 54 Mbps
- `radiotap.timestamp.ts` — Kernel timestamp (microseconds) — **EXCLUDED FOR TRAINING** (temporal leakage)
- `radiotap.mactime` — MAC hardware timestamp — **EXCLUDED FOR TRAINING** (temporal leakage)
- `wlan_radio.signal_dbm` — RSSI signal strength (dBm): typical range -30 to -90
- `radiotap.channel.flags.ofdm` — OFDM modulation (802.11a/g): 0 or 1
- `radiotap.channel.flags.cck` — CCK modulation (802.11b): 0 or 1

**Attack-Specific (2 features):**

- `wlan.reason` — Deauth/Disassoc reason code (0–46): 0 for non-deauth frames
- `frame.len` — Total frame length (bytes): 26 for deauth, 100–1500 for data — **EXCLUDED FOR TRAINING** (device identity leakage)
- ``

### Training Features (13 Features)

After removing columns that cause **data leakage** (timestamps encode capture time; frame.len encodes device identity), the model uses:

| #   | Feature Name                  | Range      | Significance                                                        |
| --- | ----------------------------- | ---------- | ------------------------------------------------------------------- |
| 1   | `wlan.fc.type`                | 0–2        | Frame category (mgmt/control/data)                                  |
| 2   | `wlan.fc.subtype`             | 0–15       | Frame subtype; 12 = deauth                                          |
| 3   | `wlan.fc.ds`                  | 0–3        | AP vs. client indicator                                             |
| 4   | `wlan.fc.protected`           | 0–1        | **Evil Twin signal**: legitimate APs encrypt; rogue APs often don't |
| 5   | `wlan.fc.moredata`            | 0–1        | AP buffered data for client                                         |
| 6   | `wlan.fc.frag`                | 0–1        | Frame fragmentation flag                                            |
| 7   | `wlan.fc.retry`               | 0–1        | Retransmission (link quality indicator)                             |
| 8   | `wlan.fc.pwrmgt`              | 0–1        | Client power state                                                  |
| 9   | `radiotap.length`             | 18–36      | Header metadata completeness                                        |
| 10  | `radiotap.datarate`           | 1–54 Mbps  | **Evil Twin signal**: rogue APs use anomalous rates                 |
| 11  | `radiotap.signal.dbm`         | -30 to -90 | **Evil Twin signal**: weaker signal than legitimate AP              |
| 12  | `radiotap.channel.flags.ofdm` | 0–1        | Frequency band (802.11a/g)                                          |
| 13  | `radiotap.channel.flags.cck`  | 0–1        | Frequency band (802.11b)                                            |

### Feature Processing Pipeline

```
1. Packet Capture          → Live stream via tcpdump or PCAP file
2. Scapy Parsing          → Extract Dot11 + RadioTap layers
3. Feature Encoding       → MAC → 48-bit int; flags → 0/1
4. Feature Aggregation    → Compute temporal rates over sliding windows
5. StandardScaler         → Normalise each feature to mean=0, std=1 (fitted on training data only)
6. DNN Input              → 13-dim tensor for inference
```

### CSV Output Format (extract_features.py)

Each row in `Features.csv` contains:

```
wlan_fc.type, wlan_fc.subtype, wlan_sa, wlan_ta, wlan_ra, wlan_seq,
wlan_fc.ds, wlan_fc.protected, wlan_fc.moredata, wlan_fc.frag,
wlan_fc.retry, wlan_fc.pwrmgt, radiotap.length, radiotap.datarate,
radiotap.timestamp.ts, radiotap.mactime, wlan_radio.signal_dbm,
radiotap.channel.flags.ofdm, radiotap.channel.flags.cck, frame.len,
wlan.reason, wlan.da_is_broadcast, label
```

**Labels:**

- `label = 0` → Normal/trusted traffic
- `label = 1` → Evil Twin attack (same SSID, different BSSID)
- `label = 2` → Deauthentication attack (wlan.fc.subtype == 12)

### Real-World Examples

**Normal Beacon Frame:**

```
Type: 0 (management)  |  Subtype: 8 (beacon)  |  Protected: 1 (WPA encrypted)
Signal: -45 dBm       |  Rate: 24 Mbps        |  Broadcast: 0 (unicast)
```

**Evil Twin Beacon (Conflicting BSSID):**

```
Type: 0 (management)  |  Subtype: 8 (beacon)  |  Protected: 0 (NO encryption)
Signal: -65 dBm       |  Rate: 6 Mbps (lower)|  BSSID: aa:bb:cc:dd:ee:02 (different!)
```

**Deauth Flood Frame:**

```
Type: 0 (management)  |  Subtype: 12 (deauth)     |  Reason: 2 (spoofed)
Protected: 0          |  Broadcast: 1 (ff:ff...)  |  Rate: 1 Mbps
```

---

## Model Details

The neural network is a 4-layer feedforward classifier built with PyTorch that processes these **13 features**:

| Layer    | Neurons | Activation          |
| -------- | ------- | ------------------- |
| Input    | 13      | —                   |
| Hidden 1 | 128     | ReLU + Dropout(0.3) |
| Hidden 2 | 64      | ReLU + Dropout(0.3) |
| Hidden 3 | 32      | ReLU                |
| Output   | 3       | Softmax             |

**Training configuration:**

| Parameter        | Value                       |
| ---------------- | --------------------------- |
| Epochs           | 50                          |
| Batch size       | 64                          |
| Optimizer        | Adam (lr=0.001)             |
| Loss function    | Cross Entropy               |
| Train/test split | 80% / 20%                   |
| Class balancing  | Upsampling (minority class) |
| Feature scaling  | StandardScaler              |
| Regularisation   | Dropout 30%                 |
| Training time    | ~5 minutes                  |
| Total parameters | ~17,000                     |

---

## Performance

| Metric                          | Value          |
| ------------------------------- | -------------- |
| Overall Accuracy (3-class)      | **97.5%**      |
| Normal Classification Precision | **99%**        |
| Evil Twin Precision             | **98%**        |
| Deauth Attack Recall            | **96%**        |
| Macro F1 Score                  | **97.2%**      |
| Per-Packet Detection Speed      | **< 50 ms**    |
| Training Time (50 epochs)       | **~5 minutes** |

**Class-wise breakdown:**

- **Normal traffic:** High precision (99%) — minimal false positives
- **Evil Twin attacks:** High precision (98%) and recall (97%) — reliable detection
- **Deauth attacks:** High recall (96%) — catches most flood events

---

## Detection Logic

Live detection applies four layers in priority order:

```
1. MAC Conflict Rule (deterministic)
   └─ Same SSID broadcasting from multiple BSSIDs?
      → EVIL TWIN (Conflict) — 100% confidence

2. Deauth Flood Detection (deterministic)
   └─ Deauth frame rate > threshold (e.g., 10/5s)?
      → DEAUTH ATTACK (Flood) — 100% confidence
      → Potential precursor to Evil Twin attack

3. OUI Fingerprinting (deterministic)
   └─ BSSID prefix matches known mobile hotspot OUI database?
      → MOBILE — 100% confidence

4. ML Inference (probabilistic)
   └─ Normalise 35+ features → DNN forward pass → softmax
      └─ Features include deauth_rate, beacon_rate, anomalies
      → If evil_prob ≥ 0.5: EVIL TWIN (ML)
      → Confidence = evil_prob × 100%
```

**Detection Priorities:**

- High-confidence deterministic rules are evaluated first to avoid ML false positives
- Deauth floods are flagged immediately to alert operators to potential coordinated attacks
- Combined detections (deauth + SSID conflict) indicate a sophisticated Evil Twin attack in progress

---

## Hardware Requirements

| Component         | Specification                                           |
| ----------------- | ------------------------------------------------------- |
| Capture Router    | Ubiquiti UniFi U6+ running OpenWrt                      |
| Router Interfaces | `phy0-mon0` (2.4GHz), `phy1-mon0` (5GHz) — monitor mode |
| Capture Server    | Linux Mint / Ubuntu                                     |
| Router IP         | 192.168.32.55 (configurable in `live_detection.py`)     |
| SSH Access        | Passwordless SSH from server to router                  |
| Python            | 3.9+                                                    |
| RAM               | 2GB minimum for training                                |

---

## Known Limitations

- **Synthetic attack data** — Evil Twin and deauth traffic were generated in a controlled lab using mobile hotspots and packet injection tools, not real adversarial deployments. The model may not generalise to every real-world variant.
- **Deauth threshold tuning** — The deauth flood detection threshold (currently 10 frames/5s) may require adjustment for different network environments (high-traffic venues vs. quiet offices).
- **Hardware dependency** — live detection requires SSH access to a specific OpenWrt router. Update `OPENWRT_IP` and `INTERFACE` in `live_detection.py` for different hardware.
- **Incomplete radio features** — some AWID3 radio-layer features (signal dBm, radiotap timestamps) are hardware-dependent and may be absent on certain interfaces.
- **Single-session dataset** — the model was trained on captures from one lab session. A larger, more diverse dataset would improve robustness against deauth variants and region-specific attack patterns.
- **Deauth reason code ambiguity** — Legitimate disconnections use similar reason codes (3, 8) as spoofed attacks; temporal clustering and rate analysis help distinguish them.

---

## Future Work

- Validate against real adversarial Evil Twin and deauth deployments in varied environments
- Implement adaptive deauth thresholds based on network baseline traffic analysis
- Incorporate the public AWID3 dataset for broader training coverage
- Abstract the hardware dependency to support any monitor-mode wireless interface
- Explore CNN/LSTM architectures to capture temporal packet sequence patterns and deauth burst signatures
- Federated detection across multiple sensors for enterprise-scale deployments
- Add support for detecting other Wi-Fi attacks: WPS brute force, key recovery, fragmentation attacks

---

## Dependencies

| Package        | Version | Purpose                               |
| -------------- | ------- | ------------------------------------- |
| torch          | 2.1.0   | Neural network training and inference |
| numpy          | 1.24.3  | Numerical computation                 |
| pandas         | 2.0.3   | Data loading and manipulation         |
| scikit-learn   | 1.3.0   | Scaling, splitting, metrics           |
| scapy          | 2.5.0   | 802.11 packet parsing                 |
| flask          | 3.0.0   | Web dashboard server                  |
| flask-socketio | 5.6.1   | Real-time WebSocket alerts            |
| matplotlib     | 3.7.2   | Training visualisation                |
| seaborn        | 0.12.2  | Confusion matrix plots                |
| tqdm           | 4.67.3  | Training progress bars                |
| colorama       | 0.4.6   | Coloured terminal output              |

Install all with:

```bash
pip install -r requirements.txt
```

---

## Acknowledgements

- [AWID3 Dataset](https://icsdweb.aegean.gr/awid/awid3) — feature set reference
- [Scapy](https://scapy.net/) — packet parsing
- [PyTorch](https://pytorch.org/) — deep learning framework
- [Flask-SocketIO](https://flask-socketio.readthedocs.io/) — real-time dashboard

---

_MSc Project — Team 21_
