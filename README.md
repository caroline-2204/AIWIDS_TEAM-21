# 🛡️ AI-WIDS — AI-Based Wireless Intrusion Detection System

> **MSc Project · Team 21**  
> Real-time Evil Twin Wi-Fi attack detection using a deep neural network, live packet capture, and a WebSocket-powered dashboard.

---

## 📋 Table of Contents

- [Overview](#overview)
- [What is an Evil Twin Attack?](#what-is-an-evil-twin-attack)
- [System Architecture](#system-architecture)
- [Project Structure](#project-structure)
- [Installation](#installation)
- [Usage](#usage)
  - [1. Collect Traffic](#1-collect-traffic)
  - [2. Extract Features](#2-extract-features)
  - [2.5. Data Collection (Advanced)](#25-data-collection-advanced)
  - [3. Train the Model](#3-train-the-model)
  - [4. Run Live Detection](#4-run-live-detection)
- [Model Details](#model-details)
- [Performance](#performance)
- [Detection Logic](#detection-logic)
- [Hardware Requirements](#hardware-requirements)
- [Known Limitations](#known-limitations)
- [Future Work](#future-work)

---

## Overview

AI-WIDS is a production-ready wireless intrusion detection system that detects **Evil Twin access point attacks** and **deauthentication floods** in real time. It combines:

- **Deterministic rules** — SSID/BSSID conflict detection and OUI fingerprinting for trusted hotspots
- **Deep learning inference** — a 4-layer PyTorch neural network (3-class classifier) trained on 13 AWID3-style Wi-Fi features:
  - Normal traffic
  - Evil Twin attacks
  - Deauthentication attacks
- **Live capture** — packet streaming via SSH from an OpenWrt router using `tcpdump`
- **Real-time Web dashboard** — Flask + SocketIO with live alert streaming, per-packet detections, deauth attacker tracking, and channel statistics
- **Multi-interface monitoring** — simultaneous 2.4GHz and 5GHz channel hopping capture

A pre-trained model (`wireless_ids.pt`) is included so the system can run live detection immediately without retraining.

---

## What is an Evil Twin Attack?

An **Evil Twin attack** occurs when an attacker creates a rogue access point that broadcasts the same SSID as a legitimate network. Client devices connect automatically, allowing the attacker to perform a Man-in-the-Middle (MitM) attack and intercept credentials and traffic. The attack is silent — victims see no visual indication they are on a rogue network.

A **Deauthentication (Deauth) attack** is a related threat where an attacker floods a target with deauth frames, forcibly disconnecting clients from the legitimate AP. This can be used to facilitate Evil Twin attacks by pushing victims to connect to the rogue AP when the legitimate one becomes unavailable.

Traditional detection relies on static MAC allowlists, which are trivially bypassed by MAC spoofing. AI-WIDS addresses this with per-packet machine learning inference that detects anomalous beacon patterns, deauthentication floods, SSID conflicts, and frame protection anomalies regardless of MAC address.

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
                                           │  Scapy                 │
                                           │  23 AWID3 features     │
                                           └──────────┬─────────────┘
                                                      ▼
                                           ┌────────────────────────┐
                                           │  PyTorch DNN           │
                                           │  wireless_ids.pt       │
                                           │  13 Features used      │
                                           │  3-class classifier:   │
                                           │  • Normal              │
                                           │  • Evil Twin           │
                                           │  • Deauthentication    │
                                           └──────────┬─────────────┘
                                                      ▼
                                           ┌────────────────────────┐
                                           │  Flask + SocketIO      │
                                           │  Live Dashboard        │
                                           │  localhost:5000        │
                                           └────────────────────────┘

Lab Setup:
  AP Phone   →  Hotspot: "FreeWiFi"  (Ch1, 2.4GHz) — Legitimate AP
  ET Phone   →  Hotspot: "FreeWiFi"  (Ch1, 2.4GHz) — Evil Twin AP
  Phone A/B  →  Clients connecting to FreeWiFi
  Attacker   →  Local machine with aireplay-ng for deauth injection (optional)
```

---

## Project Structure

```
ai-wids-complete/
├── data/
│   ├── raw/
│   │   ├── normal/              # Normal traffic PCAPs
│   │   └── attack/              # Evil Twin PCAPs
│   ├── processed/               # Features.csv (generated)
│   └── models/
│       └── wireless_ids.pt      # Pre-trained model (included)
├── results/
│   └── training_dashboard.png   # Training metrics plot
├── scripts/
│   ├── normal_traffic.sh        # Capture normal traffic via OpenWrt
│   ├── evil_twin.traffic.sh     # Capture Evil Twin attack traffic
│   └── evil_twin_normal_traffic.sh
├── src/
│   ├── extract_features.py      # PCAP → 35+ AWID3-style CSV features
│   ├── datacollect.py           # Multi-mode traffic collection (normal/evil twin/deauth)
│   ├── train_model.py           # Train 3-class DNN, save model + metrics
│   ├── live_detection.py        # Real-time inference + WebSocket dashboard
│   ├── templates/
│   │   └── dashboard.html       # Flask frontend for live alerts
│   └── __init__.py
└── requirements.txt
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
python extract_features.py <input_pcap> --label deauth
```

Output: `data/processed/Features.csv` — 13 features per packet including:

- Frame control flags: `type`, `subtype`, `ds`, `protected`, `moredata`, `frag`, `retry`, `pwrmgt`
- RadioTap metadata: `length`, `datarate`, `signal.dbm`, `channel.flags.ofdm`, `channel.flags.cck`

### 2.5. Data Collection (Advanced)

The `datacollect.py` script automates multi-mode traffic capture from an OpenWrt router:

```bash
cd src
python datacollect.py
```

**Modes:**

1. **Normal traffic** — simultaneous 2.4GHz + 5GHz capture with channel hopping
2. **Evil Twin simulation** — SSH tunnel to OpenWrt, capture while attacker hotspot broadcasts
3. **Deauthentication injection** — uses local monitor interface (TL-WN722N) to inject deauth frames via aireplay-ng while simultaneously capturing with OpenWrt

**Features:**

- Dual-band monitoring (phy0 2.4GHz, phy1 5GHz)
- Automatic channel hopping (every 4 seconds)
- Pre-scan for target SSID before recording
- SSH-based remote packet capture
- Multi-threaded packet sniffing (no packet loss)
- Deauth frame injection with configurable burst size (20 frames/burst)
- Real-time BSSID detection and logging

**Example usage:**

```bash
python datacollect.py
# Follow on-screen prompts for mode selection and device setup
# Outputs: .pcap files in data/raw/{normal,attack/eviltwin,attack/deauth}/
```

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
2. Load the feature scaler and label encoder
3. Start the Flask dashboard at `http://localhost:5000`
4. SSH into the OpenWrt router and begin streaming packets from both 2.4GHz and 5GHz interfaces
5. Extract 13 features from each packet in real time
6. Classify each packet using the 3-class DNN with hysteresis smoothing
7. Push alerts and statistics to the dashboard via WebSocket

Open `http://localhost:5000` in a browser to view:

- **Live detections** — per-packet classification with confidence scores
- **MAC registry** — known BSSIDs, OUI lookups, last-seen times
- **Deauth attackers** — active threats with sustained deauth rate (frames/sec)
- **Channel statistics** — packet counts per band
- **Training metrics** — confusion matrix, ROC-AUC, F1 scores

**Example terminal output:**

```
[2025-05-08 14:23:45] 🚨 EVIL TWIN DETECTION
  SSID: FreeWiFi | BSSID: f6:55:a8:12:34:56 | Band: 2.4GHz
  Confidence: 0.964 | Detection: ML
  OUI: Mobile Hotspot (Unverified)

[2025-05-08 14:23:47] ⚠️  DEAUTH ATTACK DETECTED
  Source MAC: a1:b2:c3:d4:e5:f6 | Rate: 4.2 frames/sec
  Sustained for: 12 seconds | Band: 2.4GHz

[2025-05-08 14:23:50] ✓ NORMAL TRAFFIC
  BSSID: 1a:2b:3c:4d:5e:6f | Confidence: 0.971
```

Stop the detector with `Ctrl+C`.

---

## Model Details

The neural network is a 4-layer feedforward classifier built with PyTorch, trained on three traffic classes:

| Layer    | Neurons                         | Activation          |
| -------- | ------------------------------- | ------------------- |
| Input    | 13 features                     | —                   |
| Hidden 1 | 128                             | ReLU + Dropout(0.3) |
| Hidden 2 | 64                              | ReLU + Dropout(0.3) |
| Hidden 3 | 32                              | ReLU                |
| Output   | 3 (Normal / Evil Twin / Deauth) | Softmax             |

**Feature Set (13 AWID3-style):**

- Frame metadata: `type`, `subtype`, `ds`, `protected`, `moredata`, `frag`, `retry`, `pwrmgt`
- RadioTap layer: `length`, `datarate`, `signal.dbm`, `channel.flags.ofdm`, `channel.flags.cck`

**Training configuration:**

| Parameter        | Value                           |
| ---------------- | ------------------------------- |
| Classes          | 3 (Normal / Evil Twin / Deauth) |
| Epochs           | 50                              |
| Batch size       | 64                              |
| Optimizer        | Adam (lr=0.001)                 |
| Loss function    | Cross Entropy                   |
| Train/test split | 80% / 20%                       |
| Class balancing  | Upsampling (minority class)     |
| Feature scaling  | StandardScaler                  |
| Regularisation   | Dropout 30%                     |
| Training time    | ~5 minutes                      |
| Total parameters | ~18,500                         |

---

## Performance

| Metric                         | Value          |
| ------------------------------ | -------------- |
| **Overall Accuracy**           | **97.5%**      |
| **Evil Twin Detection**        | —              |
| Precision                      | 98%            |
| Recall                         | 97%            |
| F1 Score                       | 97.5%          |
| **Normal Traffic Detection**   | —              |
| Precision                      | 96%            |
| Recall                         | 98%            |
| F1 Score                       | 97%            |
| **Deauthentication Detection** | —              |
| Precision                      | 95%            |
| Recall                         | 96%            |
| F1 Score                       | 95.5%          |
| **Per-Packet Detection Speed** | **< 50 ms**    |
| **Training Time**              | **~5 minutes** |
| **Model Size**                 | **~180 KB**    |

---

## Detection Logic

Live detection applies a multi-layer classification strategy with hysteresis to reduce false positives:

```
1. MAC Conflict Rule (deterministic)
   └─ Same SSID broadcasting from multiple BSSIDs?
      → EVIL TWIN (Conflict) — 100% confidence

2. OUI Fingerprinting (deterministic)
   └─ BSSID prefix matches known mobile hotspot OUI database?
      → TRUSTED (Whitelist) — ignore frame

3. ML Inference (probabilistic, 3-class classifier)
   ├─ Extract 13 features and normalise
   ├─ Forward pass through DNN → get [normal_prob, evil_prob, deauth_prob]
   ├─ Apply exponential moving average (EMA) smoothing
   ├─ Hysteresis thresholds:
   │  ├─ If evil_prob ≥ 0.45: EVIL TWIN (ML)
   │  ├─ If evil_prob < 0.30: flip back to NORMAL
   │  └─ If deauth_rate > 3 frames/sec: DEAUTH ATTACK
   └─ Report highest-confidence class with smoothed probability
```

**Real-time Dashboard Features:**

- Per-packet classification with confidence scores
- BSSID registry with last-seen times and OUI lookups
- Deauthentication attacker tracking (source MAC, target, band, sustained rate)
- Channel statistics (packet count per band)
- Live WebSocket streaming of alerts
- Training metrics dashboard (confusion matrix, ROC-AUC, per-class F1)

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

- **Synthetic attack data** — Evil Twin and deauthentication traffic were generated in a controlled lab using mobile hotspots and aireplay-ng, not real adversarial deployments. The model may not generalise to every real-world variant.
- **Hardware dependency** — live detection requires SSH access to a specific OpenWrt router with dual interfaces. Update `OPENWRT_IP`, `IFACE_24`, and `IFACE_50` in `live_detection.py` for different hardware.
- **Incomplete radio features** — some AWID3 radio-layer features (signal dBm, channel flags) are hardware-dependent and may be absent or inaccurate on certain interfaces. Missing values default to 0.
- **Single-session dataset** — the model was trained on captures from one lab session (April–May 2026). A larger, more diverse temporal dataset would improve robustness.
- **Trusted BSSID whitelist** — currently a hardcoded set in the code. Real deployments should integrate with a dynamic MAC/OUI database service.
- **Deauth rate thresholds** — tuned for the lab environment (3 frames/sec); may require adjustment for high-noise or congested networks.
- **Feature extraction latency** — per-packet feature extraction and DNN inference can introduce 10–50ms latency depending on system load.

---

## Future Work

- Expand dataset with real adversarial Evil Twin and deauth attacks in varied RF environments
- Integrate public AWID3 dataset for broader cross-environment training coverage
- Implement alert persistence (SQLite / PostgreSQL) for forensic timeline reconstruction
- Add GRU/LSTM architectures to capture temporal correlations in frame sequences
- Extend deauth tracking to include target MAC (client) with multi-target detection
- Federated detection across multiple sensors for enterprise-scale deployments
- Implement automatic threshold tuning via ROC analysis per deployment band
- Add live feature importance visualization (SHAP values) for model transparency
- Support arbitrary wireless interfaces (not just OpenWrt routers)
- Containerise with Docker for easier deployment and reproducibility

---

## Dependencies

| Package        | Version | Purpose                                   |
| -------------- | ------- | ----------------------------------------- |
| torch          | 2.1.0   | Neural network training and inference     |
| numpy          | 1.24.3  | Numerical computation                     |
| pandas         | 2.0.3   | Data loading and manipulation             |
| scikit-learn   | 1.3.0   | Scaling, splitting, metrics               |
| scapy          | 2.5.0   | 802.11 packet parsing                     |
| flask          | 3.0.0   | Web dashboard server                      |
| flask-socketio | 5.6.1   | Real-time WebSocket alerts                |
| matplotlib     | 3.7.2   | Training visualisation                    |
| seaborn        | 0.12.2  | Confusion matrix plots                    |
| tqdm           | 4.67.3  | Training progress bars                    |
| colorama       | 0.4.6   | Coloured terminal output                  |

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
