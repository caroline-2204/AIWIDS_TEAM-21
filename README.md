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

AI-WIDS is a production-ready wireless intrusion detection system that detects **Evil Twin access point attacks** in real time. It combines:

- **Deterministic rules** — SSID/BSSID conflict detection and OUI fingerprinting
- **Deep learning inference** — a 4-layer PyTorch neural network trained on 35+ AWID3-style Wi-Fi features
- **Live capture** — packet streaming via SSH from an OpenWrt router using `tcpdump`
- **Web dashboard** — Flask + SocketIO real-time alert interface

A pre-trained model (`wireless_ids.pt`) is included so the system can run live detection immediately without retraining.

---

## What is an Evil Twin Attack?

An Evil Twin attack occurs when an attacker creates a rogue access point that broadcasts the same SSID as a legitimate network. Client devices connect automatically, allowing the attacker to perform a Man-in-the-Middle (MitM) attack and intercept credentials and traffic. The attack is silent — victims see no visual indication they are on a rogue network.

Traditional detection relies on static MAC allowlists, which are trivially bypassed by MAC spoofing. AI-WIDS addresses this with per-packet machine learning inference that detects anomalous beacon patterns, deauthentication floods, and SSID conflicts regardless of MAC address.

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
                                           │  Scapy + PyShark       │
                                           │  35+ AWID3 features    │
                                           └──────────┬─────────────┘
                                                      ▼
                                           ┌────────────────────────┐
                                           │  PyTorch DNN           │
                                           │  wireless_ids.pt       │
                                           │  Normal / Evil Twin    │
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
│   ├── extract_features.py      # PCAP → AWID3-style CSV features
│   ├── awid3_to_features.py     # AWID3 dataset converter (tshark-based)
│   ├── train_model.py           # Train the DNN, save model + dashboard
│   ├── live_detection.py        # Real-time inference + Flask dashboard
│   └── utils/
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

Stop the detector with `Ctrl+C`.

---

## Model Details

The neural network is a 4-layer feedforward classifier built with PyTorch:

| Layer | Neurons | Activation |
|-------|---------|------------|
| Input | 35+ features | — |
| Hidden 1 | 128 | ReLU + Dropout(0.3) |
| Hidden 2 | 64 | ReLU + Dropout(0.3) |
| Hidden 3 | 32 | ReLU |
| Output | 2 (Normal / Evil Twin) | Softmax |

**Training configuration:**

| Parameter | Value |
|-----------|-------|
| Epochs | 50 |
| Batch size | 64 |
| Optimizer | Adam (lr=0.001) |
| Loss function | Cross Entropy |
| Train/test split | 80% / 20% |
| Class balancing | Upsampling (minority class) |
| Feature scaling | StandardScaler |
| Regularisation | Dropout 30% |
| Training time | ~5 minutes |
| Total parameters | ~17,000 |

---

## Performance

| Metric | Value |
|--------|-------|
| Overall Accuracy | **97.5%** |
| Evil Twin Precision | **98%** |
| Evil Twin Recall | **97%** |
| F1 Score (Evil Twin) | **97.5%** |
| Per-Packet Detection Speed | **< 50 ms** |
| Training Time | **~5 minutes** |

---

## Detection Logic

Live detection applies three layers in priority order:

```
1. MAC Conflict Rule (deterministic)
   └─ Same SSID broadcasting from multiple BSSIDs?
      → EVIL TWIN (Conflict) — 100% confidence

2. OUI Fingerprinting (deterministic)
   └─ BSSID prefix matches known mobile hotspot OUI database?
      → MOBILE — 100% confidence

3. ML Inference (probabilistic)
   └─ Normalise features → DNN forward pass → softmax
      → If evil_prob ≥ 0.5: EVIL TWIN (ML)
      → Confidence = evil_prob × 100%
```

---

## Hardware Requirements

| Component | Specification |
|-----------|--------------|
| Capture Router | Ubiquiti UniFi U6+ running OpenWrt |
| Router Interfaces | `phy0-mon0` (2.4GHz), `phy1-mon0` (5GHz) — monitor mode |
| Capture Server | Linux Mint / Ubuntu |
| Router IP | 192.168.32.55 (configurable in `live_detection.py`) |
| SSH Access | Passwordless SSH from server to router |
| Python | 3.9+ |
| RAM | 2GB minimum for training |

---

## Known Limitations

- **Synthetic attack data** — Evil Twin traffic was generated in a controlled lab using mobile hotspots, not real adversarial deployments. The model may not generalise to every real-world variant.
- **Hardware dependency** — live detection requires SSH access to a specific OpenWrt router. Update `OPENWRT_IP` and `INTERFACE` in `live_detection.py` for different hardware.
- **Incomplete radio features** — some AWID3 radio-layer features (signal dBm, radiotap timestamps) are hardware-dependent and may be absent on certain interfaces.
- **Single-session dataset** — the model was trained on captures from one lab session. A larger, more diverse dataset would improve robustness.

---

## Future Work

- Validate against real adversarial Evil Twin deployments in varied environments
- Incorporate the public AWID3 dataset for broader training coverage
- Abstract the hardware dependency to support any monitor-mode wireless interface
- Explore CNN/LSTM architectures to capture temporal packet sequence patterns
- Federated detection across multiple sensors for enterprise-scale deployments

---

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| torch | 2.1.0 | Neural network training and inference |
| numpy | 1.24.3 | Numerical computation |
| pandas | 2.0.3 | Data loading and manipulation |
| scikit-learn | 1.3.0 | Scaling, splitting, metrics |
| scapy | 2.5.0 | 802.11 packet parsing |
| pyshark | 0.6 | AWID3-style feature extraction via tshark |
| flask | 3.0.0 | Web dashboard server |
| flask-socketio | 5.6.1 | Real-time WebSocket alerts |
| matplotlib | 3.7.2 | Training visualisation |
| seaborn | 0.12.2 | Confusion matrix plots |
| tqdm | 4.67.3 | Training progress bars |
| colorama | 0.4.6 | Coloured terminal output |

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

*MSc Project — Team 21*
