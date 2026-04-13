# AIWIDS-TEAM-21 — AI-Based Wireless Intrusion Detection System

MSc Project: AI-powered WIDS for detecting Evil Twin and Deauthentication attacks on Wi-Fi networks.

## Detected Attacks

| Attack | Detection Method |
|--------|-----------------|
| Evil Twin | SSID conflict (deterministic) + DNN classifier |
| Deauthentication / DoS | DNN classifier on deauth frame rate features |

## Architecture

```
OpenWrt Router (monitor mode)
  ↓ SSH / tcpdump stream
extract_features.py  →  Features.csv
train_model.py       →  wireless_ids.pt  +  results/
live_detection.py    →  http://localhost:5000 (real-time dashboard)
```

## Quick Start

```bash
# 1. Install dependencies
pip install -r ai-wids-complete/requirements.txt

# 2. Collect traffic (run each script, follow prompts)
cd ai-wids-complete
./scripts/normal_traffic.sh
./scripts/evil_twin.traffic.sh
./scripts/deauth_traffic.sh

# 3. Extract features
python src/extract_features.py

# 4. Train model
python src/train_model.py

# 5. Live detection
python src/live_detection.py
# → open http://localhost:5000
```

## Results

After training, evaluation files are saved to `ai-wids-complete/results/`:

| File | Contents |
|------|----------|
| `classification_report.txt` | Precision / Recall / F1 per class |
| `metrics_summary.txt` | Accuracy, ROC-AUC, CV accuracy |
| `cross_validation.txt` | 5-fold CV fold-by-fold results |
| `training_dashboard.png` | Loss / accuracy curves + confusion matrix |

See [DEMO.md](DEMO.md) for full demo instructions and hardware setup.

## File Structure

```
AIWIDS-TEAM-21/
├── DEMO.md
├── README.md
└── ai-wids-complete/
    ├── requirements.txt
    ├── scripts/
    │   ├── normal_traffic.sh
    │   ├── evil_twin.traffic.sh
    │   └── deauth_traffic.sh
    ├── src/
    │   ├── extract_features.py   # PCAP → Features.csv
    │   ├── train_model.py        # Train DNN, export results
    │   ├── live_detection.py     # Real-time detection + dashboard
    │   └── awid3_to_features.py  # Convert AWID3 dataset
    ├── data/
    │   ├── raw/normal/           # Normal PCAPs
    │   ├── raw/attack/           # Evil Twin PCAPs
    │   ├── raw/deauth/           # Deauth PCAPs
    │   ├── processed/            # Features.csv, Features_sample.csv
    │   └── models/               # wireless_ids.pt
    └── results/                  # Training metrics and plots
```
