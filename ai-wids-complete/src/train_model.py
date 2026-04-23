#!/usr/bin/env python3
"""
train_model.py — AI-WIDS Threat Detection (Evil Twin + Deauth)
Reads Features.csv produced by extract_features.py and trains a Deep Neural
Network to classify Wi-Fi packets as:
    0 = normal/trusted
    1 = evil twin
    2 = deauth attack

Execution (always run from the project root, not from inside src/):
    python make_test_data.py
    python src/train_model.py --data_dir data/processed --sample 2000 --epochs 10
    #once feature extraction added
    python src/train_model.py --data_dir data/processed --epochs 50

    python src/train_model.py                          # full training run
    python src/train_model.py --sample 2000 --epochs 10  # quick test

Output:
    data/model/wireless_ids.pt     ← trained model (loaded by live_detection.py)
    data/model/scaler.pkl          ← feature scaler
    data/model/label_encoder.pkl   ← label encoder
    data/model/plots/training_dashboard.png

Features.csv is produced by extract_features.py and contains these columns:

    Column name              What it is
    ─────────────────────    ─────────────────────────────────────────────────
    wlan_fc.type             Frame type: 0=management, 1=control, 2=data
    wlan_fc.subtype          Subtype within the frame type (0–15)
                             Key deauth signal: subtype=12 (0x0C)
    wlan_fc.ds               To/From Distribution System bits
    wlan_fc.protected        Protected Frame flag — strongest evil twin signal
    wlan_fc.moredata         More Data flag
    wlan_fc.frag             More Fragments flag
    wlan_fc.retry            Retry flag — 1 if retransmission
    wlan_fc.pwrmgt           Power Management flag
    radiotap.length          RadioTap header length
    radiotap.datarate        Data rate in 0.5Mbps units
    radiotap.timestamp.ts    RadioTap timestamp
    radiotap.mactime         MAC timestamp from RadioTap
    radiotap.signal.dbm      Signal strength in dBm
    radiotap.channel.flags.ofdm  1 if OFDM channel
    radiotap.channel.flags.cck   1 if CCK channel
    frame.len                Total frame length in bytes
    label                    0 = normal/trusted, 1 = evil twin, 2 = deauth attack
"""

# IMPORTS
import os                                    # File and folder operations
import argparse                              # Command-line argument parsing
import time                                  # Measuring training duration
import warnings
warnings.filterwarnings("ignore")            # Suppress noisy warnings

import numpy as np                           # Numerical array operations
import pandas as pd                          # CSV loading and DataFrame operations
import torch                                 # PyTorch deep learning framework
import torch.nn as nn                        # Neural network layer definitions
import torch.optim as optim                  # Optimisers (Adam etc.)
from torch.utils.data import (
    DataLoader, TensorDataset, WeightedRandomSampler
)
from sklearn.model_selection import train_test_split   # Split into train/val/test
from sklearn.preprocessing import StandardScaler       # Normalise features (mean=0, std=1)
from sklearn.preprocessing import LabelEncoder         # Encode labels as integers
from sklearn.preprocessing import label_binarize       # One-vs-rest binarisation for multi-class ROC-AUC
from sklearn.metrics import (
    classification_report,                   # Per-class precision/recall/F1
    confusion_matrix,                        # True/false positive breakdown
    roc_auc_score,                           # Area under ROC curve
    f1_score                                 # Macro F1 score
)
import joblib                                # Save scaler/encoder objects to disk
import matplotlib
matplotlib.use("Agg")                        # Non-interactive backend — saves to file
import matplotlib.pyplot as plt
import seaborn as sns

# Optional colour output
try:
    from colorama import Fore, Style, Back, init as colorama_init
    colorama_init(autoreset=True)
    RED = Fore.RED;    GRN = Fore.GREEN;   CYN = Fore.CYAN
    YLW = Fore.YELLOW; MAG = Fore.MAGENTA; RST = Style.RESET_ALL
    WHT = Fore.WHITE;  BAK = Back.MAGENTA
except ImportError:
    RED = GRN = CYN = YLW = MAG = RST = WHT = BAK = ""

# Optional progress bar
try:
    from tqdm import tqdm
    HAS_TQDM = True
except ImportError:
    HAS_TQDM = False
    class tqdm:                              # Minimal shim so code never crashes
        def __init__(self, iterable=None, **kw): self._it = iterable
        def __iter__(self): return iter(self._it)
        @staticmethod
        def write(s): print(s)


# FILE PATHS
# Always use the folder this script lives in as the anchor point so paths
# work no matter which directory you run the script from.
BASE_DIR     = os.path.dirname(os.path.abspath(__file__))   # .../src/
PROJECT_ROOT = os.path.dirname(BASE_DIR)                    # .../ai-wids-complete/

# All outputs land in data/model/ inside the project root
MODEL_DIR    = os.path.join(PROJECT_ROOT, "data", "model")
PLOT_DIR     = os.path.join(MODEL_DIR, "plots")
MODEL_PATH   = os.path.join(MODEL_DIR, "wireless_ids.pt")   # Main model output
SCALER_PATH  = os.path.join(MODEL_DIR, "scaler.pkl")
ENCODE_PATH  = os.path.join(MODEL_DIR, "label_encoder.pkl")

# Default CSV location — where extract_features.py writes Features.csv
DEFAULT_DATA_DIR = os.path.join(PROJECT_ROOT, "data", "processed")

# Create output folders now so saves never fail mid-training
os.makedirs(MODEL_DIR, exist_ok=True)
os.makedirs(PLOT_DIR,  exist_ok=True)


# FEATURE CONFIGURATION
# These are the EXACT column names that extract_features.py writes to
# Features.csv. If extract_features.py changes its column names, update
# this list to match — nothing else in this file needs changing.
FEATURE_COLS = [
    "wlan_fc.type",               # Frame type: 0=management, 1=control, 2=data
    "wlan_fc.subtype",            # Subtype within the type category (0–15)
    "wlan_fc.ds",                 # To/From DS bits — indicates infrastructure mode
    "wlan_fc.protected",          # Protected Frame flag — STRONGEST evil twin signal
                                  #   Legitimate APs encrypt frames; evil twins often don't
    "wlan_fc.moredata",           # More Data flag — AP has buffered frames for client
    "wlan_fc.frag",               # More Fragments flag — 1 if frame is fragmented
    "wlan_fc.retry",              # Retry flag — 1 if this is a retransmission
    "wlan_fc.pwrmgt",             # Power Management — client sleeping or awake
    "radiotap.length",            # RadioTap header length in bytes
    "radiotap.datarate",          # Transmission data rate (0.5 Mbps units)
    # radiotap.timestamp.ts and radiotap.mactime intentionally excluded:
    # they encode absolute capture time and perfectly separate classes recorded
    # at different times — this is temporal data leakage, not a real signal.
    "radiotap.signal.dbm",        # Received signal strength in dBm (e.g. -65)
    "radiotap.channel.flags.ofdm",# 1 if the channel uses OFDM modulation
    "radiotap.channel.flags.cck", # 1 if the channel uses CCK modulation
    # frame.len excluded: evil twin device always produces 392-byte beacons while
    # legitimate AP averages 270 bytes — model learns device identity, not attack.
    # Re-include only after collecting evil twin data from multiple devices/positions.
]

# Label column — matches what extract_features.py writes
LABEL_COL    = "label"
LABEL_NORMAL = 0                  # extract_features.py writes 0 for normal/trusted
LABEL_ATTACK = 1                  # extract_features.py writes 1 for evil twin
LABEL_DEAUTH = 2                  # extract_features.py writes 2 for deauth attack
                                  #   Key frame marker: wlan_fc.type=0, wlan_fc.subtype=12
N_CLASSES    = 3                  # normal / evil twin / deauth

N_FEATURES   = len(FEATURE_COLS)  # 13 (timestamps + frame.len removed to prevent leakage)


# NEURAL NETWORK ARCHITECTURE
class WirelessIDS(nn.Module):
    """
    4-layer Feedforward Deep Neural Network for Wi-Fi threat detection.

    Architecture:  13 → 128 → 64 → 32 → 3
                   ReLU activations + Dropout(0.3) regularisation

    Classes:
        0 = normal / trusted AP
        1 = evil twin attack
        2 = deauth attack (wlan_fc.type=0, wlan_fc.subtype=12)

    Why this design:
    - 4 layers learn non-linear combinations of the 13 input features
    - Width decreases each layer (128→64→32) to progressively compress
      the feature space down to a 3-class decision
    - Dropout randomly disables 30% of neurons during training to
      prevent memorising the training data (overfitting)
    - Output is 3 raw logits; CrossEntropyLoss applies softmax internally
    """

    def __init__(self, input_size: int = 13, num_classes: int = N_CLASSES,
                 dropout_p: float = 0.3):
        """
        Args:
            input_size  : number of input features (13 after removing timestamp leakage)
            num_classes : number of output classes (3: normal / evil twin / deauth)
            dropout_p   : fraction of neurons randomly disabled per pass (0.3 = 30%)
        """
        super().__init__()

        # Fully connected layers — each Linear(in, out) learns a weight matrix
        self.fc1 = nn.Linear(input_size, 128)      # 13 features → 128 neurons
        self.fc2 = nn.Linear(128, 64)              # 128 neurons → 64 neurons
        self.fc3 = nn.Linear(64, 32)               # 64 neurons  → 32 neurons
        self.fc4 = nn.Linear(32, num_classes)      # 32 neurons  → 3 outputs
                                                   #   output[0] = score for class 0 (normal)
                                                   #   output[1] = score for class 1 (evil twin)
                                                   #   output[2] = score for class 2 (deauth)

        self.relu    = nn.ReLU()                 # ReLU: max(0, x) — adds non-linearity
        self.dropout = nn.Dropout(p=dropout_p)   # Zeros random neurons during training

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        """Forward pass — data flows through all 4 layers."""
        x = self.relu(self.fc1(x));  x = self.dropout(x)   # Layer 1 + regularisation
        x = self.relu(self.fc2(x));  x = self.dropout(x)   # Layer 2 + regularisation
        x = self.relu(self.fc3(x));  x = self.dropout(x)   # Layer 3 + regularisation
        return self.fc4(x)   # Layer 4 — raw logits, NO softmax here


# DATA LOADING
def find_csvs(data_dir: str) -> list:
    """Find all CSV files in data_dir (including subdirectories)."""
    found = []
    for root, _, files in os.walk(data_dir):
        for f in files:
            if f.lower().endswith(".csv"):
                found.append(os.path.join(root, f))
    return sorted(found)


def load_features(data_dir: str, sample_n: int = 0):
    """
    Load Features.csv produced by extract_features.py.

    What this function does:
      1. Finds all CSV files in data_dir
      2. Reads and merges them into one DataFrame
      3. Filters to only normal (0) and evil twin (1) rows
      4. Fills any missing feature columns with 0
      5. Replaces NaN values with the column median
      6. Optionally subsamples for quick testing

    Args:
        data_dir : path to data/processed/ folder
        sample_n : rows to subsample for testing (0 = use all rows)

    Returns:
        X  : float32 numpy array shape (N, 16) — feature matrix
        y  : integer numpy array shape (N,)    — labels (0 or 1)
        le : fitted LabelEncoder
    """

    # Find CSV files
    csvs = find_csvs(data_dir)
    if not csvs:
        raise FileNotFoundError(
            f"\nNo CSV files found in '{data_dir}'.\n"
            f"Run extract_features.py first:\n"
            f"  python src/extract_features.py\n"
            f"This reads data/raw/normal/ and data/raw/attack/ PCAPs\n"
            f"and writes data/processed/Features.csv\n"
        )

    print(f"{CYN}[*] Found {len(csvs)} CSV file(s) in: {data_dir}")

    # Read and merge all CSV files
    frames = []
    for path in csvs:
        try:
            df = pd.read_csv(path, low_memory=False)
            # AWID3 source files use '?' for missing values — replace with NaN
            df.replace("?", np.nan, inplace=True)
            frames.append(df)
            print(f"    ✓  {os.path.basename(path):45s} {len(df):>10,} rows")
        except Exception as e:
            print(f"{YLW}    !  Skipped {os.path.basename(path)}: {e}")

    if not frames:
        raise ValueError("All CSV files failed to load.")

    df = pd.concat(frames, ignore_index=True)
    print(f"\n    Total loaded : {len(df):,} rows")

    # Check label column exists
    if LABEL_COL not in df.columns:
        raise ValueError(
            f"Column '{LABEL_COL}' not found in CSV.\n"
            f"Columns found: {list(df.columns)[:20]}\n"
            f"Check that extract_features.py adds a 'label' column."
        )

    # Coerce label to integer (handles both int and float CSVs)
    # pandas sometimes reads integer columns as float (e.g. 0.0 instead of 0)
    df[LABEL_COL] = pd.to_numeric(df[LABEL_COL], errors="coerce")
    df[LABEL_COL] = df[LABEL_COL].dropna().astype(int)

    # Filter to 3 classes: 0 (normal), 1 (evil twin), 2 (deauth)
    df = df[df[LABEL_COL].isin([LABEL_NORMAL, LABEL_ATTACK, LABEL_DEAUTH])].copy()
    print(f"    After label filter  : {len(df):,} rows")

    if len(df) == 0:
        actual = pd.concat(frames)[LABEL_COL].dropna().unique()[:10]
        raise ValueError(
            f"No rows matched label 0 (normal), 1 (evil twin), or 2 (deauth).\n"
            f"Labels found in your CSV: {list(actual)}\n"
            f"Check the label column in extract_features.py.\n"
            f"  normal rows  → label=0\n"
            f"  evil twin    → label=1\n"
            f"  deauth       → label=2  (wlan_fc.type=0, wlan_fc.subtype=12)"
        )

    # Class distribution
    dist = df[LABEL_COL].value_counts().sort_index()
    label_names = {0: "normal", 1: "evil_twin", 2: "deauth"}
    print(f"\n{CYN}[*] Class distribution:")
    for lbl, cnt in dist.items():
        name = label_names.get(lbl, str(lbl))
        print(f"    {name:25s} (label={lbl}): {cnt:10,}  ({100*cnt/len(df):.1f}%)")

    # Feature leakage diagnostic — print per-class mean for each feature
    # Any feature with near-zero overlap between classes is a leakage candidate
    print(f"\n{CYN}[*] Feature means by class (leakage check):")
    print(f"    {'Feature':<35s} {'normal(0)':>12} {'evil_twin(1)':>14} {'ratio':>8}")
    print(f"    {'-'*72}")
    for col in FEATURE_COLS:
        if col not in df.columns:
            continue
        m0 = df.loc[df[LABEL_COL] == 0, col].mean()
        m1 = df.loc[df[LABEL_COL] == 1, col].mean()
        ratio = abs(m1 - m0) / (abs(m0) + 1e-9)
        flag = "  <-- SUSPECT" if ratio > 0.5 else ""
        print(f"    {col:<35s} {m0:>12.4f} {m1:>14.4f} {ratio:>8.3f}{flag}")

    # Handle missing feature columns
    # If extract_features.py didn't produce a column, fill with 0
    missing = [c for c in FEATURE_COLS if c not in df.columns]
    if missing:
        print(f"\n{YLW}[!] Missing feature columns (filling with 0): {missing}")
        print(f"    Check extract_features.py produces all 16 columns.")
    for col in missing:
        df[col] = 0.0

    # Coerce all feature columns to numeric, fill NaN with column median ─
    for col in FEATURE_COLS:
        df[col] = pd.to_numeric(df[col], errors="coerce")
    df[FEATURE_COLS] = df[FEATURE_COLS].fillna(df[FEATURE_COLS].median())

    # Optional subsample for quick testing
    if sample_n > 0 and len(df) > sample_n:
        per_class = sample_n // 2
        parts = []
        for lbl in [LABEL_NORMAL, LABEL_ATTACK]:
            subset = df[df[LABEL_COL] == lbl]
            parts.append(subset.sample(min(len(subset), per_class), random_state=42))
        df = pd.concat(parts).sample(frac=1, random_state=42).reset_index(drop=True)
        print(f"\n    Subsampled to {len(df):,} rows (--sample {sample_n})")

    # Build feature matrix X and label vector y
    X  = df[FEATURE_COLS].values.astype(np.float32)   # Shape: (N, 16)
    le = LabelEncoder()
    y  = le.fit_transform(df[LABEL_COL].values)        # 0 stays 0, 1 stays 1

    print(f"\n    Label map : {dict(zip(le.classes_, le.transform(le.classes_)))}")
    print(f"    X shape   : {X.shape}")
    return X, y, le


# DATALOADER CREATION
def make_loaders(X_tr, y_tr, X_va, y_va, batch_size: int, balance: bool):
    """
    Wrap numpy arrays in PyTorch DataLoaders for training.

    When balance=True, uses WeightedRandomSampler so each training batch
    sees roughly equal numbers of normal and evil twin samples.
    This is important because real captures will have far more normal
    traffic than evil twin traffic.

    Args:
        X_tr, y_tr : training features and labels
        X_va, y_va : validation features and labels
        batch_size : samples per batch (default 64)
        balance    : whether to apply class balancing

    Returns:
        tr_loader : training DataLoader (balanced/shuffled)
        va_loader : validation DataLoader (unshuffled, real distribution)
    """
    Xtr = torch.tensor(X_tr, dtype=torch.float32)
    ytr = torch.tensor(y_tr, dtype=torch.long)
    Xva = torch.tensor(X_va, dtype=torch.float32)
    yva = torch.tensor(y_va, dtype=torch.long)

    if balance:
        # Give minority class higher weight so it appears as often as majority
        counts  = np.bincount(y_tr)           # [n_class0, n_class1]
        weights = 1.0 / counts[y_tr]          # inverse-frequency per sample
        sampler = WeightedRandomSampler(
            torch.tensor(weights, dtype=torch.float32),
            num_samples=len(y_tr),
            replacement=True
        )
        tr_loader = DataLoader(TensorDataset(Xtr, ytr),
                               batch_size=batch_size, sampler=sampler)
    else:
        tr_loader = DataLoader(TensorDataset(Xtr, ytr),
                               batch_size=batch_size, shuffle=True)

    va_loader = DataLoader(TensorDataset(Xva, yva),
                           batch_size=batch_size, shuffle=False)
    return tr_loader, va_loader


# TRAINING AND EVALUATION
def train_epoch(model, loader, criterion, optimizer, device):
    """
    One full pass over all training batches.

    Per batch:
      1. Move data to device (GPU or CPU)
      2. Zero gradients from the previous batch
      3. Forward pass — get predictions
      4. Compute CrossEntropy loss
      5. Backward pass — compute gradients
      6. Optimiser step — update weights

    Returns average loss and accuracy for this epoch.
    """
    model.train()                                # Enables dropout
    loss_sum = correct = total = 0

    for Xb, yb in loader:
        Xb, yb = Xb.to(device), yb.to(device)
        optimizer.zero_grad()                   # Clear last batch's gradients
        out  = model(Xb)                        # Forward pass
        loss = criterion(out, yb)               # Compute loss
        loss.backward()                         # Compute gradients
        optimizer.step()                        # Update weights

        loss_sum += loss.item() * len(yb)
        correct  += (out.argmax(1) == yb).sum().item()
        total    += len(yb)

    return loss_sum / total, correct / total


@torch.no_grad()                                # Disables gradient computation
def eval_epoch(model, loader, criterion, device):
    """
    Evaluate the model on validation or test data.

    @torch.no_grad() ensures weights are never updated here —
    it also saves memory by not building the computation graph.

    Returns loss, accuracy, all predictions, and all true labels.
    """
    model.eval()                                # Disables dropout
    loss_sum = correct = total = 0
    all_preds, all_labels = [], []

    for Xb, yb in loader:
        Xb, yb = Xb.to(device), yb.to(device)
        out  = model(Xb)
        loss = criterion(out, yb)

        loss_sum += loss.item() * len(yb)
        correct  += (out.argmax(1) == yb).sum().item()
        total    += len(yb)
        all_preds.append(out.argmax(1).cpu().numpy())
        all_labels.append(yb.cpu().numpy())

    return (loss_sum / total, correct / total,
            np.concatenate(all_preds), np.concatenate(all_labels))


# SAVE MODEL
def save_checkpoint(model, scaler, le, feature_cols):
    """
    Save everything live_detection.py needs into one .pt file.

    wireless_ids.pt contains:
      - model weights     (state_dict)
      - StandardScaler    (so live packets are scaled the same way as training)
      - LabelEncoder      (so integer predictions → class names)
      - feature list      (so live_detection uses the same 16 columns in order)
    """
    torch.save({
        "model_state_dict": model.state_dict(),
        "scaler":           scaler,
        "label_encoder":    le,
        "features":         feature_cols,
    }, MODEL_PATH)

    joblib.dump(scaler, SCALER_PATH)
    joblib.dump(le,     ENCODE_PATH)

    print(f"{GRN}    [✓] Model   → {MODEL_PATH}")
    print(f"{GRN}    [✓] Scaler  → {SCALER_PATH}")
    print(f"{GRN}    [✓] Encoder → {ENCODE_PATH}")


# TRAINING DASHBOARD PLOT
def plot_dashboard(history, y_test, test_preds, class_names):
    """
    Generate a 2×2 visualisation dashboard and save as PNG.

    Panels:
      [0,0] Training and validation loss over epochs
      [0,1] Training and validation accuracy over epochs
      [1,0] Confusion matrix on the held-out test set
      [1,1] Training summary statistics text box
    """
    plt.style.use("seaborn-v0_8-darkgrid")
    fig, axes = plt.subplots(2, 2, figsize=(15, 10))

    # Loss curve
    axes[0, 0].plot(history["tr_loss"], label="Train Loss",
                    color="#FF6B6B", linewidth=2)
    axes[0, 0].plot(history["va_loss"], label="Val Loss",
                    color="#FF9999", linewidth=2, linestyle="--")
    axes[0, 0].set_title("Loss Over Time", fontsize=14, fontweight="bold")
    axes[0, 0].set_xlabel("Epoch"); axes[0, 0].set_ylabel("Loss")
    axes[0, 0].legend(); axes[0, 0].grid(True, alpha=0.3)

    # Accuracy curve
    axes[0, 1].plot([a*100 for a in history["tr_acc"]],
                    label="Train Accuracy", color="#4ECDC4", linewidth=2)
    axes[0, 1].plot([a*100 for a in history["va_acc"]],
                    label="Val Accuracy", color="#95E1D3",
                    linewidth=2, linestyle="--")
    axes[0, 1].set_title("Accuracy Over Time", fontsize=14, fontweight="bold")
    axes[0, 1].set_xlabel("Epoch"); axes[0, 1].set_ylabel("Accuracy (%)")
    axes[0, 1].set_ylim(0, 105)
    axes[0, 1].legend(loc="lower right"); axes[0, 1].grid(True, alpha=0.3)

    # Confusion matrix
    # Rows = actual label, Columns = predicted label
    # Top-left  = True Negatives  (normal correctly passed)
    # Top-right = False Positives (normal wrongly flagged as evil twin)
    # Bot-left  = False Negatives (evil twin missed — the dangerous ones)
    # Bot-right = True Positives  (evil twin correctly detected)
    cm = confusion_matrix(y_test, test_preds)
    sns.heatmap(cm, annot=True, fmt="d", cmap="Blues",
                xticklabels=class_names, yticklabels=class_names,
                ax=axes[1, 0])
    axes[1, 0].set_title("Confusion Matrix (Test Set)", fontsize=14, fontweight="bold")
    axes[1, 0].set_xlabel("Predicted"); axes[1, 0].set_ylabel("Actual")

    # Summary text
    axes[1, 1].axis("off")
    best_epoch = int(np.argmax(history["va_acc"])) + 1
    summary = (
        f"  TRAINING SUMMARY\n"
        f"  {'─'*35}\n\n"
        f"  Final Train Accuracy : {history['tr_acc'][-1]*100:.2f}%\n"
        f"  Final Val Accuracy   : {history['va_acc'][-1]*100:.2f}%\n\n"
        f"  Best Val Accuracy    : {max(history['va_acc'])*100:.2f}%\n"
        f"  Best Epoch           : {best_epoch}\n\n"
        f"  Final Train Loss     : {history['tr_loss'][-1]:.4f}\n"
        f"  Total Epochs         : {len(history['tr_loss'])}\n\n"
        f"  Model Parameters     : {history.get('model_params', 0):,}\n"
        f"  Dataset Size         : {history.get('dataset_size', 0):,} samples\n"
        f"\n  Architecture : {N_FEATURES}→128→64→32→2\n"
        f"  Optimiser    : Adam  |  Dropout: 0.3"
    )
    axes[1, 1].text(0.05, 0.95, summary, fontsize=11, family="monospace",
                    verticalalignment="top", transform=axes[1, 1].transAxes)

    plt.tight_layout()
    out = os.path.join(PLOT_DIR, "training_dashboard.png")
    plt.savefig(out, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"{GRN}    [✓] Dashboard → {out}")


# MAIN TRAINING PIPELINE
def main(args):
    """
    Full end-to-end training pipeline.

    Steps:
      1.  Detect GPU/CPU
      2.  Load Features.csv from data/processed/
      3.  Split 70% train / 15% val / 15% test
      4.  Normalise with StandardScaler (fit on train only)
      5.  Create DataLoaders with class balancing
      6.  Build WirelessIDS model + Adam optimiser
      7.  Train with early stopping on macro F1
      8.  Evaluate best checkpoint on test set
      9.  Save wireless_ids.pt + plots
    """
    print(f"\n{BAK}{WHT} AI-WIDS MODEL TRAINING {RST}\n")
    print(f"{MAG}{'='*62}")
    print(f"{MAG}  AI-WIDS Evil Twin Detection System")
    print(f"{MAG}  Complete Production Implementation")
    print(f"{MAG}{'='*62}\n")

    # 1. Device
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"{CYN}[*] Device   : {device}")
    print(f"{CYN}[*] Data dir : {args.data_dir}\n")

    # 2. Load data
    X, y, le = load_features(args.data_dir, args.sample)

    # 3. Split 70 / 15 / 15
    # stratify=y keeps the same class ratio in every split
    X_tr, X_te, y_tr, y_te = train_test_split(
        X, y, test_size=0.15, random_state=42, stratify=y)
    X_tr, X_va, y_tr, y_va = train_test_split(
        X_tr, y_tr, test_size=0.176, random_state=42, stratify=y_tr)
    # 0.176 × 85% ≈ 15% of total → gives 70/15/15

    print(f"\n{CYN}[*] Split (70/15/15) — "
          f"Train: {len(X_tr):,}  Val: {len(X_va):,}  Test: {len(X_te):,}")

    # 4. Scale
    # Fit ONLY on training data — then apply the same transform to val and test
    # Fitting on val/test would let the model "see" test data early (data leakage)
    scaler = StandardScaler()
    X_tr_s = scaler.fit_transform(X_tr)
    X_va_s = scaler.transform(X_va)
    X_te_s = scaler.transform(X_te)

    # 5. DataLoaders
    tr_loader, va_loader = make_loaders(
        X_tr_s, y_tr, X_va_s, y_va,
        batch_size=args.batch,
        balance=args.balance     # WeightedRandomSampler handles class imbalance
    )

    # ── 6. Model, loss, optimiser ─────────────────────────────────────────
    model     = WirelessIDS(input_size=N_FEATURES, num_classes=N_CLASSES,
                            dropout_p=args.dropout).to(device)
    criterion = nn.CrossEntropyLoss()    # Softmax + NLL in one numerically stable op
    optimizer = optim.Adam(model.parameters(), lr=args.lr, weight_decay=1e-4)
    # ReduceLROnPlateau halves the learning rate when val loss stops improving
    scheduler = optim.lr_scheduler.ReduceLROnPlateau(
        optimizer, mode="min", patience=5, factor=0.5)

    n_params = sum(p.numel() for p in model.parameters())
    print(f"{CYN}[*] Model    : {N_FEATURES}→128→64→32→{N_CLASSES}  "
          f"(0=normal / 1=evil_twin / 2=deauth)")
    print(f"    Params   : {n_params:,}  |  Dropout: {args.dropout}  |  LR: {args.lr}")

    # ── 7. Training loop ──────────────────────────────────────────────────
    history = {
        "tr_loss": [], "va_loss": [],
        "tr_acc":  [], "va_acc":  [],
        "model_params": n_params,
        "dataset_size": len(X),
    }
    best_f1    = 0.0       # Best validation macro F1 seen so far
    best_state = None      # Model weights at best F1
    pat_ctr    = 0         # Epochs since last improvement

    print(f"\n{CYN}{'─'*62}")
    print(f"  Epoch  │  Train Loss  │  Train Acc  │  Val Loss  │  Val Acc")
    print(f"{CYN}{'─'*62}")

    epoch_range = range(1, args.epochs + 1)
    if HAS_TQDM:
        epoch_range = tqdm(epoch_range, desc="Training", unit="epoch",
                           bar_format="{l_bar}{bar:30}{r_bar}")

    t0 = time.time()

    for epoch in epoch_range:

        # Training phase — weights ARE updated
        tr_loss, tr_acc = train_epoch(model, tr_loader, criterion, optimizer, device)

        # Validation phase — weights are NOT updated
        va_loss, va_acc, va_preds, va_labels = eval_epoch(
            model, va_loader, criterion, device)

        # Reduce LR if val loss hasn't improved for 5 epochs
        scheduler.step(va_loss)

        history["tr_loss"].append(tr_loss); history["va_loss"].append(va_loss)
        history["tr_acc"].append(tr_acc);   history["va_acc"].append(va_acc)

        # Macro F1 weighs both classes equally — better than accuracy for
        # imbalanced data because it can't be gamed by predicting majority always
        val_f1 = f1_score(va_labels, va_preds, average="macro", zero_division=0)

        if val_f1 > best_f1:
            best_f1    = val_f1
            # Clone the weights so they aren't overwritten next epoch
            best_state = {k: v.clone() for k, v in model.state_dict().items()}
            pat_ctr    = 0
        else:
            pat_ctr += 1

        # Print every 10 epochs so terminal isn't flooded
        if epoch % 10 == 0 or epoch == 1:
            tqdm.write(
                f"  Epoch {epoch:02d}: Loss {tr_loss:.4f} | "
                f"Acc {tr_acc*100:.1f}% | "
                f"Val Loss {va_loss:.4f} | Val Acc {va_acc*100:.1f}%"
            )

        # Early stopping — quit if no improvement for --patience epochs
        if args.early_stop and pat_ctr >= args.patience:
            tqdm.write(f"\n{YLW}[!] Early stopping at epoch {epoch} "
                       f"(no improvement for {args.patience} epochs)")
            break

    print(f"\n{GRN}[✓] Training complete in {time.time()-t0:.1f}s  "
          f"|  Best Val Macro-F1: {best_f1:.4f}")

    # 8. Test set evaluation
    # Load the BEST checkpoint, not the final epoch — prevents overfitting bias
    model.load_state_dict(best_state)

    te_loader = DataLoader(
        TensorDataset(torch.tensor(X_te_s, dtype=torch.float32),
                      torch.tensor(y_te,   dtype=torch.long)),
        batch_size=args.batch)

    _, te_acc, te_preds, te_labels = eval_epoch(model, te_loader, criterion, device)

    # Map integer labels back to names for the report
    label_name_map = {0: "normal", 1: "evil_twin", 2: "deauth"}
    class_names = [label_name_map.get(int(c), str(c)) for c in le.classes_]

    print(f"\n{CYN}{'─'*62}  Test Set Results")
    print(classification_report(te_labels, te_preds,
                                target_names=class_names, digits=4))
    try:
        # multi-class ROC-AUC requires one-vs-rest strategy
        te_bin = label_binarize(te_labels, classes=list(range(N_CLASSES)))
        pr_bin = label_binarize(te_preds,  classes=list(range(N_CLASSES)))
        print(f"  ROC-AUC (OVR) : "
              f"{roc_auc_score(te_bin, pr_bin, average='macro', multi_class='ovr'):.4f}")
    except Exception:
        pass

    # ── 9. Save ───────────────────────────────────────────────────────────
    print(f"\n{CYN}[*] Saving model ...")
    save_checkpoint(model, scaler, le, FEATURE_COLS)

    print(f"\n{CYN}[*] Generating training dashboard ...")
    plot_dashboard(history, te_labels, te_preds, class_names)

    print(f"\n{BAK}{WHT} TRAINING COMPLETE {RST}")
    print(f"{GRN}Model saved: {MODEL_PATH}{RST}")
    print(f"{GRN}Next step  : python src/live_detection.py{RST}\n")


# COMMAND-LINE ARGUMENTS
def parse_args():
    p = argparse.ArgumentParser(
        description="AI-WIDS: Train Evil Twin Detection DNN"
    )
    p.add_argument(
        "--data_dir", default=DEFAULT_DATA_DIR,
        help="Folder containing Features.csv (default: data/processed/)"
    )
    p.add_argument("--epochs",   type=int,   default=50,
                   help="Max training epochs (default: 50)")
    p.add_argument("--lr",       type=float, default=0.0005,
                   help="Learning rate (default: 0.0005)")
    p.add_argument("--batch",    type=int,   default=64,
                   help="Batch size (default: 64)")
    p.add_argument("--dropout",  type=float, default=0.2,
                   help="Dropout probability (default: 0.2)")
    p.add_argument("--patience", type=int,   default=50,
                   help="Early stopping patience in epochs (default: 50)")
    p.add_argument("--sample",   type=int,   default=0,
                   help="Subsample N rows for quick testing (0 = all data)")
    p.add_argument("--no-early-stop", dest="early_stop", action="store_false",
                   help="Disable early stopping")
    p.add_argument("--no-balance",    dest="balance",    action="store_false",
                   help="Disable class balancing (not recommended)")
    p.set_defaults(early_stop=True, balance=True)
    return p.parse_args()


# ENTRY POINT
if __name__ == "__main__":
    main(parse_args())

