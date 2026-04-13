#!/usr/bin/env python3
"""
train_model.py — AI-WIDS Evil Twin Detection

Purpose : Train a Deep Neural Network to detect Evil Twin Wi-Fi attacks
Dataset : AWID3 (Aegean Wi-Fi Intrusion Dataset v3) — real 802.11 captures
          Download: https://icsdweb.aegean.gr/awid/awid3

Execution:
    python train_model.py                                  # default settings
    python train_model.py --data_dir data/processed        # custom data folder
    python train_model.py --epochs 50 --lr 0.001           # custom hyperparams
    python train_model.py --sample 2000 --epochs 10        # quick test run

Output:
    data/model/wireless_ids.pt          ← trained model (used by live_detection.py)
    data/model/scaler.pkl               ← feature scaler (must ship with model)
    data/model/label_encoder.pkl        ← label encoder
    data/model/plots/training_dashboard.png  ← 2×2 visualisation dashboard

AWID3 CSV setup — place files in data/processed/:
    Normal traffic : any CSV where label column = "normal"
    Evil Twin      : any CSV where label column = "Evil Twin"
    Or combined    : a single Features.csv with both labels

16 AWID3 features used (proven sufficient by Chatzoglou et al. 2022):
    wlan.fc.type, wlan.fc.subtype, wlan.fc.ds, wlan.fc.frag,
    wlan.fc.retry, wlan.fc.pwrmgt, wlan.fc.moredata, wlan.fc.protected,
    wlan.duration, wlan.ra, frame.len, frame.time_delta,
    frame.time_delta_displayed, wlan.fc.order,
    radiotap.channel.freq, radiotap.dbm_antsignal
"""

# IMPORTS
import os                                    # File and folder operations
import argparse                              # Command-line argument parsing
import time                                  # Measuring training duration
import warnings
warnings.filterwarnings("ignore")            # Suppress noisy sklearn/torch warnings

import numpy as np                           # Numerical array operations
import pandas as pd                          # CSV loading and DataFrame manipulation
import torch                                 # PyTorch core framework
import torch.nn as nn                        # Neural network layer definitions
import torch.optim as optim                  # Optimisers (Adam, SGD, etc.)
from torch.utils.data import (              # PyTorch data utilities
    DataLoader, TensorDataset, WeightedRandomSampler
)
from sklearn.model_selection import train_test_split   # Split data into train/val/test
from sklearn.preprocessing import StandardScaler       # Normalise features to mean=0, std=1
from sklearn.preprocessing import LabelEncoder         # Convert string labels to integers
from sklearn.metrics import (
    classification_report,                   # Per-class precision/recall/F1
    confusion_matrix,                        # TP/FP/TN/FN breakdown
    roc_auc_score,                           # Area under the ROC curve
    f1_score                                 # Harmonic mean of precision and recall
)
import joblib                                # Save/load Python objects (scaler, encoder)
import matplotlib                            # Plotting backend configuration
matplotlib.use("Agg")                        # Use non-interactive backend (saves to file)
import matplotlib.pyplot as plt              # Create figures and axes
import seaborn as sns                        # Statistical heatmaps and styling

# ── Optional colour output in the terminal (gracefully skipped if not installed) ──
try:
    from colorama import Fore, Style, Back, init as colorama_init
    colorama_init(autoreset=True)            # Reset colour after every print automatically
    RED = Fore.RED;   GRN = Fore.GREEN;  CYN = Fore.CYAN
    YLW = Fore.YELLOW; MAG = Fore.MAGENTA; RST = Style.RESET_ALL
    WHT = Fore.WHITE;  BAK = Back.MAGENTA
except ImportError:
    # If colorama is not installed just use empty strings — no crash
    RED = GRN = CYN = YLW = MAG = RST = WHT = BAK = ""

# ── Optional progress bars (gracefully skipped if not installed) ──────────────
try:
    from tqdm import tqdm
    HAS_TQDM = True
except ImportError:
    HAS_TQDM = False
    class tqdm:                              # Minimal shim so tqdm calls don't crash
        def __init__(self, iterable=None, **kw): self._it = iterable
        def __iter__(self): return iter(self._it)
        @staticmethod
        def write(s): print(s)              # tqdm.write() falls back to print()


# FILE PATHS
# BASE_DIR is always the folder that contains this script, regardless of
# where you run it from — prevents the "wrong directory" FileNotFoundError.
BASE_DIR    = os.path.dirname(os.path.abspath(__file__))

# Output folders — created automatically if they don't exist
MODEL_DIR   = os.path.join(BASE_DIR, "data", "model")        # Trained model files
PLOT_DIR    = os.path.join(MODEL_DIR, "plots")                # Dashboard PNG

# Output file paths
MODEL_PATH  = os.path.join(MODEL_DIR, "wireless_ids.pt")      # PyTorch model weights
SCALER_PATH = os.path.join(MODEL_DIR, "scaler.pkl")           # StandardScaler object
ENCODE_PATH = os.path.join(MODEL_DIR, "label_encoder.pkl")    # LabelEncoder object

# Create the folders now so saves never fail
os.makedirs(MODEL_DIR, exist_ok=True)
os.makedirs(PLOT_DIR,  exist_ok=True)


# AWID3 FEATURE CONFIGURATION
# These 16 column names are the exact Wireshark field names used in AWID3 CSVs.
# Research (Chatzoglou et al. 2022) showed these 16 are sufficient for high
# accuracy evil twin detection — using all 253 features adds noise and overhead.
AWID3_FEATURES = [
    "wlan.fc.type",               # Frame type: 0=management, 1=control, 2=data
    "wlan.fc.subtype",            # Frame subtype within the type (0–15)
    "wlan.fc.ds",                 # To DS / From DS bits — indicates infrastructure mode
    "wlan.fc.frag",               # More Fragments flag — set if frame is fragmented
    "wlan.fc.retry",              # Retry flag — 1 if this is a retransmission
    "wlan.fc.pwrmgt",             # Power Management flag — client sleeping or awake
    "wlan.fc.moredata",           # More Data flag — AP has buffered frames for client
    "wlan.fc.protected",          # Protected Frame flag — STRONGEST evil twin signal
                                  #   Legitimate APs use protection; evil twins often don't
    "wlan.duration",              # NAV duration field in microseconds
    "wlan.ra",                    # Receiver Address (MAC encoded as integer)
    "frame.len",                  # Total frame length in bytes
    "frame.time_delta",           # Seconds since the previous captured frame
    "frame.time_delta_displayed", # Same but as displayed by Wireshark
    "wlan.fc.order",              # Strictly Ordered flag (rarely set in normal traffic)
    "radiotap.channel.freq",      # Physical radio channel frequency in MHz (e.g. 2412)
    "radiotap.dbm_antsignal",     # Received signal strength in dBm (e.g. -65)
]

# Label column and class names — must match the strings in your AWID3 CSV exactly
LABEL_COL    = "label"            # Column name that holds the class label
LABEL_NORMAL = "normal"           # Label for legitimate traffic
LABEL_ATTACK = "Evil Twin"        # Label for evil twin attack traffic in AWID3
                                  # If your CSV uses "evil_twin" update this line


# NEURAL NETWORK ARCHITECTURE
class WirelessIDS(nn.Module):
    """
    4-layer Feedforward Deep Neural Network for binary classification.

    Architecture:  input → 128 → 64 → 32 → 2
                   (with ReLU activations and Dropout regularisation)

    Why this architecture?
    - 4 layers give enough depth to learn non-linear patterns in 802.11 traffic
    - Width decreases (128→64→32) to progressively compress features
    - Dropout(0.3) randomly disables 30% of neurons per forward pass during
      training to prevent overfitting on the training data
    - Output is 2 raw logits (one per class); CrossEntropyLoss applies softmax

    This architecture matches the pre-trained wireless_ids.pt checkpoint.
    """

    def __init__(self, input_size: int = 16, dropout_p: float = 0.3):
        """
        Initialise all layers.
        Args:
            input_size : number of input features (16 for AWID3)
            dropout_p  : probability of dropping a neuron (default 0.3 = 30%)
        """
        super().__init__()                        # Initialise nn.Module parent class

        # Fully connected layers — each maps from N inputs to M outputs
        self.fc1 = nn.Linear(input_size, 128)     # Layer 1: 16 features  → 128 neurons
        self.fc2 = nn.Linear(128, 64)             # Layer 2: 128 neurons  → 64 neurons
        self.fc3 = nn.Linear(64, 32)              # Layer 3: 64 neurons   → 32 neurons
        self.fc4 = nn.Linear(32, 2)               # Layer 4: 32 neurons   → 2 outputs
                                                  #   output[0] = score for "Evil Twin"
                                                  #   output[1] = score for "normal"

        self.relu    = nn.ReLU()                  # ReLU: replaces negative values with 0
                                                  #   introduces non-linearity so the model
                                                  #   can learn complex decision boundaries
        self.dropout = nn.Dropout(p=dropout_p)    # Dropout regularisation (prevents overfitting)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        """
        Define the forward pass — how data flows through the network.
        Args:
            x : input tensor of shape [batch_size, input_size]
        Returns:
            raw logits of shape [batch_size, 2]
        """
        x = self.relu(self.fc1(x))   # Pass through layer 1, apply ReLU
        x = self.dropout(x)          # Randomly zero 30% of neurons (training only)
        x = self.relu(self.fc2(x))   # Pass through layer 2, apply ReLU
        x = self.dropout(x)          # Dropout again
        x = self.relu(self.fc3(x))   # Pass through layer 3, apply ReLU
        x = self.dropout(x)          # Dropout again
        x = self.fc4(x)              # Final layer — NO activation here because
                                     # CrossEntropyLoss applies softmax internally
        return x                     # Return raw logits [batch_size, 2]


# DATA LOADING
def find_csvs(data_dir: str) -> list:
    """
    Recursively find all CSV files inside data_dir.
    Returns a sorted list of full file paths.
    """
    found = []
    for root, _, files in os.walk(data_dir):     # Walk the folder tree
        for f in files:
            if f.lower().endswith(".csv"):        # Case-insensitive .csv check
                found.append(os.path.join(root, f))
    return sorted(found)                         # Sort for consistent ordering


def load_awid3(data_dir: str, sample_n: int = 0):
    """
    Load AWID3 CSV files, clean them, and return feature matrix + labels.

    Handles two layouts:
      A) Single merged file (e.g. Features.csv) with a 'label' column
      B) Multiple per-attack CSVs — reads all and filters to normal + Evil Twin

    Steps performed:
      1. Find and read all CSVs in data_dir
      2. Replace AWID3's '?' missing value marker with NaN
      3. Filter rows to only normal and Evil Twin classes
      4. Fill any remaining NaN values with the column median
      5. Optionally subsample for quick testing

    Args:
        data_dir : folder containing AWID3 CSV files
        sample_n : if > 0, subsample to this many rows total (for quick tests)

    Returns:
        X  : float32 numpy array of shape (N, 16)
        y  : integer numpy array of shape (N,)
        le : fitted LabelEncoder (maps class names ↔ integers)
    """
    # ── Find CSVs ──────────────────────────────────────────────────────────
    csvs = find_csvs(data_dir)
    if not csvs:
        raise FileNotFoundError(
            f"\nNo CSV files found in '{data_dir}'.\n"
            f"Download AWID3 from: https://icsdweb.aegean.gr/awid/awid3\n"
            f"Place the CSV files in: {data_dir}\n"
        )

    print(f"{CYN}[*] Found {len(csvs)} CSV file(s) in: {data_dir}")

    # ── Read each CSV ──────────────────────────────────────────────────────
    frames = []
    for path in csvs:
        try:
            df = pd.read_csv(path, low_memory=False)   # low_memory=False avoids dtype warnings
            df.replace("?", np.nan, inplace=True)      # AWID3 uses '?' for missing values
            frames.append(df)
            print(f"    ✓  {os.path.basename(path):45s} {len(df):>10,} rows")
        except Exception as e:
            print(f"{YLW}    !  Skipped {os.path.basename(path)}: {e}")

    if not frames:
        raise ValueError("All CSV files failed to load.")

    # ── Merge all files into one DataFrame ─────────────────────────────────
    df = pd.concat(frames, ignore_index=True)
    print(f"\n    Total loaded : {len(df):,} rows")

    # ── Validate label column exists ───────────────────────────────────────
    if LABEL_COL not in df.columns:
        raise ValueError(
            f"Column '{LABEL_COL}' not found.\n"
            f"Columns present: {list(df.columns)[:20]}"
        )

    # ── Filter to binary classification: normal vs Evil Twin ───────────────
    # AWID3 has 13 attack types — we only need normal and Evil Twin rows
    df = df[df[LABEL_COL].isin([LABEL_NORMAL, LABEL_ATTACK])].copy()
    print(f"    After label filter  : {len(df):,} rows")

    if len(df) == 0:
        # Show the user what labels are actually in the file to help them fix it
        actual = pd.concat(frames)[LABEL_COL].dropna().unique()[:10]
        raise ValueError(
            f"No rows matched '{LABEL_NORMAL}' or '{LABEL_ATTACK}'.\n"
            f"Labels in your dataset: {list(actual)}\n"
            f"Update LABEL_NORMAL / LABEL_ATTACK at the top of train_model.py."
        )

    # ── Show class distribution ────────────────────────────────────────────
    # AWID3 evil twin is heavily imbalanced (~35:1 normal:attack)
    dist = df[LABEL_COL].value_counts()
    print(f"\n{CYN}[*] Class distribution:")
    for cls, cnt in dist.items():
        print(f"    {cls:25s}: {cnt:10,}  ({100 * cnt / len(df):.1f}%)")

    # ── Handle missing feature columns ────────────────────────────────────
    missing = [c for c in AWID3_FEATURES if c not in df.columns]
    if missing:
        print(f"\n{YLW}[!] Missing columns (filling with 0): {missing}")
    for col in missing:
        df[col] = 0.0                              # Fill absent columns with zero

    # ── Convert features to numeric, fill NaN with column median ──────────
    for col in AWID3_FEATURES:
        df[col] = pd.to_numeric(df[col], errors="coerce")   # Non-numeric → NaN
    df[AWID3_FEATURES] = df[AWID3_FEATURES].fillna(
        df[AWID3_FEATURES].median()                # Replace NaN with median value
    )

    # ── Optional subsample for quick testing ──────────────────────────────
    # Useful when you want to verify the pipeline works before running on millions of rows
    if sample_n > 0 and len(df) > sample_n:
        per_class = sample_n // 2                  # Equal samples from each class
        parts = []
        for lbl in [LABEL_NORMAL, LABEL_ATTACK]:
            subset = df[df[LABEL_COL] == lbl]
            parts.append(subset.sample(min(len(subset), per_class), random_state=42))
        df = pd.concat(parts).sample(frac=1, random_state=42).reset_index(drop=True)
        print(f"\n    Subsampled to {len(df):,} rows (--sample {sample_n})")

    # ── Build feature matrix and encode labels ─────────────────────────────
    X  = df[AWID3_FEATURES].values.astype(np.float32)   # Shape: (N, 16)
    le = LabelEncoder()
    y  = le.fit_transform(df[LABEL_COL].values)         # "Evil Twin"→0, "normal"→1

    print(f"\n    Label map : {dict(zip(le.classes_, le.transform(le.classes_)))}")
    print(f"    X shape   : {X.shape}")
    return X, y, le


# DATALOADER CREATION
def make_loaders(X_tr, y_tr, X_va, y_va, batch_size: int, balance: bool):
    """
    Wrap numpy arrays in PyTorch DataLoaders ready for training.

    If balance=True, uses WeightedRandomSampler so each batch sees roughly
    equal numbers of normal and evil twin samples — critical for AWID3 because
    normal traffic outnumbers attacks by ~35:1 without balancing.

    Args:
        X_tr, y_tr : training features and labels (numpy arrays)
        X_va, y_va : validation features and labels
        batch_size : number of samples per batch
        balance    : whether to use weighted sampling to counter class imbalance

    Returns:
        tr_loader : DataLoader for training (shuffled / balanced)
        va_loader : DataLoader for validation (unshuffled)
    """
    # Convert numpy arrays to PyTorch tensors
    Xtr = torch.tensor(X_tr, dtype=torch.float32)   # Features must be float32
    ytr = torch.tensor(y_tr, dtype=torch.long)       # Labels must be int64 (long)
    Xva = torch.tensor(X_va, dtype=torch.float32)
    yva = torch.tensor(y_va, dtype=torch.long)

    if balance:
        # Compute per-sample weights — minority class gets higher weight
        # so it appears as often as the majority class in each batch
        counts  = np.bincount(y_tr)                  # [count_class0, count_class1]
        weights = 1.0 / counts[y_tr]                 # Inverse frequency weighting
        sampler = WeightedRandomSampler(
            weights=torch.tensor(weights, dtype=torch.float32),
            num_samples=len(y_tr),                   # Draw same total number of samples
            replacement=True                         # Allow the same sample multiple times
        )
        tr_loader = DataLoader(
            TensorDataset(Xtr, ytr),
            batch_size=batch_size,
            sampler=sampler                          # WeightedSampler replaces shuffle=True
        )
    else:
        tr_loader = DataLoader(
            TensorDataset(Xtr, ytr),
            batch_size=batch_size,
            shuffle=True                             # Standard random shuffling
        )

    # Validation loader — never shuffle, never balance (we want real distribution)
    va_loader = DataLoader(
        TensorDataset(Xva, yva),
        batch_size=batch_size,
        shuffle=False
    )
    return tr_loader, va_loader


# SINGLE EPOCH TRAINING
def train_epoch(model, loader, criterion, optimizer, device):
    """
    Run one full training epoch over all batches.

    Process per batch:
      1. Move data to GPU/CPU
      2. Zero out gradients from the previous batch
      3. Forward pass — compute predictions
      4. Compute loss — compare predictions to true labels
      5. Backward pass — compute gradients via backpropagation
      6. Optimiser step — update weights using the gradients

    Args:
        model     : WirelessIDS neural network
        loader    : training DataLoader
        criterion : loss function (CrossEntropyLoss)
        optimizer : Adam optimiser
        device    : torch.device (cpu or cuda)

    Returns:
        avg_loss : mean loss across all samples in this epoch
        accuracy : fraction of correctly classified samples (0.0–1.0)
    """
    model.train()                                # Enable dropout (training mode)
    loss_sum = correct = total = 0

    for Xb, yb in loader:
        Xb, yb = Xb.to(device), yb.to(device)  # Move batch to GPU/CPU

        optimizer.zero_grad()                   # Clear gradients from last batch
        out  = model(Xb)                        # Forward pass — get raw logits
        loss = criterion(out, yb)               # Compute cross-entropy loss
        loss.backward()                         # Backprop — compute gradients
        optimizer.step()                        # Update all model weights

        # Track cumulative loss and accuracy for reporting
        loss_sum += loss.item() * len(yb)       # Weighted by batch size
        correct  += (out.argmax(1) == yb).sum().item()  # Count correct predictions
        total    += len(yb)

    return loss_sum / total, correct / total    # Return averages


# SINGLE EPOCH EVALUATION
@torch.no_grad()                                # Disable gradient tracking (saves memory)
def eval_epoch(model, loader, criterion, device):
    """
    Evaluate the model on a dataset without updating weights.

    @torch.no_grad() means PyTorch won't build the computation graph,
    which saves memory and is faster — correct for val/test evaluation.

    Args:
        model     : WirelessIDS neural network
        loader    : validation or test DataLoader
        criterion : loss function
        device    : torch.device

    Returns:
        avg_loss  : mean loss across all samples
        accuracy  : fraction of correct predictions (0.0–1.0)
        all_preds : numpy array of predicted class indices
        all_labels: numpy array of true class indices
    """
    model.eval()                                # Disable dropout (evaluation mode)
    loss_sum = correct = total = 0
    all_preds, all_labels = [], []

    for Xb, yb in loader:
        Xb, yb = Xb.to(device), yb.to(device)
        out  = model(Xb)
        loss = criterion(out, yb)

        loss_sum += loss.item() * len(yb)
        correct  += (out.argmax(1) == yb).sum().item()
        total    += len(yb)

        # Collect all predictions and labels for confusion matrix etc.
        all_preds.append(out.argmax(1).cpu().numpy())
        all_labels.append(yb.cpu().numpy())

    return (
        loss_sum / total,
        correct / total,
        np.concatenate(all_preds),              # Flatten list of arrays into one
        np.concatenate(all_labels)
    )


# TRAINING DASHBOARD PLOT
def plot_training_dashboard(history, y_test, test_preds, class_names):
    """
    Generate a 2×2 visualisation dashboard and save it as a PNG.

    Panel layout:
      [0,0] Training Loss over epochs
      [0,1] Train vs Validation Accuracy over epochs
      [1,0] Confusion Matrix on the test set
      [1,1] Training Summary text box

    The confusion matrix shows:
      - True Positives  (Evil Twin correctly detected)
      - False Negatives (Evil Twin missed — the dangerous ones)
      - False Positives (Normal traffic wrongly flagged)
      - True Negatives  (Normal traffic correctly passed)

    Args:
        history     : dict with keys tr_loss, va_loss, tr_acc, va_acc,
                      model_params, dataset_size
        y_test      : true labels from the test set
        test_preds  : predicted labels from the test set
        class_names : list of class name strings e.g. ["Evil Twin", "normal"]
    """
    plt.style.use("seaborn-v0_8-darkgrid")      # Clean dark-grid style for readability
    fig, axes = plt.subplots(2, 2, figsize=(15, 10))  # 2 rows × 2 columns

    # ── Panel [0,0]: Training Loss ─────────────────────────────────────────
    axes[0, 0].plot(
        history["tr_loss"],
        label="Train Loss",
        color="#FF6B6B",           # Red — warm colour for training metric
        linewidth=2
    )
    axes[0, 0].plot(
        history["va_loss"],
        label="Val Loss",
        color="#FF9999",           # Lighter red for validation
        linewidth=2,
        linestyle="--"             # Dashed to distinguish from train line
    )
    axes[0, 0].set_title("Loss Over Time", fontsize=14, fontweight="bold")
    axes[0, 0].set_xlabel("Epoch", fontsize=12)
    axes[0, 0].set_ylabel("Loss", fontsize=12)
    axes[0, 0].legend(loc="upper right")
    axes[0, 0].grid(True, alpha=0.3)

    # ── Panel [0,1]: Accuracy ──────────────────────────────────────────────
    # Convert 0.0–1.0 fractions to percentages for readability
    tr_acc_pct = [a * 100 for a in history["tr_acc"]]
    va_acc_pct = [a * 100 for a in history["va_acc"]]

    axes[0, 1].plot(tr_acc_pct, label="Train Accuracy", color="#4ECDC4", linewidth=2)
    axes[0, 1].plot(va_acc_pct, label="Val Accuracy",   color="#95E1D3", linewidth=2,
                    linestyle="--")
    axes[0, 1].set_title("Accuracy Over Time", fontsize=14, fontweight="bold")
    axes[0, 1].set_xlabel("Epoch", fontsize=12)
    axes[0, 1].set_ylabel("Accuracy (%)", fontsize=12)
    axes[0, 1].set_ylim(0, 105)              # Give a little headroom above 100%
    axes[0, 1].legend(loc="lower right")
    axes[0, 1].grid(True, alpha=0.3)

    # ── Panel [1,0]: Confusion Matrix ─────────────────────────────────────
    cm = confusion_matrix(y_test, test_preds)
    sns.heatmap(
        cm,
        annot=True,                          # Print numbers inside cells
        fmt="d",                             # Format as integers
        cmap="Blues",                        # Blue colour scale
        xticklabels=class_names,             # Predicted class names on X axis
        yticklabels=class_names,             # Actual class names on Y axis
        ax=axes[1, 0]
    )
    axes[1, 0].set_title("Confusion Matrix (Test Set)", fontsize=14, fontweight="bold")
    axes[1, 0].set_xlabel("Predicted", fontsize=12)
    axes[1, 0].set_ylabel("Actual", fontsize=12)

    # ── Panel [1,1]: Training Summary text box ─────────────────────────────
    axes[1, 1].axis("off")                   # Hide the axes — we just want text

    best_val_epoch = int(np.argmax(history["va_acc"])) + 1    # +1 for 1-indexed
    best_val_acc   = max(history["va_acc"]) * 100
    final_tr_acc   = history["tr_acc"][-1]  * 100
    final_va_acc   = history["va_acc"][-1]  * 100
    final_loss     = history["tr_loss"][-1]
    n_epochs       = len(history["tr_loss"])
    n_params       = history.get("model_params", "N/A")
    n_samples      = history.get("dataset_size", "N/A")

    summary = (
        f"  TRAINING SUMMARY\n"
        f"  {'─'*35}\n\n"
        f"  Final Train Accuracy : {final_tr_acc:.2f}%\n"
        f"  Final Val Accuracy   : {final_va_acc:.2f}%\n\n"
        f"  Best Val Accuracy    : {best_val_acc:.2f}%\n"
        f"  Best Epoch           : {best_val_epoch}\n\n"
        f"  Final Train Loss     : {final_loss:.4f}\n"
        f"  Total Epochs         : {n_epochs}\n\n"
        f"  Model Parameters     : {n_params:,}\n"
        f"  Dataset Size         : {n_samples:,} samples\n"
        f"\n  Architecture: input→128→64→32→2\n"
        f"  Optimiser: Adam | Dropout: 0.3"
    )
    axes[1, 1].text(
        0.05, 0.95, summary,
        fontsize=11,
        family="monospace",
        verticalalignment="top",             # Align text to top of text box
        transform=axes[1, 1].transAxes      # Use axis coordinates (0–1)
    )

    # ── Save the dashboard ─────────────────────────────────────────────────
    plt.tight_layout()                       # Prevent panels overlapping
    out_path = os.path.join(PLOT_DIR, "training_dashboard.png")
    plt.savefig(out_path, dpi=150, bbox_inches="tight")  # High-res save
    plt.close()                              # Free memory

    print(f"{GRN}    [✓] Dashboard saved → {out_path}")


# SAVE MODEL CHECKPOINT
def save_checkpoint(model, scaler, le):
    """
    Save the trained model and preprocessing objects to disk.

    wireless_ids.pt stores everything live_detection.py needs in one file:
      - model weights (state_dict)
      - the fitted StandardScaler (so live traffic is scaled the same way)
      - the LabelEncoder (so predictions are decoded to class names)
      - the feature list (so live_detection.py uses the same 16 columns)

    Also saves scaler.pkl and label_encoder.pkl as separate files
    in case they need to be loaded independently.
    """
    # Bundle everything into one dict and save as a PyTorch checkpoint
    torch.save(
        {
            "model_state_dict": model.state_dict(),  # Learned weights
            "scaler":           scaler,              # StandardScaler fit on training data
            "label_encoder":    le,                  # Maps integers back to class names
            "features":         AWID3_FEATURES,      # Column order expected at inference
        },
        MODEL_PATH
    )
    # Also save scaler and encoder separately for convenience
    joblib.dump(scaler, SCALER_PATH)
    joblib.dump(le,     ENCODE_PATH)

    print(f"{GRN}    [✓] Model   saved → {MODEL_PATH}")
    print(f"{GRN}    [✓] Scaler  saved → {SCALER_PATH}")
    print(f"{GRN}    [✓] Encoder saved → {ENCODE_PATH}")


# MAIN TRAINING PIPELINE
def main(args):
    """
    Full training pipeline — called when the script is run directly.

    Steps:
      1.  Detect GPU or fall back to CPU
      2.  Load and clean AWID3 CSV data
      3.  Split into train / validation / test sets
      4.  Normalise features with StandardScaler
      5.  Wrap data in PyTorch DataLoaders (with class balancing)
      6.  Initialise WirelessIDS model, loss function, and Adam optimiser
      7.  Train for up to --epochs epochs with early stopping on val F1
      8.  Evaluate the best checkpoint on the held-out test set
      9.  Save model checkpoint + plots
    """

    # ── Header ─────────────────────────────────────────────────────────────
    print(f"\n{BAK}{WHT} AI-WIDS MODEL TRAINING {RST}\n")
    print(f"{MAG}{'='*62}")
    print(f"{MAG}  AI-WIDS  |  Evil Twin Detection  |  Training on AWID3")
    print(f"{MAG}{'='*62}\n")

    # ── Step 1: Device selection ───────────────────────────────────────────
    # Uses GPU (CUDA) if available for faster matrix operations, otherwise CPU
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"{CYN}[*] Device   : {device}")
    print(f"{CYN}[*] Data dir : {args.data_dir}\n")

    # ── Step 2: Load AWID3 data ────────────────────────────────────────────
    X, y, le = load_awid3(args.data_dir, args.sample)

    # ── Step 3: Train / Validation / Test split ────────────────────────────
    # First split: 80% train+val, 20% test
    X_tr, X_te, y_tr, y_te = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y  # stratify keeps class ratio
    )
    # Second split: from the 80%, take 15% as validation (~12% of total)
    X_tr, X_va, y_tr, y_va = train_test_split(
        X_tr, y_tr, test_size=0.15, random_state=42, stratify=y_tr
    )
    print(f"\n{CYN}[*] Split — Train: {len(X_tr):,}  Val: {len(X_va):,}  Test: {len(X_te):,}")

    # ── Step 4: Feature scaling ────────────────────────────────────────────
    # StandardScaler transforms each feature to mean=0, std=1
    # IMPORTANT: fit only on training data, then apply the same transform to val/test
    # Fitting on val/test would leak information and inflate scores
    scaler = StandardScaler()
    X_tr_s = scaler.fit_transform(X_tr)     # Fit scaler to training data + transform
    X_va_s = scaler.transform(X_va)         # Transform val using training stats
    X_te_s = scaler.transform(X_te)         # Transform test using training stats

    # ── Step 5: DataLoaders ────────────────────────────────────────────────
    tr_loader, va_loader = make_loaders(
        X_tr_s, y_tr, X_va_s, y_va,
        batch_size=args.batch,
        balance=args.balance                 # WeightedRandomSampler for 35:1 imbalance
    )

    # ── Step 6: Model, loss function, optimiser ────────────────────────────
    # input_size matches the number of features (16 for AWID3)
    model = WirelessIDS(input_size=X.shape[1], dropout_p=args.dropout).to(device)

    # CrossEntropyLoss = Softmax + Negative Log Likelihood
    # Correct choice for multi-class classification with integer labels
    criterion = nn.CrossEntropyLoss()

    # Adam optimiser — adaptive learning rate, works well for most DNN tasks
    # weight_decay=1e-4 adds L2 regularisation to penalise large weights
    optimizer = optim.Adam(model.parameters(), lr=args.lr, weight_decay=1e-4)

    # ReduceLROnPlateau halves the learning rate when val loss stops improving
    # patience=5 means it waits 5 epochs before reducing
    scheduler = optim.lr_scheduler.ReduceLROnPlateau(
        optimizer, mode="min", patience=5, factor=0.5
    )

    n_params = sum(p.numel() for p in model.parameters())
    print(f"{CYN}[*] Model    : {X.shape[1]}→128→64→32→2")
    print(f"    Params   : {n_params:,}  |  Dropout: {args.dropout}  |  LR: {args.lr}")

    # ── Step 7: Training loop ──────────────────────────────────────────────
    # history stores metrics each epoch so we can plot them later
    history = {
        "tr_loss":      [],       # Training loss per epoch
        "va_loss":      [],       # Validation loss per epoch
        "tr_acc":       [],       # Training accuracy per epoch (0.0–1.0)
        "va_acc":       [],       # Validation accuracy per epoch (0.0–1.0)
        "model_params": n_params,
        "dataset_size": len(X),
    }

    best_f1    = 0.0              # Track best validation F1 to save best checkpoint
    best_state = None             # Copy of model weights at best F1
    pat_ctr    = 0                # Epochs since last improvement (early stopping counter)

    print(f"\n{CYN}{'─'*62}")
    print(f"  Epoch  │  Train Loss  │  Train Acc  │  Val Loss  │  Val Acc")
    print(f"{CYN}{'─'*62}")

    # Wrap epoch range in tqdm for a progress bar if available
    epoch_range = range(1, args.epochs + 1)
    if HAS_TQDM:
        epoch_range = tqdm(epoch_range, desc="Training", unit="epoch",
                           bar_format="{l_bar}{bar:30}{r_bar}")

    t0 = time.time()             # Record start time

    for epoch in epoch_range:

        # ── Training phase ─────────────────────────────────────────────────
        tr_loss, tr_acc = train_epoch(model, tr_loader, criterion, optimizer, device)

        # ── Validation phase ───────────────────────────────────────────────
        va_loss, va_acc, va_preds, va_labels = eval_epoch(
            model, va_loader, criterion, device
        )

        # Step the LR scheduler — reduces LR if val loss plateaus
        scheduler.step(va_loss)

        # Store metrics for this epoch
        history["tr_loss"].append(tr_loss);  history["va_loss"].append(va_loss)
        history["tr_acc"].append(tr_acc);    history["va_acc"].append(va_acc)

        # Compute macro F1 on validation set
        # Macro F1 treats each class equally — better metric than accuracy
        # for imbalanced datasets because accuracy can be high by just
        # predicting the majority class all the time
        val_f1 = f1_score(va_labels, va_preds, average="macro", zero_division=0)

        # Save the model state if this is the best F1 seen so far
        if val_f1 > best_f1:
            best_f1    = val_f1
            best_state = {k: v.clone() for k, v in model.state_dict().items()}
            pat_ctr    = 0                   # Reset patience counter
        else:
            pat_ctr   += 1                   # No improvement this epoch

        # Print a summary row every 10 epochs
        if epoch % 10 == 0 or epoch == 1:
            tqdm.write(
                f"  {epoch:5d}  │  {tr_loss:.5f}     │"
                f"  {tr_acc:.4f}     │  {va_loss:.5f}  │  {va_acc:.4f}"
            )

        # ── Early stopping ─────────────────────────────────────────────────
        # Stop training if val F1 hasn't improved for --patience epochs
        # This prevents overfitting and wasted compute
        if args.early_stop and pat_ctr >= args.patience:
            tqdm.write(
                f"\n{YLW}[!] Early stopping at epoch {epoch} "
                f"(no improvement for {args.patience} epochs)"
            )
            break

    elapsed = time.time() - t0
    print(f"\n{GRN}[✓] Training complete in {elapsed:.1f}s  |  Best Val Macro-F1: {best_f1:.4f}")

    # ── Step 8: Test set evaluation ────────────────────────────────────────
    # Restore the best model weights (not necessarily the last epoch)
    model.load_state_dict(best_state)

    te_loader = DataLoader(
        TensorDataset(
            torch.tensor(X_te_s, dtype=torch.float32),
            torch.tensor(y_te,   dtype=torch.long)
        ),
        batch_size=args.batch
    )
    _, te_acc, te_preds, te_labels = eval_epoch(model, te_loader, criterion, device)

    class_names = list(le.classes_)         # e.g. ["Evil Twin", "normal"]

    print(f"\n{CYN}{'─'*62}  Test Set Results")
    # classification_report shows precision, recall, F1 per class
    # Recall for Evil Twin is the most important — missed attacks are dangerous
    print(classification_report(te_labels, te_preds, target_names=class_names, digits=4))
    try:
        auc = roc_auc_score(te_labels, te_preds)
        print(f"  ROC-AUC : {auc:.4f}")    # 1.0 = perfect, 0.5 = random guess
    except Exception:
        pass                               # Skip if only one class in test set

    # ── Step 9: Save checkpoint and plots ─────────────────────────────────
    print(f"\n{CYN}[*] Saving model ...")
    save_checkpoint(model, scaler, le)

    print(f"\n{CYN}[*] Generating training dashboard ...")
    plot_training_dashboard(history, te_labels, te_preds, class_names)

    # Final summary
    print(f"\n{BAK}{WHT} TRAINING COMPLETE {RST}")
    print(f"\n{GRN}Next step: python live_detection.py{RST}\n")


# COMMAND-LINE ARGUMENTS
def parse_args():
    """
    Define and parse command-line arguments.
    All arguments have sensible defaults so the script works with no arguments.
    """
    p = argparse.ArgumentParser(
        description="AI-WIDS: Train Evil Twin Detection DNN on AWID3"
    )

    p.add_argument(
        "--data_dir",
        default=os.path.join(BASE_DIR, "data", "processed"),
        help="Folder containing AWID3 CSV files (default: data/processed/)"
    )
    p.add_argument(
        "--epochs",   type=int,   default=50,
        help="Maximum training epochs (default: 50)"
    )
    p.add_argument(
        "--lr",       type=float, default=0.001,
        help="Initial learning rate for Adam (default: 0.001)"
    )
    p.add_argument(
        "--batch",    type=int,   default=64,
        help="Batch size — samples processed per weight update (default: 64)"
    )
    p.add_argument(
        "--dropout",  type=float, default=0.3,
        help="Dropout probability — fraction of neurons dropped (default: 0.3)"
    )
    p.add_argument(
        "--patience", type=int,   default=10,
        help="Early stopping patience in epochs (default: 10)"
    )
    p.add_argument(
        "--sample",   type=int,   default=0,
        help="Subsample N rows for quick testing — 0 means use all data (default: 0)"
    )
    p.add_argument(
        "--no-early-stop", dest="early_stop", action="store_false",
        help="Disable early stopping and always train for --epochs epochs"
    )
    p.add_argument(
        "--no-balance", dest="balance", action="store_false",
        help="Disable WeightedRandomSampler (not recommended for imbalanced AWID3)"
    )
    p.set_defaults(early_stop=True, balance=True)
    return p.parse_args()


# ENTRY POINT
if __name__ == "__main__":
    main(parse_args())           # Parse CLI arguments and run the training pipeline
