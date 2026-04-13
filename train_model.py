#!/usr/bin/env python3
"""
===============================================================================
AI-WIDS Model Training Module
===============================================================================
Trains a Deep Neural Network to detect Wi-Fi attacks: Evil Twin and Deauth.

Pipeline:
  1. Load Features.csv (produced by extract_features.py)
  2. Balance classes via upsampling
  3. Split 80/20 train/test with stratification
  4. StandardScaler normalisation (fit on train, apply to test)
  5. Train 4-layer DNN for 50 epochs with dropout regularisation
  6. 5-fold cross-validation to verify generalisation
  7. Export classification report, ROC-AUC, confusion matrix, CV results
  8. Save model + scaler to wireless_ids.pt

Architecture rationale:
  - 128→64→32 neuron funnel forces compressed representations of ~35 features
  - Dropout(0.3) prevents overfitting on datasets where one feature dominates
  - ReLU avoids vanishing gradients in deeper layers
  - Output size = 3 (normal / evil_twin / deauth)
===============================================================================
"""

import os
import time

import joblib
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import seaborn as sns
import torch
import torch.nn as nn
import torch.optim as optim
from colorama import Back, Fore, Style, init
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    roc_auc_score,
)
from sklearn.model_selection import StratifiedKFold, train_test_split
from sklearn.preprocessing import StandardScaler, label_binarize
from sklearn.utils import resample
from torch.utils.data import DataLoader, TensorDataset
from tqdm import tqdm

init(autoreset=True)

# ── Labels ────────────────────────────────────────────────────────────────────
LABEL_MAP = {"normal": 0, "evil_twin": 1, "deauth": 2}
CLASS_NAMES = ["Normal", "Evil Twin", "Deauth"]
NUM_CLASSES = 3


# ── Neural Network ────────────────────────────────────────────────────────────
class WIDSDetector(nn.Module):
    """
    4-layer feedforward DNN for multi-class Wi-Fi attack detection.
    Detects: Normal (0), Evil Twin (1), Deauth/DoS (2).
    """

    def __init__(self, input_size: int):
        super().__init__()
        self.fc1 = nn.Linear(input_size, 128)
        self.fc2 = nn.Linear(128, 64)
        self.fc3 = nn.Linear(64, 32)
        self.fc4 = nn.Linear(32, NUM_CLASSES)
        self.relu = nn.ReLU()
        # 30% dropout: prevents co-adaptation on small datasets
        self.dropout = nn.Dropout(0.3)

    def forward(self, x):
        x = self.relu(self.fc1(x))
        x = self.dropout(x)
        x = self.relu(self.fc2(x))
        x = self.dropout(x)
        x = self.relu(self.fc3(x))
        return self.fc4(x)


# ── Visualisation ─────────────────────────────────────────────────────────────
def save_training_dashboard(history: dict, save_path: str = "../results"):
    os.makedirs(save_path, exist_ok=True)
    plt.style.use("seaborn-v0_8-darkgrid")
    fig, axes = plt.subplots(2, 2, figsize=(15, 10))

    # Loss curve
    axes[0, 0].plot(history["train_loss"], label="Train Loss", color="#FF6B6B", linewidth=2)
    axes[0, 0].set_title("Training Loss", fontsize=14, fontweight="bold")
    axes[0, 0].set_xlabel("Epoch")
    axes[0, 0].set_ylabel("Loss")
    axes[0, 0].legend()

    # Accuracy curves
    axes[0, 1].plot(history["train_acc"], label="Train Acc", color="#4ECDC4", linewidth=2)
    axes[0, 1].plot(history["val_acc"], label="Val Acc", color="#95E1D3", linewidth=2, linestyle="--")
    axes[0, 1].set_title("Accuracy", fontsize=14, fontweight="bold")
    axes[0, 1].set_xlabel("Epoch")
    axes[0, 1].set_ylabel("Accuracy (%)")
    axes[0, 1].legend()

    # Confusion matrix
    if "confusion_matrix" in history:
        sns.heatmap(
            history["confusion_matrix"],
            annot=True,
            fmt="d",
            cmap="Blues",
            ax=axes[1, 0],
            xticklabels=CLASS_NAMES,
            yticklabels=CLASS_NAMES,
        )
        axes[1, 0].set_title("Confusion Matrix", fontsize=14, fontweight="bold")
        axes[1, 0].set_xlabel("Predicted")
        axes[1, 0].set_ylabel("Actual")

    # Summary text
    axes[1, 1].axis("off")
    cv_line = ""
    if "cv_mean" in history:
        cv_line = f"\n    CV Accuracy:          {history['cv_mean']:.2f}% ± {history['cv_std']:.2f}%"
    summary = (
        f"    TRAINING SUMMARY\n"
        f"    {'═'*35}\n\n"
        f"    Final Train Acc:      {history['train_acc'][-1]:.2f}%\n"
        f"    Final Val Acc:        {history['val_acc'][-1]:.2f}%\n"
        f"    Best Val Acc:         {max(history['val_acc']):.2f}%\n"
        f"    Best Epoch:           {np.argmax(history['val_acc']) + 1}\n"
        f"    Final Loss:           {history['train_loss'][-1]:.4f}\n"
        f"    ROC-AUC (macro):      {history.get('roc_auc', 0):.4f}"
        f"{cv_line}\n\n"
        f"    Dataset Size:         {history.get('dataset_size', 'N/A')}\n"
        f"    Model Params:         {history.get('model_params', 'N/A'):,}\n"
        f"    Classes:              {', '.join(CLASS_NAMES)}\n"
    )
    axes[1, 1].text(0.05, 0.5, summary, fontsize=11, family="monospace", va="center")

    plt.tight_layout()
    out = os.path.join(save_path, "training_dashboard.png")
    plt.savefig(out, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"  ✓ Dashboard saved: {Fore.GREEN}{out}{Style.RESET_ALL}")


# ── Cross-validation ──────────────────────────────────────────────────────────
def run_cross_validation(X: np.ndarray, y: np.ndarray, input_size: int, save_path: str):
    """5-fold stratified CV to verify the model generalises."""
    print(f"\n{Fore.CYAN}Running 5-fold cross-validation...{Style.RESET_ALL}")
    kfold = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    fold_accs = []
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

    for fold, (tr_idx, val_idx) in enumerate(kfold.split(X, y)):
        X_tr, X_val = X[tr_idx], X[val_idx]
        y_tr, y_val = y[tr_idx], y[val_idx]

        sc = StandardScaler()
        X_tr = sc.fit_transform(X_tr)
        X_val = sc.transform(X_val)

        model = WIDSDetector(input_size).to(device)
        opt = optim.Adam(model.parameters(), lr=0.001)
        crit = nn.CrossEntropyLoss()
        ds = DataLoader(
            TensorDataset(torch.FloatTensor(X_tr), torch.LongTensor(y_tr)),
            batch_size=64,
            shuffle=True,
        )

        model.train()
        for _ in range(20):
            for xb, yb in ds:
                xb, yb = xb.to(device), yb.to(device)
                opt.zero_grad()
                crit(model(xb), yb).backward()
                opt.step()

        model.eval()
        with torch.no_grad():
            out = model(torch.FloatTensor(X_val).to(device))
            preds = torch.max(out, 1)[1].cpu().numpy()
            acc = (preds == y_val).mean() * 100
            fold_accs.append(acc)
        print(f"  Fold {fold + 1}: {Fore.GREEN}{acc:.2f}%{Style.RESET_ALL}")

    mean, std = np.mean(fold_accs), np.std(fold_accs)
    print(f"  Mean CV Accuracy: {Fore.YELLOW}{mean:.2f}% ± {std:.2f}%{Style.RESET_ALL}\n")

    os.makedirs(save_path, exist_ok=True)
    with open(os.path.join(save_path, "cross_validation.txt"), "w") as f:
        for i, a in enumerate(fold_accs):
            f.write(f"Fold {i + 1}: {a:.2f}%\n")
        f.write(f"Mean: {mean:.2f}% ± {std:.2f}%\n")
    print(f"  ✓ CV results saved: {Fore.GREEN}{save_path}/cross_validation.txt{Style.RESET_ALL}")
    return mean, std


# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    print(f"\n{Back.MAGENTA}{Fore.WHITE} AI-WIDS MODEL TRAINING {Style.RESET_ALL}\n")

    # 1. Load data
    print(f"{Fore.CYAN}[1/7] Loading Features.csv...{Style.RESET_ALL}")
    df = pd.read_csv("../data/processed/Features.csv")
    print(f"  ✓ {Fore.GREEN}{len(df)}{Style.RESET_ALL} rows, {len(df.columns) - 1} features")

    # Show class distribution
    print(f"\n  Class distribution:")
    for label, count in df["label"].value_counts().items():
        print(f"    {label}: {Fore.YELLOW}{count}{Style.RESET_ALL}")

    # 2. Balance dataset
    print(f"\n{Fore.CYAN}[2/7] Balancing classes...{Style.RESET_ALL}")
    max_class = df["label"].value_counts().max()
    balanced = []
    for label in df["label"].unique():
        subset = df[df["label"] == label]
        upsampled = resample(subset, replace=True, n_samples=max_class, random_state=42)
        balanced.append(upsampled)
    df = pd.concat(balanced).sample(frac=1, random_state=42).reset_index(drop=True)
    print(f"  ✓ Balanced to {Fore.GREEN}{len(df)}{Style.RESET_ALL} samples ({max_class} per class)")

    # 3. Clean
    print(f"\n{Fore.CYAN}[3/7] Cleaning...{Style.RESET_ALL}")
    df = df.drop(columns=["ssid", "bssid"], errors="ignore")
    df = df.fillna(0)

    # 4. Prepare features and labels
    print(f"\n{Fore.CYAN}[4/7] Preparing features and labels...{Style.RESET_ALL}")
    X = df.drop("label", axis=1).values
    y = df["label"].map(LABEL_MAP).fillna(0).astype(int).values
    feature_names = list(df.drop("label", axis=1).columns)

    print(f"  ✓ Feature matrix: {Fore.GREEN}{X.shape}{Style.RESET_ALL}")
    for name, idx in LABEL_MAP.items():
        print(f"    {name} ({idx}): {np.sum(y == idx)}")

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    scaler = StandardScaler()
    X_train = scaler.fit_transform(X_train)
    X_test = scaler.transform(X_test)

    print(f"  ✓ Train: {X_train.shape} | Test: {X_test.shape}")

    # 5. DataLoaders
    print(f"\n{Fore.CYAN}[5/7] Creating DataLoaders...{Style.RESET_ALL}")
    train_loader = DataLoader(
        TensorDataset(torch.FloatTensor(X_train), torch.LongTensor(y_train)),
        batch_size=64,
        shuffle=True,
    )
    test_loader = DataLoader(
        TensorDataset(torch.FloatTensor(X_test), torch.LongTensor(y_test)),
        batch_size=64,
        shuffle=False,
    )

    # 6. Train
    print(f"\n{Fore.CYAN}[6/7] Training...{Style.RESET_ALL}")
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"  Device: {Fore.YELLOW}{device}{Style.RESET_ALL}")

    model = WIDSDetector(X.shape[1]).to(device)
    criterion = nn.CrossEntropyLoss()
    optimizer = optim.Adam(model.parameters(), lr=0.001)
    total_params = sum(p.numel() for p in model.parameters())
    print(f"  Parameters: {Fore.GREEN}{total_params:,}{Style.RESET_ALL}\n")

    history = {
        "train_loss": [],
        "train_acc": [],
        "val_acc": [],
        "model_params": total_params,
        "dataset_size": len(df),
    }

    for epoch in range(50):
        model.train()
        train_loss = 0
        for xb, yb in tqdm(train_loader, desc=f"  Epoch {epoch + 1:02d}/50", leave=False):
            xb, yb = xb.to(device), yb.to(device)
            optimizer.zero_grad()
            loss = criterion(model(xb), yb)
            loss.backward()
            optimizer.step()
            train_loss += loss.item()

        model.eval()
        tr_correct = val_correct = tr_total = val_total = 0
        with torch.no_grad():
            for xb, yb in train_loader:
                out = model(xb.to(device))
                pred = torch.max(out, 1)[1]
                tr_total += yb.size(0)
                tr_correct += (pred.cpu() == yb).sum().item()
            for xb, yb in test_loader:
                out = model(xb.to(device))
                pred = torch.max(out, 1)[1]
                val_total += yb.size(0)
                val_correct += (pred.cpu() == yb).sum().item()

        tr_acc = 100 * tr_correct / tr_total
        val_acc = 100 * val_correct / val_total
        avg_loss = train_loss / len(train_loader)

        history["train_loss"].append(avg_loss)
        history["train_acc"].append(tr_acc)
        history["val_acc"].append(val_acc)

        print(
            f"  Epoch {epoch + 1:02d}: Loss {avg_loss:.4f} | "
            f"Train {Fore.GREEN}{tr_acc:.2f}%{Style.RESET_ALL} | "
            f"Val {Fore.CYAN}{val_acc:.2f}%{Style.RESET_ALL}"
        )

    # 7. Evaluate and save
    print(f"\n{Fore.CYAN}[7/7] Evaluating and saving...{Style.RESET_ALL}")
    model.eval()
    all_preds, all_labels, all_probs = [], [], []

    with torch.no_grad():
        for xb, yb in test_loader:
            out = model(xb.to(device))
            probs = torch.softmax(out, dim=1).cpu().numpy()
            preds = np.argmax(probs, axis=1)
            all_preds.extend(preds)
            all_labels.extend(yb.numpy())
            all_probs.extend(probs)

    all_probs = np.array(all_probs)
    all_preds = np.array(all_preds)
    all_labels = np.array(all_labels)

    cm = confusion_matrix(all_labels, all_preds)
    history["confusion_matrix"] = cm

    report = classification_report(all_labels, all_preds, target_names=CLASS_NAMES)
    print(f"\n{report}")

    # ROC-AUC (one-vs-rest, macro average)
    y_bin = label_binarize(all_labels, classes=list(range(NUM_CLASSES)))
    # Only compute AUC for classes that actually appear in test set
    present = np.unique(all_labels)
    if len(present) >= 2:
        auc = roc_auc_score(y_bin[:, present], all_probs[:, present], multi_class="ovr", average="macro")
    else:
        auc = 0.0
    history["roc_auc"] = auc
    print(f"  ROC-AUC (macro): {Fore.GREEN}{auc:.4f}{Style.RESET_ALL}")

    # Cross-validation
    cv_mean, cv_std = run_cross_validation(
        scaler.inverse_transform(X_train), y_train, X.shape[1], "../results"
    )
    history["cv_mean"] = cv_mean
    history["cv_std"] = cv_std

    # Save results
    os.makedirs("../results", exist_ok=True)
    with open("../results/classification_report.txt", "w") as f:
        f.write(report)

    with open("../results/metrics_summary.txt", "w") as f:
        f.write(f"Final Val Accuracy:    {history['val_acc'][-1]:.2f}%\n")
        f.write(f"Best Val Accuracy:     {max(history['val_acc']):.2f}%\n")
        f.write(f"ROC-AUC (macro OvR):   {auc:.4f}\n")
        f.write(f"CV Accuracy:           {cv_mean:.2f}% ± {cv_std:.2f}%\n")
        f.write(f"Dataset Size:          {len(df)}\n")
        f.write(f"Classes:               {', '.join(CLASS_NAMES)}\n")

    print(f"  ✓ {Fore.GREEN}../results/classification_report.txt{Style.RESET_ALL}")
    print(f"  ✓ {Fore.GREEN}../results/metrics_summary.txt{Style.RESET_ALL}")

    # Save 500-row sample CSV for repo evidence
    sample_path = "../data/processed/Features_sample.csv"
    df_orig = pd.read_csv("../data/processed/Features.csv")
    df_orig.sample(min(500, len(df_orig)), random_state=42).to_csv(sample_path, index=False)
    print(f"  ✓ {Fore.GREEN}{sample_path}{Style.RESET_ALL} (500-row sample for repo)")

    # Save model
    torch.save(
        {
            "model_state_dict": model.state_dict(),
            "scaler": scaler,
            "feature_order": feature_names,
            "num_classes": NUM_CLASSES,
            "label_map": LABEL_MAP,
            "class_names": CLASS_NAMES,
        },
        "../data/models/wireless_ids.pt",
    )
    print(f"  ✓ {Fore.GREEN}../data/models/wireless_ids.pt{Style.RESET_ALL}")

    save_training_dashboard(history)

    print(f"\n{Back.GREEN}{Fore.BLACK} TRAINING COMPLETE {Style.RESET_ALL}")
    print(f"\n  Best val accuracy: {Fore.GREEN}{max(history['val_acc']):.2f}%{Style.RESET_ALL}")
    print(f"  ROC-AUC:           {Fore.GREEN}{auc:.4f}{Style.RESET_ALL}")
    print(f"  CV Accuracy:       {Fore.GREEN}{cv_mean:.2f}% ± {cv_std:.2f}%{Style.RESET_ALL}")
    print(f"\n{Fore.GREEN}Next: python src/live_detection.py{Style.RESET_ALL}\n")


if __name__ == "__main__":
    main()
