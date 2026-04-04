#!/usr/bin/env python3
"""
===============================================================================
AI-WIDS Model Training Module
===============================================================================
"""

import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import DataLoader, TensorDataset
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.utils import resample
from sklearn.metrics import confusion_matrix
import matplotlib.pyplot as plt
import seaborn as sns
import os
from tqdm import tqdm
import colorama
from colorama import Fore, Style, Back

colorama.init(autoreset=True)

class EvilTwinDetector(nn.Module):
    def __init__(self, input_size):
        super().__init__()
        self.fc1 = nn.Linear(input_size, 128)
        self.fc2 = nn.Linear(128, 64)
        self.fc3 = nn.Linear(64, 32)
        self.fc4 = nn.Linear(32, 2)
        self.relu = nn.ReLU()
        self.dropout = nn.Dropout(0.3)

    def forward(self, x):
        x = self.relu(self.fc1(x))
        x = self.dropout(x)
        x = self.relu(self.fc2(x))
        x = self.dropout(x)
        x = self.relu(self.fc3(x))
        return self.fc4(x)

def plot_training_metrics(history, save_path="../results"):
    os.makedirs(save_path, exist_ok=True)
    plt.style.use('seaborn-v0_8-darkgrid')
    fig, axes = plt.subplots(2, 2, figsize=(15, 10))
    
    axes[0, 0].plot(history['train_loss'], label='Train Loss', color='#FF6B6B', linewidth=2)
    axes[0, 0].set_title('Training Loss Over Time', fontsize=14, fontweight='bold')
    axes[0, 0].legend(loc='upper right')
    
    axes[0, 1].plot(history['train_acc'], label='Train Accuracy', color='#4ECDC4', linewidth=2)
    axes[0, 1].plot(history['val_acc'], label='Val Accuracy', color='#95E1D3', linewidth=2, linestyle='--')
    axes[0, 1].set_title('Accuracy Over Time', fontsize=14, fontweight='bold')
    axes[0, 1].legend(loc='lower right')

    if 'confusion_matrix' in history:
        sns.heatmap(history['confusion_matrix'], annot=True, fmt='d', cmap='Blues', ax=axes[1, 0],
                   xticklabels=['Normal', 'Evil Twin'], yticklabels=['Normal', 'Evil Twin'])
        axes[1, 0].set_title('Confusion Matrix (Final Epoch)', fontsize=14, fontweight='bold')

    axes[1, 1].axis('off')
    summary_text = f"""
    TRAINING SUMMARY
    ═══════════════════════════════════
    Final Train Accuracy: {history['train_acc'][-1]:.2f}%
    Final Val Accuracy:   {history['val_acc'][-1]:.2f}%
    Model Size:           {history.get('model_params', 'N/A')} params
    Dataset Size:         {history.get('dataset_size', 'N/A')} samples
    """
    axes[1, 1].text(0.1, 0.5, summary_text, fontsize=11, family='monospace', verticalalignment='center')
    plt.tight_layout()
    plt.savefig(os.path.join(save_path, 'training_dashboard.png'), dpi=150, bbox_inches='tight')
    plt.close()

def main():
    print(f"\n{Back.MAGENTA}{Fore.WHITE} AI-WIDS MODEL TRAINING {Style.RESET_ALL}\n")
    df = pd.read_csv("../data/processed/Features.csv")
    
    df_majority = df[df.label == 'normal']
    df_minority = df[df.label == 'evil_twin']
    
    if len(df_minority) > 0:
        df_minority_upsampled = resample(df_minority, replace=True, n_samples=len(df_majority), random_state=42)
        df = pd.concat([df_majority, df_minority_upsampled])
    
    df = df.drop(columns=['ssid'], errors='ignore').fillna(0)
    
    X = df.drop('label', axis=1).values
    y = (df['label'] == 'evil_twin').astype(int).values
    
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
    scaler = StandardScaler()
    X_train = scaler.fit_transform(X_train)
    X_test = scaler.transform(X_test)
    
    train_loader = DataLoader(TensorDataset(torch.FloatTensor(X_train), torch.LongTensor(y_train)), batch_size=64, shuffle=True)
    test_loader = DataLoader(TensorDataset(torch.FloatTensor(X_test), torch.LongTensor(y_test)), batch_size=64, shuffle=False)
    
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    model = EvilTwinDetector(X.shape[1]).to(device)
    criterion = nn.CrossEntropyLoss()
    optimizer = optim.Adam(model.parameters(), lr=0.001)
    
    history = {'train_loss': [], 'train_acc': [], 'val_acc': [], 'model_params': sum(p.numel() for p in model.parameters()), 'dataset_size': len(df)}
    
    for epoch in range(50):
        model.train()
        train_loss = 0
        for X_batch, y_batch in tqdm(train_loader, desc=f"Epoch {epoch+1:02d}/50", leave=False):
            X_batch, y_batch = X_batch.to(device), y_batch.to(device)
            optimizer.zero_grad()
            loss = criterion(model(X_batch), y_batch)
            loss.backward()
            optimizer.step()
            train_loss += loss.item()
            
        model.eval()
        val_correct, val_total = 0, 0
        with torch.no_grad():
            for X_batch, y_batch in test_loader:
                X_batch, y_batch = X_batch.to(device), y_batch.to(device)
                _, predicted = torch.max(model(X_batch), 1)
                val_total += y_batch.size(0)
                val_correct += (predicted == y_batch).sum().item()
                
        history['train_loss'].append(train_loss / len(train_loader))
        history['train_acc'].append(0) # Simplified for space
        history['val_acc'].append(100 * val_correct / val_total)
        
    model.eval()
    all_preds, all_labels = [], []
    with torch.no_grad():
        for X_batch, y_batch in test_loader:
            _, predicted = torch.max(model(X_batch.to(device)), 1)
            all_preds.extend(predicted.cpu().numpy())
            all_labels.extend(y_batch.numpy())
            
    history['confusion_matrix'] = confusion_matrix(all_labels, all_preds)
    
    os.makedirs("../data/model", exist_ok=True)
    torch.save({'model_state_dict': model.state_dict(), 'scaler': scaler, 'feature_order': list(df.drop('label', axis=1).columns)}, "../data/model/wireless_ids.pt")
    plot_training_metrics(history)
    print(f"\n{Back.GREEN}{Fore.BLACK} TRAINING COMPLETE {Style.RESET_ALL}")

if __name__ == "__main__":
    main()
