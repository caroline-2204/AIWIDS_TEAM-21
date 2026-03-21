#!/usr/bin/env python3
"""
train_model.py
Train Deep Neural Network for Evil Twin detection
Input: ../data/processed/Features.csv (AWID3-style)
Output: ../data/model/wireless_ids.pt
"""

import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import DataLoader, TensorDataset
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
import joblib
from sklearn.utils import resample

class EvilTwinDetector(nn.Module):
    def __init__(self, input_size):
        super().__init__()
        self.fc1 = nn.Linear(input_size, 128)
        self.fc2 = nn.Linear(128, 64)
        self.fc3 = nn.Linear(64, 32)
        self.fc4 = nn.Linear(32, 2)  # normal vs evil_twin
        self.relu = nn.ReLU()
        self.dropout = nn.Dropout(0.3)

    def forward(self, x):
        x = self.relu(self.fc1(x))
        x = self.dropout(x)
        x = self.relu(self.fc2(x))
        x = self.dropout(x)
        x = self.relu(self.fc3(x))
        x = self.fc4(x)
        return x

def main():
    # Load data
    df = pd.read_csv("../data/processed/Features.csv")
    # Balance dataset
    df_majority = df[df.label == 'normal']
    df_minority = df[df.label == 'evil_twin']

    df_minority_upsampled = resample(
        df_minority,
        replace=True,
        n_samples=len(df_majority),
        random_state=42
    )
    df = pd.concat([df_majority, df_minority_upsampled])

    # Prepare features and labels
    # X = df.drop('label', axis=1).values
    # y = (df['label'] == 'evil_twin').astype(int).values

    # Clean Data
    df = df.drop(columns=['ssid'], errors='ignore')  # remove text column
    df = df.fillna(0)  # handle missing values
    # Prepare features and labels
    X = df.drop('label', axis=1).values
    y = (df['label'] == 'evil_twin').astype(int).values
    
    print(df['label'].value_counts())

    # Split and scale
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    scaler = StandardScaler()
    X_train = scaler.fit_transform(X_train)
    X_test = scaler.transform(X_test)

    # PyTorch datasets
    train_dataset = TensorDataset(torch.FloatTensor(X_train), torch.LongTensor(y_train))
    test_dataset = TensorDataset(torch.FloatTensor(X_test), torch.LongTensor(y_test))

    train_loader = DataLoader(train_dataset, batch_size=64, shuffle=True)
    test_loader = DataLoader(test_dataset, batch_size=64)

    # Model, loss, optimizer
    # model = EvilTwinDetector(X.shape[1]).cuda()
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    model = EvilTwinDetector(X.shape[1]).to(device)

    criterion = nn.CrossEntropyLoss()
    optimizer = optim.Adam(model.parameters(), lr=0.001)

    # Training loop
    for epoch in range(50):
        model.train()
        train_loss = 0
        for X_batch, y_batch in train_loader:
            # X_batch, y_batch = X_batch.cuda(), y_batch.cuda()

            X_batch, y_batch = X_batch.to(device), y_batch.to(device)
            optimizer.zero_grad()
            outputs = model(X_batch)
            loss = criterion(outputs, y_batch)
            loss.backward()
            optimizer.step()
            train_loss += loss.item()

        # Validation
        model.eval()
        correct = 0
        total = 0
        with torch.no_grad():
            for X_batch, y_batch in test_loader:
                # X_batch, y_batch = X_batch.cuda(), y_batch.cuda()

                X_batch, y_batch = X_batch.to(device), y_batch.to(device)
                outputs = model(X_batch)
                _, predicted = torch.max(outputs, 1)
                total += y_batch.size(0)
                correct += (predicted == y_batch).sum().item()

        print(f"Epoch {epoch+1}: Loss {train_loss/len(train_loader):.4f}, Acc {100*correct/total:.2f}%")

    # Save model
    torch.save({
        'model_state_dict': model.state_dict(),
        'scaler': scaler
    }, "../data/model/wireless_ids.pt")

    print("✅ Model saved: data/model/wireless_ids.pt")

if __name__ == "__main__":
    main()

