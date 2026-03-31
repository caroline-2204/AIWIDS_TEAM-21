#!/usr/bin/env python3
"""
===============================================================================
AI-WIDS Model Training Module - IMPROVED VERSION WITH VISUALIZATION
===============================================================================
Purpose: Train Deep Neural Network for Evil Twin detection with live metrics
Input:   ../data/processed/Features.csv (AWID3-style features)
Output:  ../data/model/wireless_ids.pt (trained PyTorch model)
Features: Real-time training dashboard, plots, metrics logging
===============================================================================
"""

# ===========================
# IMPORTS
# ===========================
import torch                                 # PyTorch deep learning framework
import torch.nn as nn                        # Neural network modules
import torch.optim as optim                  # Optimization algorithms
from torch.utils.data import DataLoader, TensorDataset  # Data loading utilities
import pandas as pd                          # DataFrame operations
import numpy as np                           # Numerical computing
from sklearn.model_selection import train_test_split  # Train/test splitting
from sklearn.preprocessing import StandardScaler      # Feature scaling
from sklearn.utils import resample          # Dataset resampling
from sklearn.metrics import confusion_matrix, classification_report, roc_auc_score  # Metrics
import matplotlib.pyplot as plt              # Plotting library
import seaborn as sns                        # Statistical visualization
import os                                    # File system operations
from tqdm import tqdm                        # Progress bars
import colorama                              # Colored console output
from colorama import Fore, Style, Back       # Color constants
colorama.init(autoreset=True)                # Initialize colorama


# TODO: Change to make it predict multiple classes 
# ===========================
# NEURAL NETWORK ARCHITECTURE
# ===========================
class EvilTwinDetector(nn.Module): # TODO: IntrusionDetector
    """
    Deep Neural Network for Evil Twin Attack Detection
    Architecture: 4-layer feedforward network with dropout regularization
    """
    def __init__(self, input_size):
        """
        Initialize network layers
        Args:
            input_size (int): Number of input features (e.g., 40)
        """
        super().__init__()                   # Call parent class constructor
        # Layer 1: Input → 128 neurons
        self.fc1 = nn.Linear(input_size, 128)            # Fully connected layer
        # Layer 2: 128 → 64 neurons
        self.fc2 = nn.Linear(128, 64)                    # Hidden layer
        # Layer 3: 64 → 32 neurons
        self.fc3 = nn.Linear(64, 32)                     # Hidden layer
        # Layer 4: 32 → 2 neurons (normal vs evil_twin)
        self.fc4 = nn.Linear(32, 2)                      # Output layer (2 classes)
        # Activation function (introduces non-linearity)
        self.relu = nn.ReLU()                            # Rectified Linear Unit
        # Dropout for regularization (prevents overfitting)
        self.dropout = nn.Dropout(0.3)                   # Drop 30% of neurons during training

    def forward(self, x):
        """
        Forward pass through network
        Args:
            x (torch.Tensor): Input features [batch_size, input_size]
        Returns:
            torch.Tensor: Output logits [batch_size, 2]
        """
        x = self.relu(self.fc1(x))           # Layer 1 → ReLU activation
        x = self.dropout(x)                  # Apply dropout
        x = self.relu(self.fc2(x))           # Layer 2 → ReLU activation
        x = self.dropout(x)                  # Apply dropout
        x = self.relu(self.fc3(x))           # Layer 3 → ReLU activation
        x = self.fc4(x)                      # Layer 4 (no activation, raw logits)
        return x                             # Return output logits

# ===========================
# TRAINING VISUALIZATION FUNCTION
# ===========================
def plot_training_metrics(history, save_path="../dashboard"):
    """
    Create comprehensive training visualization dashboard
    Args:
        history (dict): Training history with loss and accuracy
        save_path (str): Directory to save plots
    """
    # Create output directory if it doesn't exist
    os.makedirs(save_path, exist_ok=True)    # Create directory recursively
    # Set plot style
    plt.style.use('seaborn-v0_8-darkgrid')   # Use seaborn style for better aesthetics

    # ===========================
    # PLOT 1: Loss Curve
    # ===========================
    fig, axes = plt.subplots(2, 2, figsize=(15, 10))  # 2x2 grid of subplots
    # Training Loss
    axes[0, 0].plot(history['train_loss'], label='Train Loss', color='#FF6B6B', linewidth=2)  # Red line
    axes[0, 0].set_title('Training Loss Over Time', fontsize=14, fontweight='bold')
    axes[0, 0].set_xlabel('Epoch', fontsize=12)            # X-axis label
    axes[0, 0].set_ylabel('Loss', fontsize=12)             # Y-axis label
    axes[0, 0].legend(loc='upper right')                   # Add legend
    axes[0, 0].grid(True, alpha=0.3)                       # Add grid lines

    # ===========================
    # PLOT 2: Accuracy Curve
    # ===========================
    axes[0, 1].plot(history['train_acc'], label='Train Accuracy', color='#4ECDC4', linewidth=2)  # Teal line
    axes[0, 1].plot(history['val_acc'], label='Val Accuracy', color='#95E1D3', linewidth=2, linestyle='--')  # Light teal dashed
    axes[0, 1].set_title('Accuracy Over Time', fontsize=14, fontweight='bold')
    axes[0, 1].set_xlabel('Epoch', fontsize=12)
    axes[0, 1].set_ylabel('Accuracy (%)', fontsize=12)
    axes[0, 1].legend(loc='lower right')                   # Legend in bottom right
    axes[0, 1].grid(True, alpha=0.3)

    # ===========================
    # PLOT 3: Confusion Matrix (Last Epoch)
    # ===========================
    if 'confusion_matrix' in history:
        cm = history['confusion_matrix']                   # Get confusion matrix
        sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', ax=axes[1, 0],  # Heatmap visualization
                   xticklabels=['Normal', 'Evil Twin'],    # X-axis labels
                   yticklabels=['Normal', 'Evil Twin'])    # Y-axis labels
        axes[1, 0].set_title('Confusion Matrix (Final Epoch)', fontsize=14, fontweight='bold')
        axes[1, 0].set_xlabel('Predicted', fontsize=12)
        axes[1, 0].set_ylabel('Actual', fontsize=12)

    # ===========================
    # PLOT 4: Training Summary
    # ===========================
    axes[1, 1].axis('off')                   # Turn off axis for text display

    # Prepare summary text
    summary_text = f"""
    TRAINING SUMMARY
    ═══════════════════════════════════

    Final Train Accuracy: {history['train_acc'][-1]:.2f}%
    Final Val Accuracy:   {history['val_acc'][-1]:.2f}%

    Best Val Accuracy:    {max(history['val_acc']):.2f}%
    Best Epoch:           {np.argmax(history['val_acc'])+1}

    Final Loss:           {history['train_loss'][-1]:.4f}
    Total Epochs:         {len(history['train_loss'])}

    Model Size:           {history.get('model_params', 'N/A')} params
    Dataset Size:         {history.get('dataset_size', 'N/A')} samples
    """

    # Display text
    axes[1, 1].text(0.1, 0.5, summary_text, fontsize=11, family='monospace',
                   verticalalignment='center')           # Center text vertically

    # Save figure
    plt.tight_layout()                       # Adjust spacing between subplots
    output_file = os.path.join(save_path, 'training_dashboard.png')
    plt.savefig(output_file, dpi=150, bbox_inches='tight')  # Save high-res image
    plt.close()                              # Close figure to free memory

    print(f"  ✓ Saved dashboard: {Fore.GREEN}{output_file}{Style.RESET_ALL}")

# ===========================
# MAIN TRAINING FUNCTION
# ===========================
def main():
    """
    Main training pipeline with comprehensive logging and visualization
    """
    # Print header
    print(f"\n{Back.MAGENTA}{Fore.WHITE} AI-WIDS MODEL TRAINING - IMPROVED VERSION {Style.RESET_ALL}\n")

    # ===========================
    # STEP 1: LOAD DATA
    # ===========================
    print(f"{Fore.CYAN}[1/6] Loading Features.csv...{Style.RESET_ALL}")

    df = pd.read_csv("../data/processed/Features.csv")    # Load features from CSV
    print(f"  ✓ Loaded: {Fore.GREEN}{len(df)}{Style.RESET_ALL} rows")
    print(f"  ✓ Features: {Fore.GREEN}{len(df.columns)-1}{Style.RESET_ALL} (excluding label)\n")

    # ===========================
    # STEP 2: BALANCE DATASET
    # ===========================
    print(f"{Fore.CYAN}[2/6] Balancing dataset...{Style.RESET_ALL}")

    # Separate majority and minority classes
    df_majority = df[df.label == 'normal']                # Normal traffic
    df_minority = df[df.label == 'evil_twin']             # Evil twin attacks

    print(f"  • Normal: {Fore.GREEN}{len(df_majority)}{Style.RESET_ALL}")
    print(f"  • Evil Twin: {Fore.RED}{len(df_minority)}{Style.RESET_ALL}")

    # Upsample minority class to match majority
    df_minority_upsampled = resample(
        df_minority,                         # Minority class DataFrame
        replace=True,                        # Sample with replacement
        n_samples=len(df_majority),          # Match majority class size
        random_state=42                      # Reproducible results
    )

    # Combine balanced classes
    df = pd.concat([df_majority, df_minority_upsampled])  # Merge DataFrames

    print(f"  ✓ Balanced: {Fore.YELLOW}{len(df)}{Style.RESET_ALL} total samples\n")

    # ===========================
    # STEP 3: CLEAN DATA
    # ===========================
    print(f"{Fore.CYAN}[3/6] Cleaning data...{Style.RESET_ALL}")

    # Remove non-numeric columns
    df = df.drop(columns=['ssid'], errors='ignore')       # Drop SSID text column

    # Handle missing values
    df = df.fillna(0)                        # Replace NaN with 0

    print(f"  ✓ Removed text columns")
    print(f"  ✓ Filled missing values\n")

    # ===========================
    # STEP 4: PREPARE FEATURES AND LABELS
    # ===========================
    print(f"{Fore.CYAN}[4/6] Preparing features and labels...{Style.RESET_ALL}")

    # Extract feature matrix (X) and labels (y)
    X = df.drop('label', axis=1).values                   # All columns except 'label'
    y = (df['label'] == 'evil_twin').astype(int).values   # Binary labels (0=normal, 1=evil_twin)

    print(f"  ✓ Feature matrix: {Fore.GREEN}{X.shape}{Style.RESET_ALL}")
    print(f"  ✓ Label distribution:")
    print(f"    • Normal (0): {Fore.GREEN}{np.sum(y==0)}{Style.RESET_ALL}")
    print(f"    • Evil Twin (1): {Fore.RED}{np.sum(y==1)}{Style.RESET_ALL}\n")

    # Split into train/test sets (80/20 split)
    X_train, X_test, y_train, y_test = train_test_split(
        X, y,                                # Features and labels
        test_size=0.2,                       # 20% for testing
        random_state=42,                     # Reproducible split
        stratify=y                           # Maintain class balance
    )

    # Standardize features (mean=0, std=1)
    scaler = StandardScaler()                # Initialize scaler
    X_train = scaler.fit_transform(X_train)  # Fit to training data and transform
    X_test = scaler.transform(X_test)        # Transform test data (no fitting)

    print(f"  ✓ Train set: {Fore.GREEN}{X_train.shape}{Style.RESET_ALL}")
    print(f"  ✓ Test set: {Fore.GREEN}{X_test.shape}{Style.RESET_ALL}\n")

    # ===========================
    # STEP 5: CREATE DATALOADERS
    # ===========================
    print(f"{Fore.CYAN}[5/6] Creating PyTorch DataLoaders...{Style.RESET_ALL}")

    # Convert NumPy arrays to PyTorch tensors
    train_dataset = TensorDataset(
        torch.FloatTensor(X_train),          # Features as float32 tensor
        torch.LongTensor(y_train)            # Labels as int64 tensor
    )

    test_dataset = TensorDataset(
        torch.FloatTensor(X_test),           # Test features
        torch.LongTensor(y_test)             # Test labels
    )

    # Create data loaders for batching
    train_loader = DataLoader(
        train_dataset,                       # Training dataset
        batch_size=64,                       # Process 64 samples at a time
        shuffle=True                         # Shuffle each epoch
    )

    test_loader = DataLoader(
        test_dataset,                        # Test dataset
        batch_size=64,                       # Same batch size
        shuffle=False                        # Don't shuffle test data
    )

    print(f"  ✓ Batch size: {Fore.YELLOW}64{Style.RESET_ALL}")
    print(f"  ✓ Train batches: {Fore.GREEN}{len(train_loader)}{Style.RESET_ALL}")
    print(f"  ✓ Test batches: {Fore.GREEN}{len(test_loader)}{Style.RESET_ALL}\n")

    # ===========================
    # STEP 6: INITIALIZE MODEL
    # ===========================
    print(f"{Fore.CYAN}[6/6] Initializing model and training...{Style.RESET_ALL}\n")

    # Detect GPU/CPU
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"  • Device: {Fore.YELLOW}{device}{Style.RESET_ALL}")

    # Create model instance
    model = EvilTwinDetector(X.shape[1]).to(device)       # Move model to GPU/CPU

    # Define loss function (Cross Entropy for classification)
    criterion = nn.CrossEntropyLoss()                     # Combines softmax + NLL loss

    # Define optimizer (Adam with learning rate 0.001)
    optimizer = optim.Adam(model.parameters(), lr=0.001)  # Adaptive learning rate

    # Count total parameters
    total_params = sum(p.numel() for p in model.parameters())
    print(f"  • Parameters: {Fore.GREEN}{total_params:,}{Style.RESET_ALL}\n")

    # Training history for visualization
    history = {
        'train_loss': [],                    # Loss per epoch
        'train_acc': [],                     # Train accuracy per epoch
        'val_acc': [],                       # Validation accuracy per epoch
        'model_params': total_params,        # Total parameters
        'dataset_size': len(df)              # Dataset size
    }

    # ===========================
    # TRAINING LOOP
    # ===========================
    print(f"{Fore.YELLOW}Training for 50 epochs...{Style.RESET_ALL}\n")

    for epoch in range(50):                  # Train for 50 epochs

        # ─────────────────────────
        # TRAINING PHASE
        # ─────────────────────────
        model.train()                        # Set model to training mode (enables dropout)
        train_loss = 0                       # Accumulate loss for this epoch

        # Process each batch with progress bar
        for X_batch, y_batch in tqdm(train_loader, desc=f"  Epoch {epoch+1:02d}/50", leave=False):
            # Move batch to device
            X_batch, y_batch = X_batch.to(device), y_batch.to(device)
            # Zero gradients from previous batch
            optimizer.zero_grad()            # Clear accumulated gradients
            # Forward pass
            outputs = model(X_batch)         # Get predictions
            # Compute loss
            loss = criterion(outputs, y_batch)  # Compare predictions to labels
            # Backward pass
            loss.backward()                  # Compute gradients
            # Update weights
            optimizer.step()                 # Apply gradients
            # Accumulate loss
            train_loss += loss.item()        # Add batch loss to total

        # Average loss over all batches
        avg_train_loss = train_loss / len(train_loader)

        # ─────────────────────────
        # VALIDATION PHASE
        # ─────────────────────────
        model.eval()                         # Set model to evaluation mode (disables dropout)

        train_correct = 0                    # Count correct predictions (train)
        train_total = 0                      # Total samples (train)
        val_correct = 0                      # Count correct predictions (val)
        val_total = 0                        # Total samples (val)

        # Evaluate on training set
        with torch.no_grad():                # Disable gradient computation
            for X_batch, y_batch in train_loader:
                X_batch, y_batch = X_batch.to(device), y_batch.to(device)
                outputs = model(X_batch)     # Get predictions
                _, predicted = torch.max(outputs, 1)  # Get class with highest score
                train_total += y_batch.size(0)        # Add batch size
                train_correct += (predicted == y_batch).sum().item()  # Count correct

        # Evaluate on test set
        with torch.no_grad():
            for X_batch, y_batch in test_loader:
                X_batch, y_batch = X_batch.to(device), y_batch.to(device)
                outputs = model(X_batch)
                _, predicted = torch.max(outputs, 1)
                val_total += y_batch.size(0)
                val_correct += (predicted == y_batch).sum().item()

        # Calculate accuracies
        train_acc = 100 * train_correct / train_total
        val_acc = 100 * val_correct / val_total

        # Store metrics in history
        history['train_loss'].append(avg_train_loss)
        history['train_acc'].append(train_acc)
        history['val_acc'].append(val_acc)

        # Print epoch summary
        print(f"  Epoch {epoch+1:02d}: Loss {avg_train_loss:.4f} | "
              f"Train Acc {Fore.GREEN}{train_acc:.2f}%{Style.RESET_ALL} | "
              f"Val Acc {Fore.CYAN}{val_acc:.2f}%{Style.RESET_ALL}")

    # ===========================
    # POST-TRAINING EVALUATION
    # ===========================
    print(f"\n{Fore.CYAN}Generating final evaluation...{Style.RESET_ALL}")

    # Get final confusion matrix
    model.eval()
    all_preds = []
    all_labels = []

    with torch.no_grad():
        for X_batch, y_batch in test_loader:
            X_batch = X_batch.to(device)
            outputs = model(X_batch)
            _, predicted = torch.max(outputs, 1)
            all_preds.extend(predicted.cpu().numpy())
            all_labels.extend(y_batch.numpy())

    # Compute confusion matrix
    cm = confusion_matrix(all_labels, all_preds)
    history['confusion_matrix'] = cm

    # ===========================
    # SAVE MODEL
    # ===========================
    print(f"\n{Fore.CYAN}Saving model...{Style.RESET_ALL}")

    torch.save({
        'model_state_dict': model.state_dict(),           # Model weights
        'scaler': scaler,                                 # Feature scaler
        'feature_order': list(df.drop('label', axis=1).columns)  # Feature names
    }, "../data/model/wireless_ids.pt")                   # Save to file

    print(f"  ✓ Model saved: {Fore.GREEN}../data/model/wireless_ids.pt{Style.RESET_ALL}\n")

    # ===========================
    # CREATE VISUALIZATION
    # ===========================
    print(f"{Fore.CYAN}Creating training dashboard...{Style.RESET_ALL}")
    plot_training_metrics(history)

    # Final summary
    print(f"\n{Back.GREEN}{Fore.BLACK} TRAINING COMPLETE {Style.RESET_ALL}")
    print(f"\n{Fore.GREEN}Next: ./live_detection.py{Style.RESET_ALL}\n")

# ===========================
# ENTRY POINT
# ===========================
if __name__ == "__main__":
    main()

