#!/usr/bin/env python3
"""
train_pytorch.py

Train a PyTorch intrusion detection model on preprocessed data.

Features:
- Supports multiple model architectures (MLP, CNN, LSTM)
- Early stopping to prevent overfitting
- Comprehensive evaluation metrics
- Model checkpointing

Usage:
    python train_pytorch.py --data-dir data/processed \
                            --model mlp \
                            --epochs 30 \
                            --output-model data/models/wifi_ids_model.pt
"""

# Standard library imports
import argparse
from pathlib import Path

# Third-party imports for ML
import numpy as np  # Numerical operations
import torch  # PyTorch core
from sklearn.metrics import (  # Evaluation metrics
    classification_report,
    confusion_matrix,
    roc_auc_score
)
from torch.utils.data import DataLoader, TensorDataset  # Data loading utilities

# Import model architectures from models.py
from models import WifiIDSMLP, WifiIDSCNN, WifiIDSLSTM


def create_model(model_type: str, input_dim: int):
    """
    Factory function to create model instance based on type.

    Args:
        model_type (str): Model architecture ("mlp", "cnn", or "lstm")
        input_dim (int): Number of input features

    Returns:
        nn.Module: Instantiated PyTorch model

    Raises:
        ValueError: If model_type is not recognized
    """
    # Check model type and return appropriate instance
    if model_type == "mlp":
        # Create Multi-Layer Perceptron
        return WifiIDSMLP(input_dim)
    if model_type == "cnn":
        # Create 1D Convolutional Network
        return WifiIDSCNN(input_dim)
    if model_type == "lstm":
        # Create LSTM Network
        return WifiIDSLSTM(input_dim)
    # If model type not recognized, raise error
    raise ValueError(f"Unknown model type: {model_type}")


def train_model(
    model,
    train_loader,
    val_loader,
    device,
    epochs=30,
    lr=1e-3,
    patience=5
):
    """
    Train the model with early stopping.

    Args:
        model (nn.Module): PyTorch model to train
        train_loader (DataLoader): Training data loader
        val_loader (DataLoader): Validation data loader
        device (torch.device): Device to train on (CPU or CUDA)
        epochs (int): Maximum number of training epochs
        lr (float): Learning rate
        patience (int): Early stopping patience (epochs without improvement)

    Returns:
        nn.Module: Trained model with best validation weights loaded
    """
    # Define loss function (cross-entropy for classification)
    criterion = torch.nn.CrossEntropyLoss()

    # Define optimizer (Adam with specified learning rate)
    optimizer = torch.optim.Adam(model.parameters(), lr=lr)

    # Initialize early stopping variables
    best_val_loss = float("inf")  # Track best validation loss
    patience_ctr = 0  # Count epochs without improvement

    # Training loop over epochs
    for epoch in range(1, epochs + 1):
        # --- Training phase ---
        # Set model to training mode (enables dropout, batchnorm training)
        model.train()

        # Initialize training loss accumulator
        train_loss_sum = 0.0

        # Count total training samples
        total = 0

        # Iterate over training batches
        for xb, yb in train_loader:
            # Move batch to device (GPU or CPU)
            xb, yb = xb.to(device), yb.to(device)

            # Zero out gradients from previous iteration
            optimizer.zero_grad()

            # Forward pass: compute model predictions
            logits = model(xb)

            # Compute loss between predictions and true labels
            loss = criterion(logits, yb)

            # Backward pass: compute gradients
            loss.backward()

            # Update model parameters using gradients
            optimizer.step()

            # Accumulate loss (weighted by batch size)
            train_loss_sum += loss.item() * xb.size(0)

            # Count samples processed
            total += xb.size(0)

        # Compute average training loss for this epoch
        train_loss = train_loss_sum / total

        # --- Validation phase ---
        # Set model to evaluation mode (disables dropout, batchnorm uses running stats)
        model.eval()

        # Initialize validation loss accumulator
        val_loss_sum = 0.0

        # Count correct predictions for accuracy
        correct = 0

        # Count total validation samples
        val_total = 0

        # Disable gradient computation for validation (saves memory, faster)
        with torch.no_grad():
            # Iterate over validation batches
            for xb, yb in val_loader:
                # Move batch to device
                xb, yb = xb.to(device), yb.to(device)

                # Forward pass: compute predictions
                logits = model(xb)

                # Compute loss
                loss = criterion(logits, yb)

                # Accumulate validation loss
                val_loss_sum += loss.item() * xb.size(0)

                # Get predicted class (argmax of logits)
                preds = logits.argmax(dim=1)

                # Count correct predictions
                correct += (preds == yb).sum().item()

                # Count samples
                val_total += xb.size(0)

        # Compute average validation loss
        val_loss = val_loss_sum / val_total

        # Compute validation accuracy
        val_acc = correct / val_total

        # Print epoch statistics
        print(
            f"Epoch {epoch:03d} | "
            f"Train Loss: {train_loss:.4f} | "
            f"Val Loss: {val_loss:.4f} | "
            f"Val Acc: {val_acc:.4f}"
        )

        # --- Early stopping logic ---
        if val_loss < best_val_loss:
            # Validation loss improved
            best_val_loss = val_loss  # Update best loss
            patience_ctr = 0  # Reset patience counter

            # Save model checkpoint (best model so far)
            torch.save(model.state_dict(), "best_model.pt")
        else:
            # Validation loss did not improve
            patience_ctr += 1  # Increment patience counter

            # Check if patience exhausted
            if patience_ctr >= patience:
                print("[!] Early stopping triggered")
                break  # Stop training

    # Load best model weights before returning
    model.load_state_dict(torch.load("best_model.pt"))

    # Return trained model
    return model


def main():
    """Main entry point for training script."""
    # Create argument parser
    parser = argparse.ArgumentParser(
        description="Train PyTorch IDS model on preprocessed data."
    )

    # Add argument for data directory
    parser.add_argument(
        "--data-dir",
        type=str,
        default="data/processed",
        help="Directory containing preprocessed .npy files"
    )

    # Add argument for model type
    parser.add_argument(
        "--model",
        type=str,
        default="mlp",
        choices=["mlp", "cnn", "lstm"],  # Valid options
        help="Model architecture to use"
    )

    # Add argument for batch size
    parser.add_argument(
        "--batch-size",
        type=int,
        default=256,
        help="Training batch size (default: 256)"
    )

    # Add argument for number of epochs
    parser.add_argument(
        "--epochs",
        type=int,
        default=30,
        help="Maximum training epochs (default: 30)"
    )

    # Add argument for learning rate
    parser.add_argument(
        "--lr",
        type=float,
        default=1e-3,
        help="Learning rate (default: 0.001)"
    )

    # Add argument for device selection
    parser.add_argument(
        "--device",
        type=str,
        default="cuda" if torch.cuda.is_available() else "cpu",
        help="Device to train on (cpu or cuda)"
    )

    # Add argument for output model path
    parser.add_argument(
        "--output-model",
        type=str,
        default="data/models/wifi_ids_model.pt",
        help="Path to save trained model"
    )

    # Parse arguments
    args = parser.parse_args()

    # --- Load preprocessed data ---
    # Convert data directory string to Path object
    data_dir = Path(args.data_dir)

    # Load training features (scaled)
    X_train = np.load(data_dir / "X_train.npy")

    # Load test features (scaled)
    X_test = np.load(data_dir / "X_test.npy")

    # Load training labels
    y_train = np.load(data_dir / "y_train.npy")

    # Load test labels
    y_test = np.load(data_dir / "y_test.npy")

    # Print data shapes for verification
    print("[*] Data loaded:")
    print(f"    X_train: {X_train.shape}")
    print(f"    X_test: {X_test.shape}")
    print(f"    y_train: {y_train.shape}")
    print(f"    y_test: {y_test.shape}")

    # --- Create train/validation split from training data ---
    # Use 80% of training data for actual training, 20% for validation
    n_train = int(0.8 * len(X_train))

    # Split training data
    X_tr, X_val = X_train[:n_train], X_train[n_train:]
    y_tr, y_val = y_train[:n_train], y_train[n_train:]

    # --- Create PyTorch datasets ---
    # Training dataset
    train_ds = TensorDataset(
        torch.tensor(X_tr, dtype=torch.float32),  # Features as float tensor
        torch.tensor(y_tr, dtype=torch.long),     # Labels as long tensor
    )

    # Validation dataset
    val_ds = TensorDataset(
        torch.tensor(X_val, dtype=torch.float32),
        torch.tensor(y_val, dtype=torch.long),
    )

    # Test dataset (for final evaluation)
    test_ds = TensorDataset(
        torch.tensor(X_test, dtype=torch.float32),
        torch.tensor(y_test, dtype=torch.long),
    )

    # --- Create data loaders ---
    # Training loader (shuffle=True for random batching)
    train_loader = DataLoader(train_ds, batch_size=args.batch_size, shuffle=True)

    # Validation loader (no shuffling needed)
    val_loader = DataLoader(val_ds, batch_size=args.batch_size)

    # Test loader (no shuffling needed)
    test_loader = DataLoader(test_ds, batch_size=args.batch_size)

    # --- Initialize model ---
    # Create device object (CPU or CUDA GPU)
    device = torch.device(args.device)

    # Create model instance and move to device
    model = create_model(args.model, input_dim=X_train.shape[1]).to(device)

    # Print training configuration
    print(f"[*] Training {args.model} model on {device}")
    print(f"    Hidden architecture: see models.py")
    print(f"    Batch size: {args.batch_size}")
    print(f"    Learning rate: {args.lr}")
    print(f"    Max epochs: {args.epochs}")

    # --- Train the model ---
    model = train_model(
        model,
        train_loader,
        val_loader,
        device,
        epochs=args.epochs,
        lr=args.lr
    )

    # --- Final evaluation on test set ---
    print("\n[*] Evaluating on test set...")

    # Set model to evaluation mode
    model.eval()

    # Lists to collect predictions and labels
    all_preds = []
    all_labels = []
    all_probs = []

    # Disable gradients for evaluation
    with torch.no_grad():
        # Iterate over test batches
        for xb, yb in test_loader:
            # Move batch to device
            xb, yb = xb.to(device), yb.to(device)

            # Forward pass
            logits = model(xb)

            # Compute class probabilities (softmax)
            probs = torch.softmax(logits, dim=1)

            # Get predicted class
            preds = probs.argmax(dim=1)

            # Collect predictions, labels, and probabilities
            all_preds.extend(preds.cpu().numpy())
            all_labels.extend(yb.cpu().numpy())
            all_probs.extend(probs[:, 1].cpu().numpy())  # Probability of attack class

    # Convert lists to numpy arrays
    all_preds = np.array(all_preds)
    all_labels = np.array(all_labels)
    all_probs = np.array(all_probs)

    # --- Print evaluation metrics ---
    print("\n" + "="*60)
    print("EVALUATION RESULTS")
    print("="*60)

    # Classification report (precision, recall, F1)
    print("\nClassification Report:")
    print(classification_report(
        all_labels,
        all_preds,
        target_names=["normal", "attack"]  # Class names for report
    ))

    # Confusion matrix
    cm = confusion_matrix(all_labels, all_preds)
    print("Confusion Matrix:")
    print("                Predicted")
    print("              Normal  Attack")
    print(f"Actual Normal   {cm[0,0]:5d}  {cm[0,1]:5d}")
    print(f"       Attack   {cm[1,0]:5d}  {cm[1,1]:5d}")

    # ROC AUC score
    auc = roc_auc_score(all_labels, all_probs)
    print(f"\nROC AUC Score: {auc:.4f}")

    print("="*60)

    # --- Save final model ---
    # Create output directory if needed
    out_path = Path(args.output_model)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    # Save model state dictionary
    torch.save(model.state_dict(), out_path)

    # Print success message
    print(f"\n[+] Model saved to {out_path}")
    print("[+] Training complete!")


# Entry point
if __name__ == "__main__":
    main()
