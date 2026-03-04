#!/usr/bin/env python3
"""
evaluate_model.py

Comprehensive evaluation of trained IDS model with visualizations.

Generates:
- Classification report (precision, recall, F1)
- Confusion matrix
- ROC curve
- Precision-Recall curve
- Feature importance (if applicable)

Usage:
    python evaluate_model.py --model data/models/wifi_ids_model.pt \
                              --data-dir data/processed \
                              --output results/evaluation_report.txt
"""

# Standard library imports
import argparse
from pathlib import Path

# Third-party imports for ML and visualization
import joblib  # For loading preprocessing objects
import matplotlib.pyplot as plt  # For plotting
import numpy as np  # Numerical operations
import seaborn as sns  # Statistical visualizations
import torch  # PyTorch
from sklearn.metrics import (  # Evaluation metrics
    accuracy_score,
    classification_report,
    confusion_matrix,
    precision_recall_curve,
    roc_auc_score,
    roc_curve,
)
from torch.utils.data import DataLoader, TensorDataset  # Data loading

# Import model architectures
from models import WifiIDSMLP, WifiIDSCNN, WifiIDSLSTM

# Set seaborn style for better-looking plots
sns.set_style("whitegrid")


def load_model_and_data(model_path: Path, data_dir: Path, model_type: str = "mlp"):
    """
    Load trained model and test data.

    Args:
        model_path (Path): Path to trained model state dict
        data_dir (Path): Directory containing preprocessed data
        model_type (str): Model architecture type

    Returns:
        tuple: (model, X_test, y_test, feature_names)
    """
    # Print status
    print(f"[*] Loading model from {model_path}")

    # Load test data
    X_test = np.load(data_dir / "X_test.npy")
    y_test = np.load(data_dir / "y_test.npy")

    # Load feature names
    feature_names = joblib.load(data_dir / "feature_names.joblib")

    # Get input dimension
    input_dim = X_test.shape[1]

    # Create model instance
    if model_type == "mlp":
        model = WifiIDSMLP(input_dim)
    elif model_type == "cnn":
        model = WifiIDSCNN(input_dim)
    elif model_type == "lstm":
        model = WifiIDSLSTM(input_dim)
    else:
        raise ValueError(f"Unknown model type: {model_type}")

    # Load trained weights
    state_dict = torch.load(model_path, map_location="cpu")
    model.load_state_dict(state_dict)

    # Set to evaluation mode
    model.eval()

    print("[+] Model and data loaded successfully")

    return model, X_test, y_test, feature_names


def get_predictions(model, X_test, batch_size=256):
    """
    Get model predictions and probabilities for test set.

    Args:
        model (nn.Module): Trained model
        X_test (np.ndarray): Test features
        batch_size (int): Batch size for inference

    Returns:
        tuple: (predictions, probabilities)
    """
    # Create test dataset
    test_ds = TensorDataset(
        torch.tensor(X_test, dtype=torch.float32),
        torch.zeros(len(X_test), dtype=torch.long)  # Dummy labels
    )

    # Create data loader
    test_loader = DataLoader(test_ds, batch_size=batch_size)

    # Lists to collect results
    all_probs = []

    # Run inference
    with torch.no_grad():
        for xb, _ in test_loader:
            # Forward pass
            logits = model(xb)

            # Compute probabilities
            probs = torch.softmax(logits, dim=1)

            # Collect probabilities
            all_probs.append(probs.cpu().numpy())

    # Concatenate all batches
    all_probs = np.vstack(all_probs)

    # Get predicted classes
    predictions = all_probs.argmax(axis=1)

    return predictions, all_probs


def plot_confusion_matrix(y_true, y_pred, output_path: Path):
    """
    Plot and save confusion matrix.

    Args:
        y_true (np.ndarray): True labels
        y_pred (np.ndarray): Predicted labels
        output_path (Path): Path to save plot
    """
    # Compute confusion matrix
    cm = confusion_matrix(y_true, y_pred)

    # Create figure
    plt.figure(figsize=(8, 6))

    # Plot heatmap
    # annot=True: show numbers in cells
    # fmt='d': format as integers
    # cmap: color map
    sns.heatmap(
        cm,
        annot=True,
        fmt='d',
        cmap='Blues',
        xticklabels=['Normal', 'Attack'],
        yticklabels=['Normal', 'Attack']
    )

    # Set labels
    plt.ylabel('True Label')
    plt.xlabel('Predicted Label')
    plt.title('Confusion Matrix')

    # Save figure
    plt.tight_layout()
    plt.savefig(output_path, dpi=300, bbox_inches='tight')
    plt.close()

    print(f"[+] Saved confusion matrix to {output_path}")


def plot_roc_curve(y_true, y_probs, output_path: Path):
    """
    Plot and save ROC curve.

    Args:
        y_true (np.ndarray): True labels
        y_probs (np.ndarray): Predicted probabilities for positive class
        output_path (Path): Path to save plot
    """
    # Compute ROC curve
    # fpr: false positive rate
    # tpr: true positive rate
    # thresholds: decision thresholds
    fpr, tpr, thresholds = roc_curve(y_true, y_probs)

    # Compute AUC (area under curve)
    auc = roc_auc_score(y_true, y_probs)

    # Create figure
    plt.figure(figsize=(8, 6))

    # Plot ROC curve
    plt.plot(fpr, tpr, linewidth=2, label=f'ROC (AUC = {auc:.4f})')

    # Plot diagonal (random classifier)
    plt.plot([0, 1], [0, 1], 'k--', linewidth=1, label='Random')

    # Set labels and limits
    plt.xlabel('False Positive Rate')
    plt.ylabel('True Positive Rate')
    plt.title('ROC Curve')
    plt.legend(loc='lower right')
    plt.xlim([0.0, 1.0])
    plt.ylim([0.0, 1.05])
    plt.grid(True, alpha=0.3)

    # Save figure
    plt.tight_layout()
    plt.savefig(output_path, dpi=300, bbox_inches='tight')
    plt.close()

    print(f"[+] Saved ROC curve to {output_path}")


def plot_precision_recall_curve(y_true, y_probs, output_path: Path):
    """
    Plot and save Precision-Recall curve.

    Args:
        y_true (np.ndarray): True labels
        y_probs (np.ndarray): Predicted probabilities
        output_path (Path): Path to save plot
    """
    # Compute precision-recall curve
    precision, recall, thresholds = precision_recall_curve(y_true, y_probs)

    # Create figure
    plt.figure(figsize=(8, 6))

    # Plot PR curve
    plt.plot(recall, precision, linewidth=2)

    # Set labels and limits
    plt.xlabel('Recall')
    plt.ylabel('Precision')
    plt.title('Precision-Recall Curve')
    plt.xlim([0.0, 1.0])
    plt.ylim([0.0, 1.05])
    plt.grid(True, alpha=0.3)

    # Save figure
    plt.tight_layout()
    plt.savefig(output_path, dpi=300, bbox_inches='tight')
    plt.close()

    print(f"[+] Saved PR curve to {output_path}")


def main():
    """Main entry point for evaluation script."""
    # Create argument parser
    parser = argparse.ArgumentParser(
        description="Comprehensive evaluation of trained IDS model."
    )

    # Add required arguments
    parser.add_argument(
        "--model",
        type=str,
        required=True,
        help="Path to trained model (.pt file)"
    )

    parser.add_argument(
        "--data-dir",
        type=str,
        required=True,
        help="Directory containing preprocessed data"
    )

    # Add optional arguments
    parser.add_argument(
        "--model-type",
        type=str,
        default="mlp",
        choices=["mlp", "cnn", "lstm"],
        help="Model architecture type"
    )

    parser.add_argument(
        "--output-dir",
        type=str,
        default="results",
        help="Output directory for results"
    )

    # Parse arguments
    args = parser.parse_args()

    # Create output directory
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    # Load model and data
    model, X_test, y_test, feature_names = load_model_and_data(
        Path(args.model),
        Path(args.data_dir),
        args.model_type
    )

    # Get predictions
    print("[*] Generating predictions...")
    y_pred, y_probs = get_predictions(model, X_test)

    # Extract probabilities for positive class (attack)
    y_probs_pos = y_probs[:, 1]

    # --- Generate evaluation report ---
    print("\n" + "="*70)
    print(" "*25 + "EVALUATION REPORT")
    print("="*70)

    # Print basic metrics
    accuracy = accuracy_score(y_test, y_pred)
    print(f"\nAccuracy: {accuracy:.4f}")

    # Print classification report
    print("\nClassification Report:")
    print(classification_report(
        y_test,
        y_pred,
        target_names=['Normal', 'Attack'],
        digits=4
    ))

    # Print confusion matrix
    cm = confusion_matrix(y_test, y_pred)
    print("Confusion Matrix:")
    print(f"                Predicted")
    print(f"               Normal  Attack")
    print(f"Actual Normal  {cm[0,0]:6d}  {cm[0,1]:6d}")
    print(f"       Attack  {cm[1,0]:6d}  {cm[1,1]:6d}")

    # Compute additional metrics
    tn, fp, fn, tp = cm.ravel()

    print(f"\nDetailed Metrics:")
    print(f"  True Positives:  {tp}")
    print(f"  True Negatives:  {tn}")
    print(f"  False Positives: {fp}")
    print(f"  False Negatives: {fn}")
    print(f"  False Positive Rate: {fp/(fp+tn):.4f}")
    print(f"  False Negative Rate: {fn/(fn+tp):.4f}")

    # ROC AUC
    auc = roc_auc_score(y_test, y_probs_pos)
    print(f"\nROC AUC Score: {auc:.4f}")

    print("="*70)

    # --- Save report to file ---
    report_path = output_dir / "evaluation_report.txt"
    with open(report_path, "w") as f:
        f.write("="*70 + "\n")
        f.write(" "*25 + "EVALUATION REPORT\n")
        f.write("="*70 + "\n\n")
        f.write(f"Model: {args.model}\n")
        f.write(f"Type: {args.model_type}\n")
        f.write(f"Test samples: {len(y_test)}\n\n")
        f.write(f"Accuracy: {accuracy:.4f}\n\n")
        f.write("Classification Report:\n")
        f.write(classification_report(
            y_test,
            y_pred,
            target_names=['Normal', 'Attack'],
            digits=4
        ))
        f.write(f"\nROC AUC Score: {auc:.4f}\n")

    print(f"\n[+] Saved text report to {report_path}")

    # --- Generate plots ---
    print("\n[*] Generating visualizations...")

    # Confusion matrix
    plot_confusion_matrix(
        y_test,
        y_pred,
        output_dir / "confusion_matrix.png"
    )

    # ROC curve
    plot_roc_curve(
        y_test,
        y_probs_pos,
        output_dir / "roc_curve.png"
    )

    # Precision-Recall curve
    plot_precision_recall_curve(
        y_test,
        y_probs_pos,
        output_dir / "precision_recall_curve.png"
    )

    print("\n[+] Evaluation complete!")
    print(f"[+] All results saved to {output_dir}")


# Entry point
if __name__ == "__main__":
    main()
