#!/usr/bin/env python3
"""
feature_engineering.py

Preprocess extracted features for machine learning:
- Encode categorical variables
- Scale numeric features
- Split into train/test sets
- Save preprocessed data and transformers

Usage:
    python feature_engineering.py --csv data/processed/wifi_features.csv \
                                  --output-dir data/processed
"""

# Standard library imports
import argparse
from pathlib import Path

# Third-party imports for machine learning preprocessing
import joblib  # For saving/loading sklearn objects
import numpy as np  # For numerical operations
import pandas as pd  # For DataFrame operations
from sklearn.model_selection import train_test_split  # For splitting data
from sklearn.preprocessing import LabelEncoder, StandardScaler  # For encoding and scaling


def main():
    """Main entry point for feature preprocessing."""
    # Create command-line argument parser
    parser = argparse.ArgumentParser(
        description="Preprocess network features for machine learning training."
    )

    # Add required argument for input CSV file
    parser.add_argument(
        "--csv",
        type=str,
        required=True,  # This argument is mandatory
        help="Path to input CSV file from pcap_to_features.py"
    )

    # Add argument for output directory
    parser.add_argument(
        "--output-dir",
        type=str,
        default="data/processed",  # Default output location
        help="Output directory for preprocessed arrays and encoders"
    )

    # Add argument for test set size
    parser.add_argument(
        "--test-size",
        type=float,
        default=0.2,  # 20% of data reserved for testing
        help="Fraction of data to use for test set (default: 0.2)"
    )

    # Add argument for random seed (for reproducibility)
    parser.add_argument(
        "--random-state",
        type=int,
        default=42,  # Standard random seed for reproducibility
        help="Random seed for train/test split (default: 42)"
    )

    # Parse all command-line arguments
    args = parser.parse_args()

    # Create output directory if it doesn't exist
    # parents=True creates parent directories as needed
    # exist_ok=True doesn't raise error if directory exists
    out_dir = Path(args.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    # Load the CSV file into a pandas DataFrame
    print(f"[*] Loading {args.csv}")
    df = pd.read_csv(args.csv)

    # Print basic statistics about the loaded data
    print(f"    Rows: {len(df)}, Columns: {len(df.columns)}")

    # --- Encode labels (binary classification) ---
    print("[*] Encoding labels...")

    # Convert labels to binary: normal=0, attack=1
    # Any label that is not "normal" becomes 1 (attack)
    y = (df["label"] != "normal").astype(int).values

    # Print class distribution (count of each class)
    print("    Label counts:", np.bincount(y))

    # --- Encode categorical columns ---
    # These columns contain string values that need numeric encoding
    cat_cols = ["src", "dst", "bssid", "src_ip", "dst_ip"]

    # Dictionary to store LabelEncoder objects for each categorical column
    encoders = {}

    # Process each categorical column
    for col in cat_cols:
        # Check if column exists in DataFrame
        if col in df.columns:
            print(f"[*] Encoding {col}")

            # Create a new LabelEncoder for this column
            le = LabelEncoder()

            # Convert column values to strings (handles any type)
            df[col] = df[col].astype(str)

            # Fit encoder and transform values to integers
            # fit_transform() learns the mapping and applies it
            df[col] = le.fit_transform(df[col])

            # Store encoder for later use (during inference)
            encoders[col] = le

            # Print number of unique classes found
            print(f"    {col}: {len(le.classes_)} classes")

    # --- Prepare feature matrix X ---
    # Drop the label column to get only features
    # errors="ignore" prevents error if "label" column doesn't exist
    X_df = df.drop(columns=["label"], errors="ignore")

    # Get list of all feature column names
    feature_names = list(X_df.columns)

    # Convert DataFrame to numpy array (required for scikit-learn)
    # dtype=float ensures all values are floating point numbers
    X = X_df.to_numpy(dtype=float)

    # Print feature column names for verification
    print("[*] Feature columns:", feature_names)

    # --- Split data into training and test sets ---
    # X_train: training features
    # X_test: test features
    # y_train: training labels
    # y_test: test labels
    X_train, X_test, y_train, y_test = train_test_split(
        X,  # Feature matrix
        y,  # Label vector
        test_size=args.test_size,  # Fraction for test set
        random_state=args.random_state,  # Random seed for reproducibility
        stratify=y,  # Maintain class proportions in both sets
    )

    # Print sizes of resulting splits
    print(f"[*] Train size: {len(X_train)}, Test size: {len(X_test)}")

    # --- Scale features to zero mean and unit variance ---
    # Scaling improves neural network training stability
    # Create StandardScaler object
    scaler = StandardScaler()

    # Fit scaler on training data and transform training set
    # fit_transform() computes mean/std and applies scaling
    X_train_scaled = scaler.fit_transform(X_train)

    # Transform test set using training statistics (no refitting)
    # This prevents data leakage from test set
    X_test_scaled = scaler.transform(X_test)

    # --- Save all preprocessed arrays ---
    # Save scaled training features
    np.save(out_dir / "X_train.npy", X_train_scaled)

    # Save scaled test features
    np.save(out_dir / "X_test.npy", X_test_scaled)

    # Save training labels
    np.save(out_dir / "y_train.npy", y_train)

    # Save test labels
    np.save(out_dir / "y_test.npy", y_test)

    # --- Save preprocessing objects for inference ---
    # Save the fitted scaler (needed to scale new data the same way)
    joblib.dump(scaler, out_dir / "scaler.joblib")

    # Save feature names list (ensures correct feature order during inference)
    joblib.dump(feature_names, out_dir / "feature_names.joblib")

    # Save each categorical encoder with its column name
    for col, enc in encoders.items():
        # Filename format: encoder_<column_name>.joblib
        joblib.dump(enc, out_dir / f"encoder_{col}.joblib")

    # Print completion message
    print("[+] Preprocessing complete. Outputs in", out_dir)
    print("    Files created:")
    print("      - X_train.npy, X_test.npy (scaled features)")
    print("      - y_train.npy, y_test.npy (labels)")
    print("      - scaler.joblib (StandardScaler)")
    print("      - feature_names.joblib (feature order)")
    print(f"      - {len(encoders)} encoder files (LabelEncoders)")


# If this script is run directly, execute main()
if __name__ == "__main__":
    main()
