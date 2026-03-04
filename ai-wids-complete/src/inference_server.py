#!/usr/bin/env python3
"""
inference_server.py

Flask REST API server for real-time intrusion detection inference.

Endpoints:
- GET /health: Check server and model status
- POST /predict: Classify a single packet
- POST /batch_predict: Classify multiple packets

Usage:
    python inference_server.py --model data/models/wifi_ids_model.pt \
                                --data-dir data/processed \
                                --port 8000
"""

# Standard library imports
import argparse
import logging
from pathlib import Path

# Third-party imports
import joblib  # For loading preprocessing objects
import numpy as np  # Numerical operations
import torch  # PyTorch for model inference
from flask import Flask, jsonify, request  # Web framework

# Import model architectures
from models import WifiIDSMLP, WifiIDSCNN, WifiIDSLSTM

# Create Flask application instance
app = Flask(__name__)

# Global variables to store loaded resources
# These are loaded once at startup and reused for all requests
MODEL = None  # PyTorch model instance
SCALER = None  # StandardScaler for feature scaling
FEATURE_NAMES = None  # List of feature names in correct order
ENCODERS = {}  # Dictionary of LabelEncoders for categorical features
DEVICE = None  # Torch device (CPU or CUDA)
MODEL_TYPE = "mlp"  # Model architecture type


def load_resources(model_path: Path, data_dir: Path, model_type: str = "mlp"):
    """
    Load model, scaler, encoders, and feature names at server startup.

    Args:
        model_path (Path): Path to saved model state dict (.pt file)
        data_dir (Path): Directory containing preprocessing objects
        model_type (str): Model architecture ("mlp", "cnn", "lstm")
    """
    # Declare global variables that will be modified
    global MODEL, SCALER, FEATURE_NAMES, ENCODERS, DEVICE, MODEL_TYPE

    # Print status message
    print(f"[*] Loading model from {model_path}")

    # Store model type
    MODEL_TYPE = model_type

    # --- Load preprocessing objects ---
    # Load list of feature names (defines feature order)
    FEATURE_NAMES = joblib.load(data_dir / "feature_names.joblib")
    print(f"[*] Loaded {len(FEATURE_NAMES)} feature names")

    # Load fitted StandardScaler
    SCALER = joblib.load(data_dir / "scaler.joblib")
    print("[*] Loaded StandardScaler")

    # --- Load categorical encoders ---
    # Find all encoder files in data directory
    for enc_file in data_dir.glob("encoder_*.joblib"):
        # Extract column name from filename (e.g., "encoder_src.joblib" -> "src")
        col = enc_file.stem.replace("encoder_", "")

        # Load the LabelEncoder for this column
        ENCODERS[col] = joblib.load(enc_file)

        print(f"[*] Loaded encoder for '{col}' ({len(ENCODERS[col].classes_)} classes)")

    # --- Determine input dimension from feature names ---
    input_dim = len(FEATURE_NAMES)

    # --- Create model instance ---
    if model_type == "mlp":
        # Create MLP model
        MODEL = WifiIDSMLP(input_dim)
    elif model_type == "cnn":
        # Create CNN model
        MODEL = WifiIDSCNN(input_dim)
    elif model_type == "lstm":
        # Create LSTM model
        MODEL = WifiIDSLSTM(input_dim)
    else:
        # Raise error for unknown model type
        raise ValueError(f"Unknown model type: {model_type}")

    # --- Load trained weights ---
    # Load state dictionary from file
    state_dict = torch.load(model_path, map_location="cpu")

    # Load weights into model
    MODEL.load_state_dict(state_dict)

    # Set model to evaluation mode (disables dropout, etc.)
    MODEL.eval()

    # --- Set device ---
    # Use GPU if available, otherwise CPU
    DEVICE = torch.device("cuda" if torch.cuda.is_available() else "cpu")

    # Move model to device
    MODEL.to(DEVICE)

    print(f"[+] Model loaded successfully on {DEVICE}")


def preprocess_features(data: dict) -> np.ndarray:
    """
    Convert raw feature dictionary to scaled feature vector.

    Args:
        data (dict): Dictionary of feature name -> value

    Returns:
        np.ndarray: Scaled feature vector ready for model input
    """
    # Initialize empty list for feature values
    x = []

    # Iterate through feature names in correct order
    for name in FEATURE_NAMES:
        # Check if this feature needs categorical encoding
        if name in ENCODERS:
            # Get value as string (categorical encoders expect strings)
            val = str(data.get(name, "unknown"))

            try:
                # Transform using fitted encoder
                # transform() returns array, take first element
                encoded = ENCODERS[name].transform([val])[0]
                x.append(float(encoded))
            except ValueError:
                # Value not seen during training, use 0 as fallback
                x.append(0.0)
        else:
            # Numeric feature, get value directly
            # Default to 0 if feature missing
            x.append(float(data.get(name, 0)))

    # Convert list to numpy array with shape (1, num_features)
    x = np.array([x], dtype=np.float32)

    # Apply scaling transformation
    x_scaled = SCALER.transform(x)

    # Return scaled features
    return x_scaled


@app.route("/health", methods=["GET"])
def health():
    """
    Health check endpoint.

    Returns JSON with server status and model load state.
    """
    # Return status dictionary as JSON
    return jsonify({
        "status": "ok",  # Server is running
        "model_loaded": MODEL is not None,  # Check if model is loaded
        "model_type": MODEL_TYPE,  # Report model architecture
        "device": str(DEVICE),  # Report compute device
        "num_features": len(FEATURE_NAMES) if FEATURE_NAMES else 0
    })


@app.route("/predict", methods=["POST"])
def predict():
    """
    Single packet prediction endpoint.

    Expects JSON payload with packet features.
    Returns JSON with prediction and confidence scores.
    """
    try:
        # Parse JSON request body
        data = request.json

        # Validate that data was provided
        if data is None:
            return jsonify({"error": "No JSON data provided"}), 400

        # Preprocess features
        x_scaled = preprocess_features(data)

        # Convert to PyTorch tensor
        x_tensor = torch.tensor(x_scaled, dtype=torch.float32).to(DEVICE)

        # Disable gradient computation (not needed for inference)
        with torch.no_grad():
            # Forward pass through model
            logits = MODEL(x_tensor)

            # Compute class probabilities using softmax
            probs = torch.softmax(logits, dim=1).cpu().numpy()[0]

            # Get predicted class (0=normal, 1=attack)
            pred = int(probs.argmax())

        # Build response dictionary
        response = {
            "prediction": pred,  # Class index
            "label": "normal" if pred == 0 else "attack",  # Class name
            "confidence_normal": float(probs[0]),  # Probability of normal
            "confidence_attack": float(probs[1]),  # Probability of attack
            "timestamp": data.get("timestamp", None),  # Echo timestamp if provided
        }

        # Return JSON response
        return jsonify(response)

    except Exception as e:
        # Handle any errors gracefully
        # Log the error
        app.logger.error(f"Prediction error: {str(e)}")

        # Return error response
        return jsonify({"error": str(e)}), 500


@app.route("/batch_predict", methods=["POST"])
def batch_predict():
    """
    Batch prediction endpoint for multiple packets.

    Expects JSON array of packet feature dictionaries.
    Returns JSON array of predictions.
    """
    try:
        # Parse JSON request body (should be list of dicts)
        data_list = request.json

        # Validate input
        if not isinstance(data_list, list):
            return jsonify({"error": "Expected JSON array"}), 400

        # Initialize list to collect results
        results = []

        # Process each packet
        for data in data_list:
            # Preprocess features
            x_scaled = preprocess_features(data)

            # Convert to tensor
            x_tensor = torch.tensor(x_scaled, dtype=torch.float32).to(DEVICE)

            # Inference
            with torch.no_grad():
                logits = MODEL(x_tensor)
                probs = torch.softmax(logits, dim=1).cpu().numpy()[0]
                pred = int(probs.argmax())

            # Append result to list
            results.append({
                "prediction": pred,
                "label": "normal" if pred == 0 else "attack",
                "confidence_normal": float(probs[0]),
                "confidence_attack": float(probs[1]),
            })

        # Return batch results
        return jsonify({"predictions": results, "count": len(results)})

    except Exception as e:
        # Handle errors
        app.logger.error(f"Batch prediction error: {str(e)}")
        return jsonify({"error": str(e)}), 500


def main():
    """Main entry point for inference server."""
    # Create argument parser
    parser = argparse.ArgumentParser(
        description="Flask inference server for WiFi IDS model."
    )

    # Add argument for model path
    parser.add_argument(
        "--model",
        type=str,
        required=True,
        help="Path to trained model (.pt file)"
    )

    # Add argument for data directory
    parser.add_argument(
        "--data-dir",
        type=str,
        required=True,
        help="Directory containing preprocessing objects"
    )

    # Add argument for model type
    parser.add_argument(
        "--model-type",
        type=str,
        default="mlp",
        choices=["mlp", "cnn", "lstm"],
        help="Model architecture type"
    )

    # Add argument for port number
    parser.add_argument(
        "--port",
        type=int,
        default=8000,
        help="Port to run server on (default: 8000)"
    )

    # Add argument for host
    parser.add_argument(
        "--host",
        type=str,
        default="0.0.0.0",
        help="Host to bind to (default: 0.0.0.0)"
    )

    # Add argument for debug mode
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Run in debug mode"
    )

    # Parse arguments
    args = parser.parse_args()

    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    # Load resources before starting server
    load_resources(
        model_path=Path(args.model),
        data_dir=Path(args.data_dir),
        model_type=args.model_type
    )

    # Print startup message
    print("="*60)
    print("AI-WIDS Inference Server")
    print("="*60)
    print(f"Model: {args.model}")
    print(f"Type: {args.model_type}")
    print(f"Device: {DEVICE}")
    print(f"Listening on http://{args.host}:{args.port}")
    print("="*60)
    print("Endpoints:")
    print("  GET  /health        - Check server status")
    print("  POST /predict       - Single packet prediction")
    print("  POST /batch_predict - Batch packet prediction")
    print("="*60)

    # Start Flask server
    # threaded=True allows multiple simultaneous requests
    app.run(
        host=args.host,
        port=args.port,
        debug=args.debug,
        threaded=True
    )


# Entry point
if __name__ == "__main__":
    main()
