#!/bin/bash
###############################################################################
# run_inference_server.sh
#
# Start the Flask inference API server
#
# Usage:
#   ./run_inference_server.sh [PORT] [MODEL_TYPE]
#
# PORT: Port number (default: 8000)
# MODEL_TYPE: mlp (default), cnn, or lstm
###############################################################################

# Enable error handling
set -e
set -u

# --- Configuration ---
# Port from argument, default to 8000
PORT="${1:-8000}"

# Model type from second argument, default to mlp
MODEL_TYPE="${2:-mlp}"

# Paths
MODEL_FILE="data/models/wifi_ids_${MODEL_TYPE}.pt"
DATA_DIR="data/processed"
LOG_DIR="logs"

# Create log directory if it doesn't exist
mkdir -p "$LOG_DIR"

# Log file with timestamp
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
LOG_FILE="${LOG_DIR}/inference_server_${TIMESTAMP}.log"

# --- Color codes ---
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

# --- Check prerequisites ---
# Check if venv exists
if [ ! -d "venv" ]; then
    echo -e "${RED}[!]${NC} Virtual environment not found"
    echo "    Run ./scripts/quick_start.sh first"
    exit 1
fi

# Check if model file exists
if [ ! -f "$MODEL_FILE" ]; then
    echo -e "${RED}[!]${NC} Model file not found: $MODEL_FILE"
    echo "    Train model first with: ./scripts/run_training.sh $MODEL_TYPE"
    exit 1
fi

# Check if preprocessed data exists
if [ ! -f "${DATA_DIR}/scaler.joblib" ]; then
    echo -e "${RED}[!]${NC} Preprocessed data not found in $DATA_DIR"
    echo "    Run training pipeline first: ./scripts/run_training.sh"
    exit 1
fi

# --- Activate venv ---
echo -e "${BLUE}[*]${NC} Activating virtual environment..."
source venv/bin/activate

# --- Print server info ---
echo ""
echo "======================================================================"
echo "  AI-WIDS Inference Server"
echo "======================================================================"
echo "  Model:      $MODEL_FILE"
echo "  Model Type: $MODEL_TYPE"
echo "  Port:       $PORT"
echo "  Log File:   $LOG_FILE"
echo "======================================================================"
echo ""
echo -e "${BLUE}[*]${NC} Starting server..."
echo -e "${YELLOW}[!]${NC} Press Ctrl+C to stop"
echo ""

# --- Start server ---
# Run server with output to both console and log file
python src/inference_server.py \
    --model "$MODEL_FILE" \
    --data-dir "$DATA_DIR" \
    --model-type "$MODEL_TYPE" \
    --port "$PORT" \
    --host "0.0.0.0" \
    2>&1 | tee "$LOG_FILE"

# This line is reached when server is stopped (Ctrl+C)
echo ""
echo -e "${GREEN}[+]${NC} Server stopped"
echo -e "${BLUE}[*]${NC} Log saved to: $LOG_FILE"
