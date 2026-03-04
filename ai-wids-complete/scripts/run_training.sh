#!/bin/bash
###############################################################################
# run_training.sh
#
# Complete training pipeline: PCAP → Features → Training → Evaluation
#
# Usage:
#   ./run_training.sh [MODEL_TYPE]
#
# MODEL_TYPE: mlp (default), cnn, or lstm
###############################################################################

# Enable error handling
set -e
set -u

# --- Configuration ---
# Model type from argument, default to mlp
MODEL_TYPE="${1:-mlp}"

# Validate model type
if [[ ! "$MODEL_TYPE" =~ ^(mlp|cnn|lstm)$ ]]; then
    echo "ERROR: Invalid model type '$MODEL_TYPE'"
    echo "Usage: $0 [mlp|cnn|lstm]"
    exit 1
fi

# Directories
RAW_DIR="data/raw"
PROCESSED_DIR="data/processed"
MODELS_DIR="data/models"
RESULTS_DIR="results"

# Output files
FEATURES_CSV="${PROCESSED_DIR}/wifi_features.csv"
MODEL_FILE="${MODELS_DIR}/wifi_ids_${MODEL_TYPE}.pt"

# Training parameters
BATCH_SIZE=256
EPOCHS=30
LEARNING_RATE=0.001

# --- Color codes ---
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

# --- Print header ---
echo ""
echo "======================================================================"
echo "  AI-WIDS Training Pipeline"
echo "======================================================================"
echo "  Model Type: $MODEL_TYPE"
echo "  Epochs:     $EPOCHS"
echo "  Batch Size: $BATCH_SIZE"
echo "======================================================================"
echo ""

# --- Check for Python venv ---
if [ ! -d "venv" ]; then
    echo -e "${YELLOW}[!]${NC} Virtual environment not found"
    echo "    Run ./scripts/quick_start.sh first"
    exit 1
fi

# Activate venv
echo -e "${BLUE}[*]${NC} Activating virtual environment..."
source venv/bin/activate

# --- Step 1: Feature Extraction ---
echo ""
echo -e "${BLUE}[*]${NC} Step 1/4: Extracting features from PCAPs..."
echo "    Looking for PCAP files in $RAW_DIR/"

# Count PCAP files
NORMAL_FILES=$(ls ${RAW_DIR}/normal_*.pcap 2>/dev/null || true)
ATTACK_FILES=$(ls ${RAW_DIR}/attack_*.pcap 2>/dev/null || true)

# Check if files exist
if [ -z "$NORMAL_FILES" ] || [ -z "$ATTACK_FILES" ]; then
    echo -e "${YELLOW}[!]${NC} ERROR: No PCAP files found"
    echo "    Place files in:"
    echo "      - ${RAW_DIR}/normal_*.pcap"
    echo "      - ${RAW_DIR}/attack_*.pcap"
    exit 1
fi

# Run feature extraction
python src/pcap_to_features.py \
    --normal ${RAW_DIR}/normal_*.pcap \
    --attack ${RAW_DIR}/attack_*.pcap \
    --output "$FEATURES_CSV"

echo -e "${GREEN}[+]${NC} Features saved to $FEATURES_CSV"

# --- Step 2: Feature Preprocessing ---
echo ""
echo -e "${BLUE}[*]${NC} Step 2/4: Preprocessing features..."

# Run preprocessing
python src/feature_engineering.py \
    --csv "$FEATURES_CSV" \
    --output-dir "$PROCESSED_DIR"

echo -e "${GREEN}[+]${NC} Preprocessed data saved to $PROCESSED_DIR"

# --- Step 3: Model Training ---
echo ""
echo -e "${BLUE}[*]${NC} Step 3/4: Training $MODEL_TYPE model..."

# Run training
python src/train_pytorch.py \
    --data-dir "$PROCESSED_DIR" \
    --model "$MODEL_TYPE" \
    --batch-size "$BATCH_SIZE" \
    --epochs "$EPOCHS" \
    --lr "$LEARNING_RATE" \
    --output-model "$MODEL_FILE"

echo -e "${GREEN}[+]${NC} Model saved to $MODEL_FILE"

# --- Step 4: Model Evaluation ---
echo ""
echo -e "${BLUE}[*]${NC} Step 4/4: Evaluating model..."

# Run evaluation
python src/evaluate_model.py \
    --model "$MODEL_FILE" \
    --data-dir "$PROCESSED_DIR" \
    --model-type "$MODEL_TYPE" \
    --output-dir "$RESULTS_DIR"

echo -e "${GREEN}[+]${NC} Evaluation results saved to $RESULTS_DIR"

# --- Print summary ---
echo ""
echo "======================================================================"
echo "  Training Complete!"
echo "======================================================================"
echo "  Model file:        $MODEL_FILE"
echo "  Evaluation report: ${RESULTS_DIR}/evaluation_report.txt"
echo "  Confusion matrix:  ${RESULTS_DIR}/confusion_matrix.png"
echo "  ROC curve:         ${RESULTS_DIR}/roc_curve.png"
echo "======================================================================"
echo ""
echo "Next steps:"
echo "  - Review evaluation report: cat ${RESULTS_DIR}/evaluation_report.txt"
echo "  - Start inference server:   ./scripts/run_inference_server.sh"
echo "  - Run live demo:            ./scripts/run_live_demo.sh"
echo ""
