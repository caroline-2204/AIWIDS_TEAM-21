#!/bin/bash
###############################################################################
# quick_start.sh
#
# Quick start script to set up and run AI-WIDS from scratch
#
# This script:
# 1. Sets up Python virtual environment
# 2. Installs dependencies
# 3. Guides through data collection
# 4. Trains model
# 5. Starts inference server
#
# Usage:
#   ./quick_start.sh
###############################################################################

# Enable strict error handling
set -e  # Exit on any error
set -u  # Exit on undefined variable

# --- Color codes for output ---
# Define ANSI color codes for pretty terminal output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'  # No Color (reset)

# --- Helper functions ---

# Print info message in blue
info() {
    echo -e "${BLUE}[*]${NC} $1"
}

# Print success message in green
success() {
    echo -e "${GREEN}[+]${NC} $1"
}

# Print warning message in yellow
warn() {
    echo -e "${YELLOW}[!]${NC} $1"
}

# Print error message in red and exit
error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
    exit 1
}

# Print section header
header() {
    echo ""
    echo "======================================================================"
    echo "  $1"
    echo "======================================================================"
    echo ""
}

# --- Check prerequisites ---
check_prerequisites() {
    header "Checking Prerequisites"

    # Check Python 3.10+
    info "Checking Python version..."
    if ! command -v python3 &> /dev/null; then
        error "Python 3 not found. Please install Python 3.10 or higher."
    fi

    # Get Python version
    PYTHON_VERSION=$(python3 --version | cut -d' ' -f2)
    success "Found Python $PYTHON_VERSION"

    # Check pip
    info "Checking pip..."
    if ! command -v pip3 &> /dev/null; then
        error "pip3 not found. Please install pip."
    fi
    success "pip found"

    # Check tcpdump
    info "Checking tcpdump..."
    if ! command -v tcpdump &> /dev/null; then
        warn "tcpdump not found (needed for packet capture)"
        warn "Install with: sudo apt install tcpdump"
    else
        success "tcpdump found"
    fi

    # Check SSH
    info "Checking SSH client..."
    if ! command -v ssh &> /dev/null; then
        error "SSH client not found. Please install openssh-client."
    fi
    success "SSH client found"
}

# --- Setup virtual environment ---
setup_venv() {
    header "Setting Up Virtual Environment"

    # Check if venv already exists
    if [ -d "venv" ]; then
        info "Virtual environment already exists"
    else
        info "Creating virtual environment..."
        # Create new virtual environment named 'venv'
        python3 -m venv venv
        success "Virtual environment created"
    fi

    # Activate virtual environment
    info "Activating virtual environment..."
    # Source the activation script
    source venv/bin/activate
    success "Virtual environment activated"

    # Upgrade pip to latest version
    info "Upgrading pip..."
    pip install --upgrade pip --quiet
    success "pip upgraded"
}

# --- Install dependencies ---
install_dependencies() {
    header "Installing Dependencies"

    # Check if requirements.txt exists
    if [ ! -f "requirements.txt" ]; then
        error "requirements.txt not found"
    fi

    # Install all packages from requirements.txt
    info "Installing Python packages (this may take a few minutes)..."
    pip install -r requirements.txt --quiet
    success "All dependencies installed"
}

# --- Create directory structure ---
create_directories() {
    header "Creating Directory Structure"

    # List of directories to create
    DIRS=("data/raw" "data/processed" "data/models" "logs" "results")

    # Create each directory
    for dir in "${DIRS[@]}"; do
        if [ ! -d "$dir" ]; then
            mkdir -p "$dir"
            info "Created $dir/"
        else
            info "$dir/ already exists"
        fi
    done

    success "Directory structure ready"
}

# --- Guide data collection ---
guide_data_collection() {
    header "Data Collection"

    echo "To train the model, you need labeled packet captures:"
    echo ""
    echo "1. NORMAL TRAFFIC:"
    echo "   - Connect Phone A to lab WiFi"
    echo "   - Browse websites, watch videos, use apps normally"
    echo "   - Capture for 60-120 seconds"
    echo ""
    echo "2. ATTACK TRAFFIC:"
    echo "   - Connect Phone B to lab WiFi"
    echo "   - Generate attack-like behavior:"
    echo "     * HTTP flood (rapid requests)"
    echo "     * Reconnect bursts (toggle WiFi on/off rapidly)"
    echo "     * Port scanning"
    echo "   - Capture for 60-120 seconds"
    echo ""

    # Ask if user wants to capture now
    read -p "Do you want to capture data now? (y/n): " -n 1 -r
    echo

    if [[ $REPLY =~ ^[Yy]$ ]]; then
        # User wants to capture now

        # Get AP IP
        read -p "Enter UniFi AP IP address (e.g., 192.168.1.20): " AP_IP

        # Capture normal traffic
        info "Capturing NORMAL traffic..."
        echo "Press Enter when Phone A is ready to generate normal traffic..."
        read
        ./scripts/capture_pcap_u6.sh "$AP_IP" data/raw/normal_1.pcap 120

        # Capture attack traffic
        info "Capturing ATTACK traffic..."
        echo "Press Enter when Phone B is ready to generate attack traffic..."
        read
        ./scripts/capture_pcap_u6.sh "$AP_IP" data/raw/attack_1.pcap 120

        success "Packet captures complete"
    else
        # User will capture later
        warn "Skipping data collection"
        warn "Place PCAP files in data/raw/ before training"
        warn "  - Normal traffic: data/raw/normal_*.pcap"
        warn "  - Attack traffic: data/raw/attack_*.pcap"
    fi
}

# --- Train model ---
train_model() {
    header "Training Model"

    # Check if PCAP files exist
    NORMAL_COUNT=$(ls data/raw/normal_*.pcap 2>/dev/null | wc -l || echo "0")
    ATTACK_COUNT=$(ls data/raw/attack_*.pcap 2>/dev/null | wc -l || echo "0")

    if [ "$NORMAL_COUNT" -eq 0 ] || [ "$ATTACK_COUNT" -eq 0 ]; then
        error "No PCAP files found in data/raw/"
    fi

    info "Found $NORMAL_COUNT normal and $ATTACK_COUNT attack PCAP files"

    # Step 1: Extract features
    info "Step 1/3: Extracting features from PCAPs..."
    python src/pcap_to_features.py \
        --normal data/raw/normal_*.pcap \
        --attack data/raw/attack_*.pcap \
        --output data/processed/wifi_features.csv
    success "Features extracted"

    # Step 2: Preprocess features
    info "Step 2/3: Preprocessing features..."
    python src/feature_engineering.py \
        --csv data/processed/wifi_features.csv \
        --output-dir data/processed
    success "Features preprocessed"

    # Step 3: Train model
    info "Step 3/3: Training PyTorch model..."
    python src/train_pytorch.py \
        --data-dir data/processed \
        --model mlp \
        --epochs 30 \
        --output-model data/models/wifi_ids_model.pt
    success "Model trained"
}

# --- Start inference server ---
start_server() {
    header "Starting Inference Server"

    info "Starting Flask API server..."
    info "Server will run on http://0.0.0.0:8000"
    info "Press Ctrl+C to stop"
    echo ""

    # Start server (this will run in foreground)
    python src/inference_server.py \
        --model data/models/wifi_ids_model.pt \
        --data-dir data/processed \
        --port 8000
}

# --- Main execution flow ---
main() {
    # Print banner
    clear
    echo ""
    echo "╔════════════════════════════════════════════════════════════════╗"
    echo "║                                                                ║"
    echo "║              AI-WIDS Quick Start Setup Script                 ║"
    echo "║                                                                ║"
    echo "║          Wireless Intrusion Detection System (PyTorch)        ║"
    echo "║                                                                ║"
    echo "╚════════════════════════════════════════════════════════════════╝"
    echo ""

    # Run setup steps
    check_prerequisites
    setup_venv
    install_dependencies
    create_directories

    # Offer data collection
    guide_data_collection

    # Ask to train model
    echo ""
    read -p "Do you want to train the model now? (y/n): " -n 1 -r
    echo

    if [[ $REPLY =~ ^[Yy]$ ]]; then
        train_model

        # Evaluate model
        info "Evaluating model..."
        python src/evaluate_model.py \
            --model data/models/wifi_ids_model.pt \
            --data-dir data/processed \
            --output-dir results
        success "Evaluation complete (see results/ directory)"

        # Ask to start server
        echo ""
        read -p "Do you want to start the inference server now? (y/n): " -n 1 -r
        echo

        if [[ $REPLY =~ ^[Yy]$ ]]; then
            start_server
        else
            info "You can start the server later with:"
            info "  ./scripts/run_inference_server.sh"
        fi
    else
        warn "Skipping training"
        warn "Run ./scripts/run_training.sh when ready"
    fi

    # Print completion message
    echo ""
    success "Setup complete!"
    echo ""
    echo "Next steps:"
    echo "  1. Start inference server: ./scripts/run_inference_server.sh"
    echo "  2. Run live demo: ./scripts/run_live_demo.sh"
    echo "  3. See docs/Live-Demo-Guide.md for full documentation"
    echo ""
}

# Run main function
main
