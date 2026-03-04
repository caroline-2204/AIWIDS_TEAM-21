#!/usr/bin/env python3
"""
models.py

PyTorch neural network architectures for wireless intrusion detection.

Includes:
- WifiIDSMLP: Multi-layer perceptron for tabular features
- WifiIDSCNN: 1D convolutional network
- WifiIDSLSTM: Recurrent network for sequential data
"""

# PyTorch imports
import torch  # Core PyTorch library
import torch.nn as nn  # Neural network layers and modules
import torch.nn.functional as F  # Activation functions and ops


class WifiIDSMLP(nn.Module):
    """
    Multi-Layer Perceptron for tabular intrusion detection features.

    Architecture:
    - Input layer: size = input_dim (number of features)
    - Hidden layers: configurable sizes with ReLU, BatchNorm, Dropout
    - Output layer: num_classes logits (typically 2 for binary classification)
    """

    def __init__(self, input_dim, hidden_dims=(128, 64), num_classes=2, dropout=0.3):
        """
        Initialize the MLP model.

        Args:
            input_dim (int): Number of input features
            hidden_dims (tuple): Sizes of hidden layers (default: (128, 64))
            num_classes (int): Number of output classes (default: 2)
            dropout (float): Dropout rate for regularization (default: 0.3)
        """
        # Call parent class constructor (required for all nn.Module subclasses)
        super().__init__()

        # Initialize empty list to store layer modules
        layers = []

        # Track the size of the previous layer (starts with input dimension)
        prev = input_dim

        # Build each hidden layer
        for h in hidden_dims:
            # Linear (fully connected) layer: maps prev features to h features
            layers.append(nn.Linear(prev, h))

            # ReLU activation: introduces non-linearity (f(x) = max(0, x))
            layers.append(nn.ReLU())

            # Batch normalization: normalizes activations for stable training
            layers.append(nn.BatchNorm1d(h))

            # Dropout: randomly zeros some activations to prevent overfitting
            layers.append(nn.Dropout(dropout))

            # Update prev to current layer size for next iteration
            prev = h

        # Add final output layer (no activation here, logits only)
        # Maps from last hidden layer to num_classes outputs
        layers.append(nn.Linear(prev, num_classes))

        # Combine all layers into a Sequential container
        # Sequential applies layers in order during forward pass
        self.net = nn.Sequential(*layers)

    def forward(self, x):
        """
        Forward pass: compute model output for input x.

        Args:
            x (torch.Tensor): Input tensor of shape (batch_size, input_dim)

        Returns:
            torch.Tensor: Logits of shape (batch_size, num_classes)
        """
        # Pass input through all layers sequentially
        return self.net(x)


class WifiIDSCNN(nn.Module):
    """
    1D Convolutional Neural Network for feature vectors.

    Treats the feature vector as a 1D sequence and applies
    convolutional filters to detect local patterns.

    Architecture:
    - Conv1D layers with BatchNorm
    - Adaptive pooling to fixed size
    - Fully connected classifier head
    """

    def __init__(self, input_dim, num_classes=2, dropout=0.3):
        """
        Initialize the CNN model.

        Args:
            input_dim (int): Number of input features
            num_classes (int): Number of output classes (default: 2)
            dropout (float): Dropout rate (default: 0.3)
        """
        # Call parent class constructor
        super().__init__()

        # First convolutional layer
        # in_channels=1: treat input as single-channel sequence
        # out_channels=32: learn 32 different filters
        # kernel_size=3: each filter looks at 3 consecutive features
        # padding=1: add padding to maintain sequence length
        self.conv1 = nn.Conv1d(1, 32, kernel_size=3, padding=1)

        # Batch normalization after first conv layer
        self.bn1 = nn.BatchNorm1d(32)

        # Second convolutional layer
        # Takes 32 input channels, produces 64 output channels
        self.conv2 = nn.Conv1d(32, 64, kernel_size=3, padding=1)

        # Batch normalization after second conv layer
        self.bn2 = nn.BatchNorm1d(64)

        # Adaptive average pooling: reduces sequence to length 1
        # Outputs fixed size regardless of input length
        self.pool = nn.AdaptiveAvgPool1d(1)

        # First fully connected layer: 64 channels -> 32 features
        self.fc1 = nn.Linear(64, 32)

        # Dropout for regularization before final layer
        self.dropout = nn.Dropout(dropout)

        # Final output layer: 32 features -> num_classes logits
        self.fc2 = nn.Linear(32, num_classes)

    def forward(self, x):
        """
        Forward pass for CNN model.

        Args:
            x (torch.Tensor): Input of shape (batch_size, input_dim)

        Returns:
            torch.Tensor: Logits of shape (batch_size, num_classes)
        """
        # Add channel dimension: (batch, input_dim) -> (batch, 1, input_dim)
        # Required for Conv1d which expects (batch, channels, length)
        x = x.unsqueeze(1)

        # First conv block: Conv -> ReLU -> BatchNorm
        x = F.relu(self.bn1(self.conv1(x)))

        # Second conv block: Conv -> ReLU -> BatchNorm
        x = F.relu(self.bn2(self.conv2(x)))

        # Adaptive pooling: reduces to (batch, 64, 1)
        x = self.pool(x)

        # Flatten: (batch, 64, 1) -> (batch, 64)
        x = x.view(x.size(0), -1)

        # First FC layer with ReLU activation
        x = F.relu(self.fc1(x))

        # Apply dropout
        x = self.dropout(x)

        # Final FC layer (outputs logits)
        x = self.fc2(x)

        # Return logits
        return x


class WifiIDSLSTM(nn.Module):
    """
    Long Short-Term Memory network for sequential data.

    Useful when packet features form a temporal sequence
    (e.g., multiple packets from same flow over time).

    Architecture:
    - LSTM layers to process sequences
    - FC classifier head on final hidden state
    """

    def __init__(
        self,
        input_dim,
        hidden_dim=64,
        num_layers=2,
        num_classes=2,
        dropout=0.3
    ):
        """
        Initialize the LSTM model.

        Args:
            input_dim (int): Number of features per time step
            hidden_dim (int): Size of LSTM hidden state (default: 64)
            num_layers (int): Number of stacked LSTM layers (default: 2)
            num_classes (int): Number of output classes (default: 2)
            dropout (float): Dropout rate between LSTM layers (default: 0.3)
        """
        # Call parent class constructor
        super().__init__()

        # LSTM layer
        self.lstm = nn.LSTM(
            input_size=input_dim,  # Features per time step
            hidden_size=hidden_dim,  # Size of hidden state
            num_layers=num_layers,  # Number of stacked LSTM layers
            batch_first=True,  # Input/output shape: (batch, seq, feature)
            dropout=dropout if num_layers > 1 else 0.0,  # Dropout between layers
        )

        # First fully connected layer after LSTM
        # Takes final hidden state -> 32 features
        self.fc1 = nn.Linear(hidden_dim, 32)

        # Dropout layer
        self.dropout = nn.Dropout(dropout)

        # Final output layer: 32 -> num_classes
        self.fc2 = nn.Linear(32, num_classes)

    def forward(self, x):
        """
        Forward pass for LSTM model.

        Args:
            x (torch.Tensor): Input of shape (batch, seq_len, input_dim)
                             or (batch, input_dim) for single time step

        Returns:
            torch.Tensor: Logits of shape (batch, num_classes)
        """
        # If input is 2D (batch, features), add sequence dimension
        if x.ndim == 2:
            # (batch, input_dim) -> (batch, 1, input_dim)
            x = x.unsqueeze(1)

        # Pass through LSTM
        # out: (batch, seq_len, hidden_dim) - all hidden states
        # _: final (hidden_state, cell_state) tuple (not needed here)
        out, _ = self.lstm(x)

        # Extract last time step's hidden state: (batch, hidden_dim)
        last = out[:, -1, :]

        # Pass through first FC layer with ReLU
        x = F.relu(self.fc1(last))

        # Apply dropout
        x = self.dropout(x)

        # Final FC layer (outputs logits)
        x = self.fc2(x)

        # Return logits
        return x


# Example usage (for testing during development)
if __name__ == "__main__":
    # Create example input tensor: batch_size=4, input_dim=15
    x = torch.randn(4, 15)

    # Test MLP model
    model_mlp = WifiIDSMLP(input_dim=15)
    out_mlp = model_mlp(x)
    print(f"MLP output shape: {out_mlp.shape}")  # Expected: (4, 2)

    # Test CNN model
    model_cnn = WifiIDSCNN(input_dim=15)
    out_cnn = model_cnn(x)
    print(f"CNN output shape: {out_cnn.shape}")  # Expected: (4, 2)

    # Test LSTM model
    model_lstm = WifiIDSLSTM(input_dim=15)
    out_lstm = model_lstm(x)
    print(f"LSTM output shape: {out_lstm.shape}")  # Expected: (4, 2)

    print("All models initialized successfully!")
