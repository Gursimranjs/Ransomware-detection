"""
CNN + ATTENTION MODEL (MAD-ANET Style)
=======================================
Based on MAD-ANET paper that achieved 97.9% on CIC-MalMem-2022

This is a KILLER architecture proven to work better than LSTM for this data.
"""

import torch
import torch.nn as nn
import torch.nn.functional as F


class AttentionLayer(nn.Module):
    """
    Self-Attention mechanism
    Allows model to focus on most discriminative features
    """
    def __init__(self, hidden_dim):
        super(AttentionLayer, self).__init__()
        self.attention_weight = nn.Parameter(torch.randn(hidden_dim, 1))
        nn.init.xavier_uniform_(self.attention_weight)

    def forward(self, x):
        # x shape: (batch, seq_len, hidden_dim)
        # Compute attention scores
        attention_scores = torch.matmul(x, self.attention_weight).squeeze(-1)  # (batch, seq_len)
        attention_weights = F.softmax(attention_scores, dim=1).unsqueeze(-1)  # (batch, seq_len, 1)

        # Weighted sum
        weighted = x * attention_weights  # (batch, seq_len, hidden_dim)
        output = weighted.sum(dim=1)  # (batch, hidden_dim)

        return output, attention_weights


class CNNAttentionModel(nn.Module):
    """
    CNN + Attention Model for Malware Detection
    Based on MAD-ANET architecture that achieved 97.9% accuracy

    Architecture:
    1. Input reshape to pseudo-2D (for CNN)
    2. Convolutional blocks with ReLU + MaxPool
    3. Attention layer
    4. Dense layers with BatchNorm
    5. Dropout for regularization
    6. Output layer
    """
    def __init__(self, input_dim, num_classes=4, dropout=0.3):
        super(CNNAttentionModel, self).__init__()

        self.input_dim = input_dim

        # Reshape input to 2D for CNN: (batch, 1, input_dim) -> treat as 1D sequence
        # We'll use 1D convolutions

        # Convolutional Block 1
        self.conv1 = nn.Conv1d(in_channels=1, out_channels=64, kernel_size=3, padding=1)
        self.bn1 = nn.BatchNorm1d(64)
        self.pool1 = nn.MaxPool1d(kernel_size=2)

        # Convolutional Block 2
        self.conv2 = nn.Conv1d(in_channels=64, out_channels=128, kernel_size=3, padding=1)
        self.bn2 = nn.BatchNorm1d(128)
        self.pool2 = nn.MaxPool1d(kernel_size=2)

        # Convolutional Block 3
        self.conv3 = nn.Conv1d(in_channels=128, out_channels=256, kernel_size=3, padding=1)
        self.bn3 = nn.BatchNorm1d(256)
        self.pool3 = nn.MaxPool1d(kernel_size=2)

        # Calculate size after convolutions and pooling
        # input_dim -> /2 -> /2 -> /2
        conv_output_size = input_dim // 8
        self.conv_output_size = conv_output_size

        # Attention layer
        self.attention = AttentionLayer(hidden_dim=256)

        # Dense Block (as per MAD-ANET: 32, 64, 128)
        self.fc1 = nn.Linear(256, 128)
        self.bn_fc1 = nn.BatchNorm1d(128)
        self.dropout1 = nn.Dropout(dropout)

        self.fc2 = nn.Linear(128, 64)
        self.bn_fc2 = nn.BatchNorm1d(64)
        self.dropout2 = nn.Dropout(dropout)

        self.fc3 = nn.Linear(64, 32)
        self.bn_fc3 = nn.BatchNorm1d(32)
        self.dropout3 = nn.Dropout(dropout)

        # Output layer
        self.output = nn.Linear(32, num_classes)

    def forward(self, x):
        # x shape: (batch, input_dim)
        # Reshape for Conv1d: (batch, channels=1, length=input_dim)
        x = x.unsqueeze(1)  # (batch, 1, input_dim)

        # Convolutional Block 1
        x = self.conv1(x)
        x = self.bn1(x)
        x = F.relu(x)
        x = self.pool1(x)

        # Convolutional Block 2
        x = self.conv2(x)
        x = self.bn2(x)
        x = F.relu(x)
        x = self.pool2(x)

        # Convolutional Block 3
        x = self.conv3(x)
        x = self.bn3(x)
        x = F.relu(x)
        x = self.pool3(x)

        # x shape: (batch, 256, conv_output_size)
        # Transpose for attention: (batch, seq_len, channels)
        x = x.permute(0, 2, 1)  # (batch, conv_output_size, 256)

        # Attention layer
        x, attention_weights = self.attention(x)  # (batch, 256)

        # Dense Block
        x = self.fc1(x)
        x = self.bn_fc1(x)
        x = F.relu(x)
        x = self.dropout1(x)

        x = self.fc2(x)
        x = self.bn_fc2(x)
        x = F.relu(x)
        x = self.dropout2(x)

        x = self.fc3(x)
        x = self.bn_fc3(x)
        x = F.relu(x)
        x = self.dropout3(x)

        # Output
        x = self.output(x)

        return x


class EnsembleModel(nn.Module):
    """
    Ensemble of multiple models for robustness
    Combines CNN+Attention with other architectures
    """
    def __init__(self, models):
        super(EnsembleModel, self).__init__()
        self.models = nn.ModuleList(models)

    def forward(self, x):
        outputs = []
        for model in self.models:
            output = model(x)
            outputs.append(F.softmax(output, dim=1))

        # Average predictions
        ensemble_output = torch.stack(outputs).mean(dim=0)

        return ensemble_output


# Test the model
if __name__ == '__main__':
    print("Testing CNN+Attention Model...")

    # Test with sample data
    batch_size = 32
    input_dim = 55
    num_classes = 4

    model = CNNAttentionModel(input_dim=input_dim, num_classes=num_classes)

    # Create dummy input
    x = torch.randn(batch_size, input_dim)

    # Forward pass
    output = model(x)

    print(f"Input shape: {x.shape}")
    print(f"Output shape: {output.shape}")
    print(f"Model parameters: {sum(p.numel() for p in model.parameters()):,}")

    assert output.shape == (batch_size, num_classes), "Output shape mismatch!"

    print("✓ Model test passed!")
