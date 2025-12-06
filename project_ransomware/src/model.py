"""
Model architectures for ransomware detection.

Includes:
- GN-BiLSTM-Attention: State-of-the-art model with Group Normalization,
  Bidirectional LSTM, and Multi-Head Self-Attention
- Baseline BiLSTM: Simple bidirectional LSTM for comparison
- Traditional ML baselines: XGBoost and Random Forest
"""

import torch
import torch.nn as nn
import torch.nn.functional as F
import numpy as np
from typing import Tuple, Optional
import math


class MultiHeadAttention(nn.Module):
    """Multi-Head Self-Attention mechanism."""

    def __init__(self, hidden_dim: int, num_heads: int = 4, dropout: float = 0.1):
        """
        Initialize Multi-Head Attention.

        Args:
            hidden_dim: Hidden dimension size
            num_heads: Number of attention heads (default: 4)
            dropout: Dropout rate (default: 0.1)
        """
        super(MultiHeadAttention, self).__init__()
        assert hidden_dim % num_heads == 0, "hidden_dim must be divisible by num_heads"

        self.hidden_dim = hidden_dim
        self.num_heads = num_heads
        self.head_dim = hidden_dim // num_heads

        # Linear projections for Q, K, V
        self.query = nn.Linear(hidden_dim, hidden_dim)
        self.key = nn.Linear(hidden_dim, hidden_dim)
        self.value = nn.Linear(hidden_dim, hidden_dim)

        # Output projection
        self.out = nn.Linear(hidden_dim, hidden_dim)
        self.dropout = nn.Dropout(dropout)

        # Scaling factor
        self.scale = math.sqrt(self.head_dim)

    def forward(self, x: torch.Tensor, mask: Optional[torch.Tensor] = None) -> torch.Tensor:
        """
        Forward pass.

        Args:
            x: Input tensor (batch_size, seq_len, hidden_dim)
            mask: Optional attention mask

        Returns:
            Attention output (batch_size, seq_len, hidden_dim)
        """
        batch_size, seq_len, _ = x.size()

        # Linear projections and split into heads
        Q = self.query(x).view(batch_size, seq_len, self.num_heads, self.head_dim).transpose(1, 2)
        K = self.key(x).view(batch_size, seq_len, self.num_heads, self.head_dim).transpose(1, 2)
        V = self.value(x).view(batch_size, seq_len, self.num_heads, self.head_dim).transpose(1, 2)

        # Attention scores
        scores = torch.matmul(Q, K.transpose(-2, -1)) / self.scale

        if mask is not None:
            scores = scores.masked_fill(mask == 0, -1e9)

        # Attention weights
        attn_weights = F.softmax(scores, dim=-1)
        attn_weights = self.dropout(attn_weights)

        # Apply attention to values
        attn_output = torch.matmul(attn_weights, V)

        # Concatenate heads
        attn_output = attn_output.transpose(1, 2).contiguous().view(
            batch_size, seq_len, self.hidden_dim
        )

        # Final linear projection
        output = self.out(attn_output)

        return output


class GNBiLSTMAttention(nn.Module):
    """
    Group Normalization + BiLSTM + Multi-Head Attention model.

    This is the SOTA architecture that achieves 99.99% accuracy as per
    Hussain et al. (2024) on CIC-MalMem-2022 dataset.
    """

    def __init__(self, input_dim: int, hidden_dim: int = 128, num_layers: int = 2,
                 num_heads: int = 4, num_classes: int = 4, dropout: float = 0.3,
                 use_attention: bool = True, use_group_norm: bool = True):
        """
        Initialize GN-BiLSTM-Attention model.

        Args:
            input_dim: Input feature dimension
            hidden_dim: LSTM hidden dimension (default: 128)
            num_layers: Number of LSTM layers (default: 2)
            num_heads: Number of attention heads (default: 4)
            num_classes: Number of output classes (default: 4)
            dropout: Dropout rate (default: 0.3)
            use_attention: Whether to use attention mechanism (default: True)
            use_group_norm: Whether to use group normalization (default: True)
        """
        super(GNBiLSTMAttention, self).__init__()

        self.input_dim = input_dim
        self.hidden_dim = hidden_dim
        self.num_layers = num_layers
        self.num_heads = num_heads
        self.num_classes = num_classes
        self.use_attention = use_attention
        self.use_group_norm = use_group_norm

        # Input projection with Group Normalization
        if use_group_norm:
            # Group Normalization (find divisible number of groups)
            # For 55 features, we can use 5 or 11 groups
            possible_groups = [g for g in [11, 5, 1] if input_dim % g == 0]
            num_groups = possible_groups[0] if possible_groups else 1
            self.group_norm = nn.GroupNorm(num_groups=num_groups, num_channels=input_dim)
        else:
            self.group_norm = nn.Identity()

        # Input projection
        self.input_projection = nn.Linear(input_dim, hidden_dim)

        # Bidirectional LSTM layers
        self.lstm = nn.LSTM(
            input_size=hidden_dim,
            hidden_size=hidden_dim,
            num_layers=num_layers,
            batch_first=True,
            bidirectional=True,
            dropout=dropout if num_layers > 1 else 0
        )

        # Multi-head attention
        lstm_output_dim = hidden_dim * 2  # Bidirectional
        if use_attention:
            self.attention = MultiHeadAttention(
                hidden_dim=lstm_output_dim,
                num_heads=num_heads,
                dropout=dropout
            )
            # Residual connection scaling
            self.attn_norm = nn.LayerNorm(lstm_output_dim)
        else:
            self.attention = None

        # Global Average Pooling (implicit in forward)

        # Classification head
        self.dropout = nn.Dropout(dropout)
        self.fc1 = nn.Linear(lstm_output_dim, hidden_dim)
        self.fc2 = nn.Linear(hidden_dim, num_classes)

        # Initialize weights
        self._init_weights()

    def _init_weights(self):
        """Initialize model weights."""
        for name, param in self.named_parameters():
            if 'weight' in name:
                if 'lstm' in name:
                    nn.init.xavier_uniform_(param)
                elif 'fc' in name or 'input_projection' in name:
                    nn.init.kaiming_normal_(param, nonlinearity='relu')
            elif 'bias' in name:
                nn.init.constant_(param, 0)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        """
        Forward pass.

        Args:
            x: Input tensor (batch_size, seq_len, input_dim)

        Returns:
            Class logits (batch_size, num_classes)
        """
        batch_size, seq_len, _ = x.size()

        # Group Normalization (applied across feature dimension)
        # Reshape for GroupNorm: (batch_size * seq_len, input_dim)
        x_reshaped = x.view(-1, self.input_dim)
        x_norm = self.group_norm(x_reshaped)
        x_norm = x_norm.view(batch_size, seq_len, self.input_dim)

        # Input projection
        x_proj = F.relu(self.input_projection(x_norm))

        # BiLSTM
        lstm_out, _ = self.lstm(x_proj)  # (batch_size, seq_len, hidden_dim*2)

        # Multi-head attention with residual connection
        if self.use_attention:
            attn_out = self.attention(lstm_out)
            lstm_out = self.attn_norm(lstm_out + attn_out)  # Residual connection

        # Global Average Pooling
        pooled = torch.mean(lstm_out, dim=1)  # (batch_size, hidden_dim*2)

        # Classification head
        x = self.dropout(pooled)
        x = F.relu(self.fc1(x))
        x = self.dropout(x)
        logits = self.fc2(x)

        return logits


class BaselineBiLSTM(nn.Module):
    """Baseline BiLSTM model without Group Normalization or Attention."""

    def __init__(self, input_dim: int, hidden_dim: int = 128, num_layers: int = 2,
                 num_classes: int = 4, dropout: float = 0.3):
        """
        Initialize Baseline BiLSTM.

        Args:
            input_dim: Input feature dimension
            hidden_dim: LSTM hidden dimension (default: 128)
            num_layers: Number of LSTM layers (default: 2)
            num_classes: Number of output classes (default: 4)
            dropout: Dropout rate (default: 0.3)
        """
        super(BaselineBiLSTM, self).__init__()

        self.lstm = nn.LSTM(
            input_size=input_dim,
            hidden_size=hidden_dim,
            num_layers=num_layers,
            batch_first=True,
            bidirectional=True,
            dropout=dropout if num_layers > 1 else 0
        )

        lstm_output_dim = hidden_dim * 2
        self.dropout = nn.Dropout(dropout)
        self.fc = nn.Linear(lstm_output_dim, num_classes)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        """
        Forward pass.

        Args:
            x: Input tensor (batch_size, seq_len, input_dim)

        Returns:
            Class logits (batch_size, num_classes)
        """
        lstm_out, _ = self.lstm(x)
        pooled = torch.mean(lstm_out, dim=1)
        x = self.dropout(pooled)
        logits = self.fc(x)
        return logits


class BaselineXGBoost:
    """XGBoost baseline for comparison."""

    def __init__(self, num_classes: int = 4, random_state: int = 42, **kwargs):
        """
        Initialize XGBoost classifier.

        Args:
            num_classes: Number of output classes
            random_state: Random seed
            **kwargs: Additional XGBoost parameters
        """
        try:
            import xgboost as xgb
        except ImportError:
            raise ImportError("XGBoost not installed. Install with: pip install xgboost")

        default_params = {
            'objective': 'multi:softmax' if num_classes > 2 else 'binary:logistic',
            'num_class': num_classes if num_classes > 2 else None,
            'max_depth': 10,
            'learning_rate': 0.1,
            'n_estimators': 200,
            'random_state': random_state,
            'tree_method': 'hist',  # Faster on CPU
            'eval_metric': 'mlogloss' if num_classes > 2 else 'logloss'
        }
        default_params.update(kwargs)

        self.model = xgb.XGBClassifier(**default_params)

    def fit(self, X: np.ndarray, y: np.ndarray, eval_set=None, verbose=False):
        """Train the model."""
        self.model.fit(X, y, eval_set=eval_set, verbose=verbose)
        return self

    def predict(self, X: np.ndarray) -> np.ndarray:
        """Make predictions."""
        return self.model.predict(X)

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        """Predict class probabilities."""
        return self.model.predict_proba(X)


class BaselineRandomForest:
    """Random Forest baseline for comparison."""

    def __init__(self, num_classes: int = 4, random_state: int = 42, **kwargs):
        """
        Initialize Random Forest classifier.

        Args:
            num_classes: Number of output classes
            random_state: Random seed
            **kwargs: Additional RF parameters
        """
        from sklearn.ensemble import RandomForestClassifier

        default_params = {
            'n_estimators': 200,
            'max_depth': 20,
            'random_state': random_state,
            'n_jobs': -1,
            'verbose': 0
        }
        default_params.update(kwargs)

        self.model = RandomForestClassifier(**default_params)

    def fit(self, X: np.ndarray, y: np.ndarray):
        """Train the model."""
        self.model.fit(X, y)
        return self

    def predict(self, X: np.ndarray) -> np.ndarray:
        """Make predictions."""
        return self.model.predict(X)

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        """Predict class probabilities."""
        return self.model.predict_proba(X)


def count_parameters(model: nn.Module) -> int:
    """
    Count trainable parameters in PyTorch model.

    Args:
        model: PyTorch model

    Returns:
        Number of trainable parameters
    """
    return sum(p.numel() for p in model.parameters() if p.requires_grad)


def get_model_summary(model: nn.Module, input_dim: int, sequence_length: int = 1):
    """
    Print model summary.

    Args:
        model: PyTorch model
        input_dim: Input feature dimension
        sequence_length: Sequence length
    """
    print("=" * 70)
    print(f"MODEL: {model.__class__.__name__}")
    print("=" * 70)
    print(model)
    print("=" * 70)
    print(f"Trainable Parameters: {count_parameters(model):,}")
    print("=" * 70)

    # Test forward pass
    device = next(model.parameters()).device
    dummy_input = torch.randn(2, sequence_length, input_dim).to(device)
    with torch.no_grad():
        output = model(dummy_input)
    print(f"Input shape:  {list(dummy_input.shape)}")
    print(f"Output shape: {list(output.shape)}")
    print("=" * 70)


# Example usage
if __name__ == "__main__":
    # Test GN-BiLSTM-Attention model
    input_dim = 55  # CIC-MalMem-2022 features
    num_classes = 4  # Benign, Ransomware, Spyware, Trojan

    print("\n1. GN-BiLSTM-Attention (Full Model)")
    model_full = GNBiLSTMAttention(
        input_dim=input_dim,
        hidden_dim=128,
        num_layers=2,
        num_heads=4,
        num_classes=num_classes,
        dropout=0.3,
        use_attention=True,
        use_group_norm=True
    )
    get_model_summary(model_full, input_dim)

    print("\n2. BiLSTM without Attention (Ablation)")
    model_no_attn = GNBiLSTMAttention(
        input_dim=input_dim,
        hidden_dim=128,
        num_layers=2,
        num_classes=num_classes,
        use_attention=False,
        use_group_norm=True
    )
    get_model_summary(model_no_attn, input_dim)

    print("\n3. BiLSTM without Group Norm (Ablation)")
    model_no_gn = GNBiLSTMAttention(
        input_dim=input_dim,
        hidden_dim=128,
        num_layers=2,
        num_classes=num_classes,
        use_attention=True,
        use_group_norm=False
    )
    get_model_summary(model_no_gn, input_dim)

    print("\n4. Baseline BiLSTM")
    model_baseline = BaselineBiLSTM(
        input_dim=input_dim,
        hidden_dim=128,
        num_layers=2,
        num_classes=num_classes
    )
    get_model_summary(model_baseline, input_dim)

    print("\n✓ All models initialized successfully!")
