"""
Utility functions for training, evaluation, and visualization.

Includes:
- Training utilities (early stopping, checkpointing)
- Evaluation metrics and visualization
- Device management (Mac MPS / CPU)
- Plotting functions for thesis-ready figures
"""

import torch
import torch.nn as nn
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.metrics import (
    classification_report, confusion_matrix, roc_curve, auc,
    precision_recall_curve, average_precision_score, roc_auc_score
)
from typing import Dict, List, Tuple, Optional
import pandas as pd
import time
import os


def get_device() -> torch.device:
    """
    Get best available device (MPS for Mac, CPU otherwise).

    Returns:
        torch.device
    """
    if torch.backends.mps.is_available():
        device = torch.device("mps")
        print("✓ Using Apple Silicon MPS acceleration")
    else:
        device = torch.device("cpu")
        print("✓ Using CPU")
    return device


def set_seed(seed: int = 42):
    """
    Set random seeds for reproducibility.

    Args:
        seed: Random seed value
    """
    torch.manual_seed(seed)
    np.random.seed(seed)
    if torch.cuda.is_available():
        torch.cuda.manual_seed_all(seed)
    print(f"✓ Random seed set to {seed}")


class EarlyStopping:
    """Early stopping to prevent overfitting."""

    def __init__(self, patience: int = 10, min_delta: float = 0.0,
                 mode: str = 'min', verbose: bool = True):
        """
        Initialize early stopping.

        Args:
            patience: Number of epochs to wait before stopping
            min_delta: Minimum change to qualify as improvement
            mode: 'min' for loss, 'max' for accuracy
            verbose: Print messages
        """
        self.patience = patience
        self.min_delta = min_delta
        self.mode = mode
        self.verbose = verbose
        self.counter = 0
        self.best_score = None
        self.early_stop = False

    def __call__(self, score: float) -> bool:
        """
        Check if training should stop.

        Args:
            score: Current metric value

        Returns:
            True if should stop, False otherwise
        """
        if self.best_score is None:
            self.best_score = score
            if self.verbose:
                print(f"  Initial best score: {score:.4f}")
            return False

        if self.mode == 'min':
            improved = score < (self.best_score - self.min_delta)
        else:
            improved = score > (self.best_score + self.min_delta)

        if improved:
            if self.verbose:
                print(f"  ✓ Score improved: {self.best_score:.4f} → {score:.4f}")
            self.best_score = score
            self.counter = 0
        else:
            self.counter += 1
            if self.verbose:
                print(f"  No improvement ({self.counter}/{self.patience})")

            if self.counter >= self.patience:
                self.early_stop = True
                if self.verbose:
                    print(f"  ⚠ Early stopping triggered!")
                return True

        return False


class ModelCheckpoint:
    """Save best model during training."""

    def __init__(self, filepath: str, mode: str = 'min', verbose: bool = True):
        """
        Initialize checkpoint manager.

        Args:
            filepath: Path to save model
            mode: 'min' for loss, 'max' for accuracy
            verbose: Print messages
        """
        self.filepath = filepath
        self.mode = mode
        self.verbose = verbose
        self.best_score = None

    def __call__(self, score: float, model: nn.Module, optimizer: Optional[torch.optim.Optimizer] = None):
        """
        Save model if score improved.

        Args:
            score: Current metric value
            model: PyTorch model to save
            optimizer: Optional optimizer state
        """
        if self.best_score is None:
            self.best_score = score
            self._save_checkpoint(model, optimizer, score)
            return

        if self.mode == 'min':
            improved = score < self.best_score
        else:
            improved = score > self.best_score

        if improved:
            if self.verbose:
                print(f"  ✓ Saving model (score: {self.best_score:.4f} → {score:.4f})")
            self.best_score = score
            self._save_checkpoint(model, optimizer, score)

    def _save_checkpoint(self, model: nn.Module, optimizer: Optional[torch.optim.Optimizer], score: float):
        """Save model checkpoint."""
        checkpoint = {
            'model_state_dict': model.state_dict(),
            'score': score
        }
        if optimizer is not None:
            checkpoint['optimizer_state_dict'] = optimizer.state_dict()

        torch.save(checkpoint, self.filepath)


def compute_metrics(y_true: np.ndarray, y_pred: np.ndarray, y_prob: np.ndarray,
                   class_names: List[str]) -> Dict:
    """
    Compute comprehensive classification metrics.

    Args:
        y_true: True labels
        y_pred: Predicted labels
        y_prob: Prediction probabilities
        class_names: List of class names

    Returns:
        Dictionary of metrics
    """
    # Classification report
    report = classification_report(y_true, y_pred, target_names=class_names,
                                   output_dict=True, zero_division=0)

    # Confusion matrix
    cm = confusion_matrix(y_true, y_pred)

    # ROC-AUC (one-vs-rest for multi-class)
    n_classes = len(class_names)
    if n_classes == 2:
        roc_auc = roc_auc_score(y_true, y_prob[:, 1])
    else:
        roc_auc = roc_auc_score(y_true, y_prob, multi_class='ovr', average='macro')

    metrics = {
        'classification_report': report,
        'confusion_matrix': cm,
        'roc_auc': roc_auc,
        'accuracy': report['accuracy'],
        'macro_avg_f1': report['macro avg']['f1-score'],
        'weighted_avg_f1': report['weighted avg']['f1-score']
    }

    return metrics


def plot_confusion_matrix(cm: np.ndarray, class_names: List[str],
                          save_path: Optional[str] = None, normalize: bool = True):
    """
    Plot confusion matrix with annotations.

    Args:
        cm: Confusion matrix
        class_names: List of class names
        save_path: Path to save figure
        normalize: Whether to normalize
    """
    if normalize:
        cm_norm = cm.astype('float') / cm.sum(axis=1)[:, np.newaxis]
    else:
        cm_norm = cm

    plt.figure(figsize=(10, 8))
    sns.heatmap(cm_norm, annot=True, fmt='.2%' if normalize else 'd',
                cmap='Blues', xticklabels=class_names, yticklabels=class_names,
                cbar_kws={'label': 'Percentage' if normalize else 'Count'})
    plt.title('Confusion Matrix' + (' (Normalized)' if normalize else ''),
              fontsize=14, fontweight='bold')
    plt.ylabel('True Label', fontsize=12, fontweight='bold')
    plt.xlabel('Predicted Label', fontsize=12, fontweight='bold')
    plt.tight_layout()

    if save_path:
        plt.savefig(save_path, dpi=300, bbox_inches='tight')
        print(f"✓ Confusion matrix saved to {save_path}")

    plt.show()


def plot_roc_curves(y_true: np.ndarray, y_prob: np.ndarray, class_names: List[str],
                   save_path: Optional[str] = None):
    """
    Plot ROC curves for multi-class classification (one-vs-rest).

    Args:
        y_true: True labels
        y_prob: Prediction probabilities
        class_names: List of class names
        save_path: Path to save figure
    """
    from sklearn.preprocessing import label_binarize

    n_classes = len(class_names)
    y_true_bin = label_binarize(y_true, classes=range(n_classes))

    plt.figure(figsize=(10, 8))

    # Plot ROC curve for each class
    for i in range(n_classes):
        fpr, tpr, _ = roc_curve(y_true_bin[:, i], y_prob[:, i])
        roc_auc = auc(fpr, tpr)
        plt.plot(fpr, tpr, linewidth=2,
                label=f'{class_names[i]} (AUC = {roc_auc:.4f})')

    # Plot diagonal
    plt.plot([0, 1], [0, 1], 'k--', linewidth=1, label='Random Classifier')

    plt.xlim([0.0, 1.0])
    plt.ylim([0.0, 1.05])
    plt.xlabel('False Positive Rate', fontsize=12, fontweight='bold')
    plt.ylabel('True Positive Rate', fontsize=12, fontweight='bold')
    plt.title('ROC Curves (One-vs-Rest)', fontsize=14, fontweight='bold')
    plt.legend(loc='lower right', fontsize=10)
    plt.grid(alpha=0.3)
    plt.tight_layout()

    if save_path:
        plt.savefig(save_path, dpi=300, bbox_inches='tight')
        print(f"✓ ROC curves saved to {save_path}")

    plt.show()


def plot_precision_recall_curves(y_true: np.ndarray, y_prob: np.ndarray,
                                 class_names: List[str], save_path: Optional[str] = None):
    """
    Plot Precision-Recall curves for multi-class classification.

    Args:
        y_true: True labels
        y_prob: Prediction probabilities
        class_names: List of class names
        save_path: Path to save figure
    """
    from sklearn.preprocessing import label_binarize

    n_classes = len(class_names)
    y_true_bin = label_binarize(y_true, classes=range(n_classes))

    plt.figure(figsize=(10, 8))

    # Plot PR curve for each class
    for i in range(n_classes):
        precision, recall, _ = precision_recall_curve(y_true_bin[:, i], y_prob[:, i])
        avg_precision = average_precision_score(y_true_bin[:, i], y_prob[:, i])
        plt.plot(recall, precision, linewidth=2,
                label=f'{class_names[i]} (AP = {avg_precision:.4f})')

    plt.xlim([0.0, 1.0])
    plt.ylim([0.0, 1.05])
    plt.xlabel('Recall', fontsize=12, fontweight='bold')
    plt.ylabel('Precision', fontsize=12, fontweight='bold')
    plt.title('Precision-Recall Curves', fontsize=14, fontweight='bold')
    plt.legend(loc='lower left', fontsize=10)
    plt.grid(alpha=0.3)
    plt.tight_layout()

    if save_path:
        plt.savefig(save_path, dpi=300, bbox_inches='tight')
        print(f"✓ Precision-Recall curves saved to {save_path}")

    plt.show()


def plot_training_history(history: Dict[str, List[float]], save_path: Optional[str] = None):
    """
    Plot training and validation loss/accuracy curves.

    Args:
        history: Dictionary with 'train_loss', 'val_loss', 'train_acc', 'val_acc'
        save_path: Path to save figure
    """
    fig, axes = plt.subplots(1, 2, figsize=(16, 6))

    # Plot loss
    axes[0].plot(history['train_loss'], label='Train Loss', linewidth=2, marker='o', markersize=4)
    axes[0].plot(history['val_loss'], label='Val Loss', linewidth=2, marker='s', markersize=4)
    axes[0].set_xlabel('Epoch', fontsize=12, fontweight='bold')
    axes[0].set_ylabel('Loss', fontsize=12, fontweight='bold')
    axes[0].set_title('Training and Validation Loss', fontsize=14, fontweight='bold')
    axes[0].legend(fontsize=11)
    axes[0].grid(alpha=0.3)

    # Plot accuracy
    axes[1].plot(history['train_acc'], label='Train Accuracy', linewidth=2, marker='o', markersize=4)
    axes[1].plot(history['val_acc'], label='Val Accuracy', linewidth=2, marker='s', markersize=4)
    axes[1].set_xlabel('Epoch', fontsize=12, fontweight='bold')
    axes[1].set_ylabel('Accuracy (%)', fontsize=12, fontweight='bold')
    axes[1].set_title('Training and Validation Accuracy', fontsize=14, fontweight='bold')
    axes[1].legend(fontsize=11)
    axes[1].grid(alpha=0.3)

    plt.tight_layout()

    if save_path:
        plt.savefig(save_path, dpi=300, bbox_inches='tight')
        print(f"✓ Training history saved to {save_path}")

    plt.show()


def export_metrics_to_csv(metrics: Dict, model_name: str, save_dir: str):
    """
    Export metrics to CSV for thesis tables.

    Args:
        metrics: Metrics dictionary from compute_metrics()
        model_name: Name of the model
        save_dir: Directory to save CSV files
    """
    os.makedirs(save_dir, exist_ok=True)

    # Classification report
    report_df = pd.DataFrame(metrics['classification_report']).transpose()
    report_path = os.path.join(save_dir, f'{model_name}_classification_report.csv')
    report_df.to_csv(report_path)
    print(f"✓ Classification report saved to {report_path}")

    # Confusion matrix
    cm_df = pd.DataFrame(metrics['confusion_matrix'])
    cm_path = os.path.join(save_dir, f'{model_name}_confusion_matrix.csv')
    cm_df.to_csv(cm_path, index=False)
    print(f"✓ Confusion matrix saved to {cm_path}")


def generate_latex_table(metrics: Dict, model_name: str, class_names: List[str]) -> str:
    """
    Generate LaTeX table from metrics for thesis.

    Args:
        metrics: Metrics dictionary
        model_name: Name of model
        class_names: List of class names

    Returns:
        LaTeX table string
    """
    report = metrics['classification_report']

    latex = "\\begin{table}[h]\n"
    latex += "\\centering\n"
    latex += f"\\caption{{Classification Results: {model_name}}}\n"
    latex += "\\begin{tabular}{|l|c|c|c|c|}\n"
    latex += "\\hline\n"
    latex += "Class & Precision & Recall & F1-Score & Support \\\\\n"
    latex += "\\hline\n"

    for cls in class_names:
        if cls in report:
            prec = report[cls]['precision'] * 100
            rec = report[cls]['recall'] * 100
            f1 = report[cls]['f1-score'] * 100
            sup = int(report[cls]['support'])
            latex += f"{cls} & {prec:.2f}\\% & {rec:.2f}\\% & {f1:.2f}\\% & {sup} \\\\\n"

    latex += "\\hline\n"
    acc = metrics['accuracy'] * 100
    latex += f"\\textbf{{Accuracy}} & \\multicolumn{{3}}{{c|}}{{{acc:.2f}\\%}} & {sum([int(report[c]['support']) for c in class_names if c in report])} \\\\\n"
    latex += "\\hline\n"
    latex += "\\end{tabular}\n"
    latex += "\\end{table}\n"

    return latex


class Timer:
    """Simple timer for benchmarking."""

    def __init__(self):
        self.start_time = None
        self.elapsed = 0

    def start(self):
        """Start timer."""
        self.start_time = time.time()

    def stop(self) -> float:
        """Stop timer and return elapsed time."""
        if self.start_time is None:
            return 0
        self.elapsed = time.time() - self.start_time
        return self.elapsed

    def reset(self):
        """Reset timer."""
        self.start_time = None
        self.elapsed = 0


def print_metrics_summary(metrics: Dict, class_names: List[str], model_name: str = "Model"):
    """
    Print comprehensive metrics summary.

    Args:
        metrics: Metrics dictionary
        class_names: List of class names
        model_name: Name of model
    """
    report = metrics['classification_report']

    print("\n" + "="*80)
    print(f"EVALUATION RESULTS: {model_name}")
    print("="*80)
    print(f"\nOverall Accuracy: {metrics['accuracy']*100:.2f}%")
    print(f"ROC-AUC Score:    {metrics['roc_auc']:.4f}")
    print(f"Macro Avg F1:     {metrics['macro_avg_f1']:.4f}")
    print(f"Weighted Avg F1:  {metrics['weighted_avg_f1']:.4f}")

    print("\n" + "-"*80)
    print("Per-Class Metrics:")
    print("-"*80)
    print(f"{'Class':<15} {'Precision':>12} {'Recall':>12} {'F1-Score':>12} {'Support':>12}")
    print("-"*80)

    for cls in class_names:
        if cls in report:
            prec = report[cls]['precision'] * 100
            rec = report[cls]['recall'] * 100
            f1 = report[cls]['f1-score'] * 100
            sup = int(report[cls]['support'])
            print(f"{cls:<15} {prec:>11.2f}% {rec:>11.2f}% {f1:>11.2f}% {sup:>12,}")

    print("="*80 + "\n")


# Example usage
if __name__ == "__main__":
    print("Testing utility functions...\n")

    # Test device selection
    device = get_device()

    # Test seed setting
    set_seed(42)

    # Test early stopping
    early_stop = EarlyStopping(patience=3, verbose=True)
    for epoch in range(10):
        score = 1.0 / (epoch + 1)  # Decreasing score
        print(f"Epoch {epoch+1}: score = {score:.4f}")
        if early_stop(score):
            print("Training stopped!")
            break

    print("\n✓ All utility functions working!")
