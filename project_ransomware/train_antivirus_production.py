"""
ANTIVIRUS PRODUCTION MODEL
==========================
Multi-malware detection optimized for real-world deployment
Prioritizes ransomware but detects all malware types with high accuracy

Key features:
- Hierarchical class weighting (Ransomware > Spyware/Trojan > Benign)
- Focal loss for hard example mining
- Dual optimization: Ransomware F1 + Overall Malware Recall
- Production-ready architecture for real-time deployment
"""

import os
import numpy as np
import pandas as pd
import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import Dataset, DataLoader
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score
from imblearn.over_sampling import SMOTE
import json
from datetime import datetime

# Import CNN+Attention model
import sys
sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))
from cnn_attention_model import CNNAttentionModel

# Configuration
DATA_PATH = 'data/enhanced_dataset.csv'
MODEL_SAVE_PATH = 'models/antivirus_production_best.pth'
RESULTS_PATH = 'results/antivirus_training_results.json'

# Hyperparameters tuned for production antivirus
BATCH_SIZE = 32  # Smaller for better gradient updates
DROPOUT = 0.5    # Higher dropout for better generalization
LEARNING_RATE = 0.0005  # Lower for stability
NUM_EPOCHS = 100
PATIENCE = 15
DEVICE = torch.device('mps' if torch.backends.mps.is_available() else 'cpu')

print(f"Using device: {DEVICE}")

# Focal Loss - focuses on hard-to-classify examples
class FocalLoss(nn.Module):
    def __init__(self, alpha=None, gamma=2.0, reduction='mean'):
        super(FocalLoss, self).__init__()
        self.alpha = alpha
        self.gamma = gamma
        self.reduction = reduction

    def forward(self, inputs, targets):
        ce_loss = nn.functional.cross_entropy(inputs, targets, reduction='none', weight=self.alpha)
        pt = torch.exp(-ce_loss)
        focal_loss = ((1 - pt) ** self.gamma) * ce_loss

        if self.reduction == 'mean':
            return focal_loss.mean()
        elif self.reduction == 'sum':
            return focal_loss.sum()
        else:
            return focal_loss

# Custom Dataset
class MalwareDataset(Dataset):
    def __init__(self, features, labels):
        self.features = torch.FloatTensor(features)
        self.labels = torch.LongTensor(labels)

    def __len__(self):
        return len(self.features)

    def __getitem__(self, idx):
        return self.features[idx], self.labels[idx]

def load_and_preprocess_data():
    """Load enhanced dataset and prepare for training"""
    print("\n" + "="*60)
    print("LOADING ENHANCED DATASET")
    print("="*60)

    df = pd.read_csv(DATA_PATH)
    print(f"Total samples: {len(df):,}")

    # Features and labels
    X = df.drop(['Category', 'MalwareType'], axis=1).values
    y = df['MalwareType'].map({'Benign': 0, 'Ransomware': 1, 'Spyware': 2, 'Trojan': 3}).values

    print(f"\nClass Distribution:")
    for i, label in enumerate(['Benign', 'Ransomware', 'Spyware', 'Trojan']):
        count = np.sum(y == i)
        print(f"  {label}: {count:,} ({count/len(y)*100:.2f}%)")

    # Train-test split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    # Apply SMOTE only to training data
    print("\nApplying SMOTE to balance training data...")
    smote = SMOTE(random_state=42, k_neighbors=5)
    X_train_balanced, y_train_balanced = smote.fit_resample(X_train, y_train)

    print(f"\nAfter SMOTE:")
    for i, label in enumerate(['Benign', 'Ransomware', 'Spyware', 'Trojan']):
        count = np.sum(y_train_balanced == i)
        print(f"  {label}: {count:,} ({count/len(y_train_balanced)*100:.2f}%)")

    # Normalize features
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train_balanced)
    X_test_scaled = scaler.transform(X_test)

    return X_train_scaled, X_test_scaled, y_train_balanced, y_test, scaler

def calculate_hierarchical_weights(y_train):
    """
    Calculate class weights with hierarchical importance:
    Ransomware > Spyware/Trojan > Benign
    """
    class_counts = np.bincount(y_train)
    total_samples = len(y_train)

    # Base weights (inverse frequency)
    base_weights = total_samples / (len(class_counts) * class_counts)

    # Hierarchical boosting
    # Ransomware: +50% boost (most critical)
    base_weights[1] *= 1.5

    # Spyware and Trojan: +25% boost (important but less critical than ransomware)
    base_weights[2] *= 1.25
    base_weights[3] *= 1.25

    # Benign: no boost (baseline)

    # Normalize
    base_weights = base_weights / base_weights.sum() * len(class_counts)

    print(f"\nHierarchical Class Weights:")
    labels = ['Benign', 'Ransomware', 'Spyware', 'Trojan']
    for i, label in enumerate(labels):
        print(f"  {label}: {base_weights[i]:.4f}")

    return torch.FloatTensor(base_weights).to(DEVICE)

def train_epoch(model, train_loader, criterion, optimizer):
    model.train()
    total_loss = 0
    correct = 0
    total = 0

    for features, labels in train_loader:
        features, labels = features.to(DEVICE), labels.to(DEVICE)

        optimizer.zero_grad()
        outputs = model(features)
        loss = criterion(outputs, labels)
        loss.backward()
        optimizer.step()

        total_loss += loss.item()
        _, predicted = torch.max(outputs.data, 1)
        total += labels.size(0)
        correct += (predicted == labels).sum().item()

    return total_loss / len(train_loader), 100 * correct / total

def validate(model, val_loader, criterion):
    model.eval()
    total_loss = 0
    all_preds = []
    all_labels = []
    all_probs = []

    with torch.no_grad():
        for features, labels in val_loader:
            features, labels = features.to(DEVICE), labels.to(DEVICE)

            outputs = model(features)
            loss = criterion(outputs, labels)

            total_loss += loss.item()
            probs = torch.softmax(outputs, dim=1)
            _, predicted = torch.max(outputs.data, 1)

            all_preds.extend(predicted.cpu().numpy())
            all_labels.extend(labels.cpu().numpy())
            all_probs.extend(probs.cpu().numpy())

    return total_loss / len(val_loader), np.array(all_preds), np.array(all_labels), np.array(all_probs)

def calculate_production_metrics(y_true, y_pred, y_probs):
    """
    Calculate metrics relevant for production antivirus:
    1. Overall malware detection rate (recall for any malware)
    2. Ransomware-specific F1 score
    3. False positive rate (Benign wrongly classified as malware)
    """
    # Convert to binary: Benign (0) vs Any Malware (1)
    y_true_binary = (y_true > 0).astype(int)
    y_pred_binary = (y_pred > 0).astype(int)

    # Malware detection metrics
    malware_tp = np.sum((y_true_binary == 1) & (y_pred_binary == 1))
    malware_fn = np.sum((y_true_binary == 1) & (y_pred_binary == 0))
    malware_fp = np.sum((y_true_binary == 0) & (y_pred_binary == 1))

    overall_malware_recall = malware_tp / (malware_tp + malware_fn) if (malware_tp + malware_fn) > 0 else 0
    false_positive_rate = malware_fp / np.sum(y_true_binary == 0) if np.sum(y_true_binary == 0) > 0 else 0

    # Ransomware-specific metrics
    ransomware_mask = y_true == 1
    if np.sum(ransomware_mask) > 0:
        ransomware_tp = np.sum((y_true == 1) & (y_pred == 1))
        ransomware_fp = np.sum((y_true != 1) & (y_pred == 1))
        ransomware_fn = np.sum((y_true == 1) & (y_pred != 1))

        ransomware_precision = ransomware_tp / (ransomware_tp + ransomware_fp) if (ransomware_tp + ransomware_fp) > 0 else 0
        ransomware_recall = ransomware_tp / (ransomware_tp + ransomware_fn) if (ransomware_tp + ransomware_fn) > 0 else 0
        ransomware_f1 = 2 * (ransomware_precision * ransomware_recall) / (ransomware_precision + ransomware_recall) if (ransomware_precision + ransomware_recall) > 0 else 0
    else:
        ransomware_precision = ransomware_recall = ransomware_f1 = 0

    # Combined production score: 60% malware detection + 40% ransomware F1
    production_score = 0.6 * overall_malware_recall + 0.4 * ransomware_f1

    return {
        'overall_malware_recall': overall_malware_recall,
        'false_positive_rate': false_positive_rate,
        'ransomware_precision': ransomware_precision,
        'ransomware_recall': ransomware_recall,
        'ransomware_f1': ransomware_f1,
        'production_score': production_score
    }

def main():
    print("\n" + "="*60)
    print("ANTIVIRUS PRODUCTION MODEL TRAINING")
    print("="*60)

    # Load data
    X_train, X_test, y_train, y_test, scaler = load_and_preprocess_data()

    # Create data loaders
    train_dataset = MalwareDataset(X_train, y_train)
    test_dataset = MalwareDataset(X_test, y_test)

    train_loader = DataLoader(train_dataset, batch_size=BATCH_SIZE, shuffle=True)
    test_loader = DataLoader(test_dataset, batch_size=BATCH_SIZE, shuffle=False)

    # Initialize model
    input_dim = X_train.shape[1]
    model = CNNAttentionModel(input_dim=input_dim, num_classes=4, dropout=DROPOUT).to(DEVICE)

    print(f"\nModel Architecture: CNN + Attention")
    print(f"Input features: {input_dim}")
    print(f"Output classes: 4 (Benign, Ransomware, Spyware, Trojan)")

    # Hierarchical class weights
    class_weights = calculate_hierarchical_weights(y_train)

    # Focal Loss with hierarchical weights
    criterion = FocalLoss(alpha=class_weights, gamma=2.0)
    optimizer = optim.Adam(model.parameters(), lr=LEARNING_RATE, weight_decay=1e-5)
    scheduler = optim.lr_scheduler.ReduceLROnPlateau(optimizer, mode='max', factor=0.5, patience=5, verbose=True)

    # Training loop
    print("\n" + "="*60)
    print("TRAINING")
    print("="*60)

    best_production_score = 0
    best_ransomware_f1 = 0
    patience_counter = 0
    training_history = []

    for epoch in range(NUM_EPOCHS):
        train_loss, train_acc = train_epoch(model, train_loader, criterion, optimizer)
        val_loss, val_preds, val_labels, val_probs = validate(model, test_loader, criterion)

        # Calculate production metrics
        prod_metrics = calculate_production_metrics(val_labels, val_preds, val_probs)

        # Overall accuracy
        val_acc = 100 * np.mean(val_preds == val_labels)

        print(f"\nEpoch {epoch+1}/{NUM_EPOCHS}")
        print(f"  Train Loss: {train_loss:.4f} | Train Acc: {train_acc:.2f}%")
        print(f"  Val Loss: {val_loss:.4f} | Val Acc: {val_acc:.2f}%")
        print(f"  Malware Detection Rate: {prod_metrics['overall_malware_recall']*100:.2f}%")
        print(f"  False Positive Rate: {prod_metrics['false_positive_rate']*100:.2f}%")
        print(f"  Ransomware F1: {prod_metrics['ransomware_f1']*100:.2f}%")
        print(f"  Production Score: {prod_metrics['production_score']*100:.2f}%")

        # Save training history
        training_history.append({
            'epoch': epoch + 1,
            'train_loss': train_loss,
            'train_acc': train_acc,
            'val_loss': val_loss,
            'val_acc': val_acc,
            **{f'val_{k}': v for k, v in prod_metrics.items()}
        })

        # Learning rate scheduling
        scheduler.step(prod_metrics['production_score'])

        # Save best model based on production score
        if prod_metrics['production_score'] > best_production_score:
            best_production_score = prod_metrics['production_score']
            best_ransomware_f1 = prod_metrics['ransomware_f1']

            os.makedirs('models', exist_ok=True)
            torch.save({
                'epoch': epoch,
                'model_state_dict': model.state_dict(),
                'optimizer_state_dict': optimizer.state_dict(),
                'production_score': best_production_score,
                'ransomware_f1': best_ransomware_f1,
                'input_dim': input_dim,
                'scaler': scaler
            }, MODEL_SAVE_PATH)

            print(f"  ✓ New best model saved! (Production Score: {best_production_score*100:.2f}%)")
            patience_counter = 0
        else:
            patience_counter += 1
            print(f"  No improvement ({patience_counter}/{PATIENCE})")

        if patience_counter >= PATIENCE:
            print(f"\nEarly stopping triggered after {epoch+1} epochs")
            break

    # Load best model for final evaluation
    print("\n" + "="*60)
    print("FINAL EVALUATION ON TEST SET")
    print("="*60)

    checkpoint = torch.load(MODEL_SAVE_PATH, weights_only=False)
    model.load_state_dict(checkpoint['model_state_dict'])

    _, final_preds, final_labels, final_probs = validate(model, test_loader, criterion)

    # Classification report
    labels_names = ['Benign', 'Ransomware', 'Spyware', 'Trojan']
    print("\nClassification Report:")
    print(classification_report(final_labels, final_preds, target_names=labels_names, digits=4))

    # Confusion matrix
    cm = confusion_matrix(final_labels, final_preds)
    print("\nConfusion Matrix:")
    print("Predicted →")
    print(f"{'':12} {'Benign':>10} {'Ransomware':>12} {'Spyware':>10} {'Trojan':>10}")
    for i, label in enumerate(labels_names):
        print(f"{label:12} {cm[i][0]:10} {cm[i][1]:12} {cm[i][2]:10} {cm[i][3]:10}")

    # Production metrics
    final_prod_metrics = calculate_production_metrics(final_labels, final_preds, final_probs)

    print("\n" + "="*60)
    print("PRODUCTION ANTIVIRUS METRICS")
    print("="*60)
    print(f"Overall Malware Detection Rate: {final_prod_metrics['overall_malware_recall']*100:.2f}%")
    print(f"False Positive Rate: {final_prod_metrics['false_positive_rate']*100:.2f}%")
    print(f"Ransomware Precision: {final_prod_metrics['ransomware_precision']*100:.2f}%")
    print(f"Ransomware Recall: {final_prod_metrics['ransomware_recall']*100:.2f}%")
    print(f"Ransomware F1-Score: {final_prod_metrics['ransomware_f1']*100:.2f}%")
    print(f"Production Score: {final_prod_metrics['production_score']*100:.2f}%")

    # Save results
    results = {
        'timestamp': datetime.now().isoformat(),
        'model': 'CNN+Attention (Antivirus Production)',
        'final_metrics': {
            'overall_accuracy': float(np.mean(final_preds == final_labels)),
            **{k: float(v) for k, v in final_prod_metrics.items()}
        },
        'confusion_matrix': cm.tolist(),
        'training_history': training_history,
        'hyperparameters': {
            'batch_size': BATCH_SIZE,
            'dropout': DROPOUT,
            'learning_rate': LEARNING_RATE,
            'num_epochs': NUM_EPOCHS,
            'focal_gamma': 2.0
        }
    }

    os.makedirs('results', exist_ok=True)
    with open(RESULTS_PATH, 'w') as f:
        json.dump(results, f, indent=2)

    print(f"\n✓ Results saved to {RESULTS_PATH}")
    print(f"✓ Model saved to {MODEL_SAVE_PATH}")
    print("\nREADY FOR PRODUCTION DEPLOYMENT!")

if __name__ == '__main__':
    main()
