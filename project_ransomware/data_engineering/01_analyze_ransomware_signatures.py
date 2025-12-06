"""
DEEP RANSOMWARE SIGNATURE ANALYSIS
===================================
Identify UNIQUE patterns that distinguish ransomware from spyware/trojan

Goal: Find the smoking gun features that ONLY ransomware exhibits
"""

import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
import matplotlib.pyplot as plt
import seaborn as sns

def extract_type(label):
    return 'Benign' if label == 'Benign' else label.split('-')[0]

print("=" * 100)
print("RANSOMWARE UNIQUE SIGNATURE ANALYSIS")
print("=" * 100)

# Load data
df = pd.read_csv('data/Obfuscated-MalMem2022.csv')
df = df.drop_duplicates()

X = df.drop(['Category', 'Class'], axis=1).values
y = df['Category'].values
y_types = np.array([extract_type(label) for label in y])

feature_names = df.drop(['Category', 'Class'], axis=1).columns.tolist()

# Separate by class
benign_mask = (y_types == 'Benign')
ransomware_mask = (y_types == 'Ransomware')
spyware_mask = (y_types == 'Spyware')
trojan_mask = (y_types == 'Trojan')

X_benign = X[benign_mask]
X_ransomware = X[ransomware_mask]
X_spyware = X[spyware_mask]
X_trojan = X[trojan_mask]

print(f"\nSample counts:")
print(f"  Benign:     {len(X_benign)}")
print(f"  Ransomware: {len(X_ransomware)}")
print(f"  Spyware:    {len(X_spyware)}")
print(f"  Trojan:     {len(X_trojan)}")

# ============================================================================
# 1. FIND FEATURES WHERE RANSOMWARE IS UNIQUELY DIFFERENT
# ============================================================================
print("\n" + "=" * 100)
print("1. RANSOMWARE UNIQUE SIGNATURES")
print("=" * 100)

print("\nLooking for features where Ransomware is SIGNIFICANTLY different...")

ransomware_unique = []

for i, feat_name in enumerate(feature_names):
    # Statistics for each class
    benign_mean = X_benign[:, i].mean()
    ransomware_mean = X_ransomware[:, i].mean()
    spyware_mean = X_spyware[:, i].mean()
    trojan_mean = X_trojan[:, i].mean()

    # Check if ransomware is significantly different from other malware
    # but similar to how it differs from benign

    # Ransomware vs other malware
    diff_spyware = abs(ransomware_mean - spyware_mean)
    diff_trojan = abs(ransomware_mean - trojan_mean)

    # If ransomware is very different from both spyware and trojan
    if diff_spyware > 0.5 and diff_trojan > 0.5:
        ransomware_unique.append({
            'feature': feat_name,
            'ransomware_mean': ransomware_mean,
            'spyware_mean': spyware_mean,
            'trojan_mean': trojan_mean,
            'benign_mean': benign_mean,
            'diff_spyware': diff_spyware,
            'diff_trojan': diff_trojan
        })

print(f"\nFound {len(ransomware_unique)} potentially unique features:")
for item in sorted(ransomware_unique, key=lambda x: x['diff_spyware'] + x['diff_trojan'], reverse=True)[:10]:
    print(f"\n  {item['feature']}:")
    print(f"    Ransomware: {item['ransomware_mean']:.2f}")
    print(f"    Spyware:    {item['spyware_mean']:.2f} (diff: {item['diff_spyware']:.2f})")
    print(f"    Trojan:     {item['trojan_mean']:.2f} (diff: {item['diff_trojan']:.2f})")
    print(f"    Benign:     {item['benign_mean']:.2f}")

# ============================================================================
# 2. FEATURE IMPORTANCE FOR RANSOMWARE VS OTHER MALWARE
# ============================================================================
print("\n" + "=" * 100)
print("2. BINARY: RANSOMWARE vs OTHER MALWARE")
print("=" * 100)

# Create binary labels: Ransomware vs (Spyware + Trojan)
malware_mask = ransomware_mask | spyware_mask | trojan_mask
X_malware = X[malware_mask]
y_malware_binary = np.where(np.array([extract_type(label) for label in y[malware_mask]]) == 'Ransomware', 1, 0)

print(f"\nBinary classification:")
print(f"  Ransomware: {y_malware_binary.sum()}")
print(f"  Other malware: {len(y_malware_binary) - y_malware_binary.sum()}")

# Train RF to find discriminative features
X_train, X_test, y_train, y_test = train_test_split(X_malware, y_malware_binary, test_size=0.2, random_state=42, stratify=y_malware_binary)

scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)

rf = RandomForestClassifier(n_estimators=200, max_depth=20, random_state=42, n_jobs=-1)
rf.fit(X_train_scaled, y_train)

train_acc = rf.score(X_train_scaled, y_train) * 100
test_acc = rf.score(X_test_scaled, y_test) * 100

print(f"\nRandom Forest (Ransomware vs Other Malware):")
print(f"  Train Accuracy: {train_acc:.2f}%")
print(f"  Test Accuracy:  {test_acc:.2f}%")

if test_acc > 80:
    print("  ✓ Ransomware IS distinguishable from other malware!")
else:
    print("  ✗ Ransomware is NOT easily distinguishable")

# Top features for distinguishing ransomware
importances = rf.feature_importances_
top_20 = np.argsort(importances)[-20:][::-1]

print(f"\nTop 20 features that distinguish RANSOMWARE from other malware:")
for idx in top_20:
    print(f"  {feature_names[idx]:<50s}: {importances[idx]:.4f}")

# ============================================================================
# 3. STATISTICAL SIGNIFICANCE TESTS
# ============================================================================
print("\n" + "=" * 100)
print("3. STATISTICAL TESTS - WHICH FEATURES ARE TRULY DIFFERENT?")
print("=" * 100)

from scipy import stats

significant_features = []

for i, feat_name in enumerate(feature_names):
    # T-test: Ransomware vs Spyware
    t_stat_spy, p_val_spy = stats.ttest_ind(X_ransomware[:, i], X_spyware[:, i])

    # T-test: Ransomware vs Trojan
    t_stat_troj, p_val_troj = stats.ttest_ind(X_ransomware[:, i], X_trojan[:, i])

    # If significantly different from BOTH (p < 0.001)
    if p_val_spy < 0.001 and p_val_troj < 0.001:
        significant_features.append({
            'feature': feat_name,
            'p_val_spyware': p_val_spy,
            'p_val_trojan': p_val_troj,
            'mean_diff_spy': abs(X_ransomware[:, i].mean() - X_spyware[:, i].mean()),
            'mean_diff_troj': abs(X_ransomware[:, i].mean() - X_trojan[:, i].mean())
        })

print(f"\nStatistically significant features (p < 0.001): {len(significant_features)}")

for item in sorted(significant_features, key=lambda x: x['mean_diff_spy'] + x['mean_diff_troj'], reverse=True)[:15]:
    print(f"\n  {item['feature']}:")
    print(f"    vs Spyware: p={item['p_val_spyware']:.2e}, diff={item['mean_diff_spy']:.2f}")
    print(f"    vs Trojan:  p={item['p_val_trojan']:.2e}, diff={item['mean_diff_troj']:.2f}")

# ============================================================================
# 4. CORRELATION BETWEEN FEATURES
# ============================================================================
print("\n" + "=" * 100)
print("4. FEATURE CORRELATION ANALYSIS")
print("=" * 100)

# Find features that are highly correlated in ransomware but not in other malware
print("\nLooking for feature combinations that indicate ransomware...")

from sklearn.feature_selection import mutual_info_classif

# Mutual information for ransomware detection
mi_scores = mutual_info_classif(X_malware, y_malware_binary, random_state=42)
top_mi_indices = np.argsort(mi_scores)[-15:][::-1]

print(f"\nTop 15 features by Mutual Information (for ransomware detection):")
for idx in top_mi_indices:
    print(f"  {feature_names[idx]:<50s}: {mi_scores[idx]:.4f}")

# ============================================================================
# 5. SAVE CRITICAL FEATURES
# ============================================================================
print("\n" + "=" * 100)
print("5. RECOMMENDED FEATURES FOR RANSOMWARE DETECTION")
print("=" * 100)

# Combine results
critical_features = set()

# Add top RF features
critical_features.update([feature_names[idx] for idx in top_20[:10]])

# Add statistically significant features
critical_features.update([item['feature'] for item in significant_features[:10]])

# Add top MI features
critical_features.update([feature_names[idx] for idx in top_mi_indices[:10]])

print(f"\nCritical features for ransomware detection ({len(critical_features)} unique):")
for feat in sorted(critical_features):
    print(f"  - {feat}")

# Save to file
import json

analysis_results = {
    'ransomware_vs_other_malware_accuracy': test_acc,
    'num_significant_features': len(significant_features),
    'critical_features': sorted(list(critical_features)),
    'top_20_rf_features': [feature_names[idx] for idx in top_20],
    'top_15_mi_features': [feature_names[idx] for idx in top_mi_indices],
    'significant_features': [item['feature'] for item in significant_features]
}

with open('results/ransomware_signature_analysis.json', 'w') as f:
    json.dump(analysis_results, f, indent=2)

print(f"\n✓ Analysis saved to: results/ransomware_signature_analysis.json")

# ============================================================================
# 6. WHAT'S MISSING?
# ============================================================================
print("\n" + "=" * 100)
print("6. DATA GAPS - WHAT'S MISSING FOR BETTER DETECTION?")
print("=" * 100)

print("\nCurrent features capture:")
print("  ✓ Process information (pslist.*)")
print("  ✓ DLL loading (dlllist.*)")
print("  ✓ Handle usage (handles.*)")
print("  ✓ Module loading (ldrmodules.*)")
print("  ✓ Code injection (malfind.*)")
print("  ✓ Process hiding (psxview.*)")
print("  ✓ Services (svcscan.*)")
print("  ✓ Callbacks (callbacks.*)")

print("\n✗ MISSING CRITICAL RANSOMWARE INDICATORS:")
print("  1. File system activity patterns:")
print("     - Number of files modified/encrypted")
print("     - File extension changes (.encrypted, .locked, etc.)")
print("     - Speed of file modifications (rapid bulk changes)")
print("  2. Network activity:")
print("     - C2 communication patterns")
print("     - Tor/onion network connections")
print("     - Bitcoin wallet connections")
print("  3. Encryption behavior:")
print("     - Cryptographic API calls (CryptEncrypt, etc.)")
print("     - Large memory allocations for key storage")
print("     - Unusual CPU spikes during encryption")
print("  4. Ransom note artifacts:")
print("     - Creation of .txt/.html ransom notes")
print("     - Wallpaper changes")
print("     - Display message windows")

print("\n" + "=" * 100)
print("CONCLUSION")
print("=" * 100)

print(f"\n✓ Ransomware CAN be distinguished from other malware: {test_acc:.1f}% accuracy")
print(f"✓ Found {len(critical_features)} critical features")
print(f"✗ Current data is INCOMPLETE - missing file system & encryption indicators")
print(f"\n→ RECOMMENDATION: Engineer new features from existing data")
print(f"→ RECOMMENDATION: Augment dataset with synthetic ransomware-specific patterns")

print("=" * 100)
