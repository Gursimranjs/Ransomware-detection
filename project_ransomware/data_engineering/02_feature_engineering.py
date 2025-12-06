"""
ADVANCED FEATURE ENGINEERING FOR RANSOMWARE DETECTION
======================================================

Create NEW features that capture ransomware-specific behavior patterns:
1. Behavioral ratios and combinations
2. Anomaly indicators
3. Temporal patterns (simulated from static features)
4. Encryption behavior proxies
"""

import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler

def extract_type(label):
    return 'Benign' if label == 'Benign' else label.split('-')[0]

print("=" * 100)
print("ADVANCED FEATURE ENGINEERING FOR RANSOMWARE DETECTION")
print("=" * 100)

# Load original data
df = pd.read_csv('data/Obfuscated-MalMem2022.csv')
df = df.drop_duplicates()

print(f"\nOriginal dataset: {df.shape}")

# Extract labels
y = df['Category'].apply(extract_type)
df['MalwareType'] = y

# Drop original labels temporarily
X_original = df.drop(['Category', 'Class', 'MalwareType'], axis=1)

print(f"Original features: {X_original.shape[1]}")

# ============================================================================
# 1. BEHAVIORAL RATIOS - Capture suspicious proportions
# ============================================================================
print("\n" + "=" * 100)
print("1. ENGINEERING BEHAVIORAL RATIO FEATURES")
print("=" * 100)

engineered_features = {}

# File handle to event ratio (ransomware accesses many files rapidly)
engineered_features['file_to_event_ratio'] = X_original['handles.nfile'] / (X_original['handles.nevent'] + 1)

# DLL loading intensity (ransomware may load crypto DLLs)
engineered_features['dll_load_intensity'] = X_original['dlllist.avg_dlls_per_proc'] / (X_original['pslist.nproc'] + 1)

# Handle churn (ransomware opens/closes many handles)
engineered_features['handle_churn'] = X_original['handles.nhandles'] / (X_original['pslist.nproc'] + 1)

# Code injection intensity
engineered_features['injection_intensity'] = X_original['malfind.ninjections'] / (X_original['pslist.nproc'] + 1)

# Process hiding tendency
engineered_features['hiding_score'] = (
    X_original['psxview.not_in_pslist'] +
    X_original['psxview.not_in_eprocess_pool'] +
    X_original['psxview.not_in_csrss_handles']
) / 3.0

# Module suspicion score
engineered_features['module_suspicion'] = (
    X_original['ldrmodules.not_in_load_avg'] +
    X_original['ldrmodules.not_in_init_avg'] +
    X_original['ldrmodules.not_in_mem_avg']
) / 3.0

# Key/registry manipulation (ransomware modifies registry)
engineered_features['registry_manipulation'] = X_original['handles.nkey'] / (X_original['pslist.nproc'] + 1)

# Mutex usage (ransomware uses mutexes for synchronization)
engineered_features['mutex_intensity'] = X_original['handles.nmutant'] / (X_original['pslist.nproc'] + 1)

# Semaphore usage (encryption synchronization)
engineered_features['semaphore_intensity'] = X_original['handles.nsemaphore'] / (X_original['pslist.nproc'] + 1)

# Section handles (memory manipulation)
engineered_features['section_manipulation'] = X_original['handles.nsection'] / (X_original['pslist.nproc'] + 1)

print(f"Created {len(engineered_features)} ratio features")

# ============================================================================
# 2. ANOMALY INDICATORS - Detect unusual patterns
# ============================================================================
print("\n" + "=" * 100)
print("2. ENGINEERING ANOMALY INDICATORS")
print("=" * 100)

# Abnormal thread count (encryption threads)
thread_mean = X_original['pslist.avg_threads'].mean()
thread_std = X_original['pslist.avg_threads'].std()
engineered_features['thread_anomaly'] = np.abs(X_original['pslist.avg_threads'] - thread_mean) / (thread_std + 1)

# Abnormal handle count (file access burst)
handle_mean = X_original['handles.avg_handles_per_proc'].mean()
handle_std = X_original['handles.avg_handles_per_proc'].std()
engineered_features['handle_anomaly'] = np.abs(X_original['handles.avg_handles_per_proc'] - handle_mean) / (handle_std + 1)

# DLL loading anomaly
dll_mean = X_original['dlllist.avg_dlls_per_proc'].mean()
dll_std = X_original['dlllist.avg_dlls_per_proc'].std()
engineered_features['dll_anomaly'] = np.abs(X_original['dlllist.avg_dlls_per_proc'] - dll_mean) / (dll_std + 1)

# Code injection anomaly
injection_threshold = X_original['malfind.ninjections'].quantile(0.75)
engineered_features['high_injection'] = (X_original['malfind.ninjections'] > injection_threshold).astype(float)

# Protection anomaly (unusual memory protection)
protection_threshold = X_original['malfind.protection'].quantile(0.75)
engineered_features['high_protection'] = (X_original['malfind.protection'] > protection_threshold).astype(float)

print(f"Created {5} anomaly indicators")

# ============================================================================
# 3. COMPOSITE SCORES - Combine multiple signals
# ============================================================================
print("\n" + "=" * 100)
print("3. ENGINEERING COMPOSITE SCORES")
print("=" * 100)

# Ransomware suspicion score (weighted combination of key indicators)
engineered_features['ransomware_suspicion_score'] = (
    0.3 * engineered_features['file_to_event_ratio'] +
    0.2 * engineered_features['injection_intensity'] +
    0.2 * engineered_features['module_suspicion'] +
    0.15 * engineered_features['registry_manipulation'] +
    0.15 * engineered_features['hiding_score']
)

# Encryption behavior proxy (high CPU, memory, file access)
engineered_features['encryption_behavior_proxy'] = (
    engineered_features['handle_churn'] *
    engineered_features['thread_anomaly'] *
    (X_original['malfind.commitCharge'] + 1)
).apply(np.log1p)  # Log transform to handle large values

# Malicious activity intensity
engineered_features['malicious_activity_intensity'] = (
    X_original['malfind.ninjections'] +
    X_original['malfind.uniqueInjections'] +
    X_original['ldrmodules.not_in_load'] +
    X_original['ldrmodules.not_in_init'] +
    X_original['ldrmodules.not_in_mem']
)

# Service manipulation (ransomware disables security services)
engineered_features['service_manipulation_score'] = (
    X_original['svcscan.nservices'] / (X_original['svcscan.nactive'] + 1)
)

print(f"Created {4} composite scores")

# ============================================================================
# 4. INTERACTION FEATURES - Capture feature combinations
# ============================================================================
print("\n" + "=" * 100)
print("4. ENGINEERING INTERACTION FEATURES")
print("=" * 100)

# File access * Injection (ransomware encrypts files after injection)
engineered_features['file_injection_interaction'] = (
    X_original['handles.nfile'] * X_original['malfind.ninjections']
)

# Registry * Hiding (ransomware modifies registry while hiding)
engineered_features['registry_hiding_interaction'] = (
    X_original['handles.nkey'] * engineered_features['hiding_score']
)

# Memory manipulation * Code injection
engineered_features['memory_injection_interaction'] = (
    X_original['handles.nsection'] * X_original['malfind.ninjections']
)

# Thread count * File access (encryption threads accessing files)
engineered_features['thread_file_interaction'] = (
    X_original['pslist.avg_threads'] * X_original['handles.nfile']
)

print(f"Created {4} interaction features")

# ============================================================================
# 5. DOMAIN-SPECIFIC FEATURES - Ransomware-specific patterns
# ============================================================================
print("\n" + "=" * 100)
print("5. ENGINEERING DOMAIN-SPECIFIC FEATURES")
print("=" * 100)

# File access burst indicator (ransomware encrypts many files)
file_access_threshold = X_original['handles.nfile'].quantile(0.75)
engineered_features['file_access_burst'] = (
    (X_original['handles.nfile'] > file_access_threshold).astype(float)
)

# Cryptographic API proxy (based on memory commits)
crypto_threshold = X_original['malfind.commitCharge'].quantile(0.75)
engineered_features['crypto_api_proxy'] = (
    (X_original['malfind.commitCharge'] > crypto_threshold).astype(float)
)

# Multi-process coordination (ransomware often uses multiple processes)
engineered_features['multi_process_coordination'] = (
    X_original['pslist.nproc'] * engineered_features['mutex_intensity']
)

# Rapid execution indicator (based on thread and handle activity)
engineered_features['rapid_execution_indicator'] = np.sqrt(
    X_original['pslist.avg_threads'] * X_original['handles.avg_handles_per_proc']
)

# Stealth operation (process hiding + module hiding)
engineered_features['stealth_operation'] = (
    engineered_features['hiding_score'] * engineered_features['module_suspicion']
)

print(f"Created {5} domain-specific features")

# ============================================================================
# 6. COMBINE ALL FEATURES
# ============================================================================
print("\n" + "=" * 100)
print("6. COMBINING ORIGINAL + ENGINEERED FEATURES")
print("=" * 100)

# Convert engineered features to DataFrame
df_engineered = pd.DataFrame(engineered_features)

# Combine with original
df_augmented = pd.concat([X_original, df_engineered], axis=1)

# Add back labels
df_augmented['Category'] = df['Category'].values
df_augmented['MalwareType'] = y.values

print(f"\nAugmented dataset shape: {df_augmented.shape}")
print(f"Original features: {X_original.shape[1]}")
print(f"Engineered features: {len(engineered_features)}")
print(f"Total features: {df_augmented.shape[1] - 2}")  # Excluding labels

# ============================================================================
# 7. FEATURE IMPORTANCE ON NEW DATASET
# ============================================================================
print("\n" + "=" * 100)
print("7. EVALUATING ENGINEERED FEATURES")
print("=" * 100)

from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split

# Separate features and labels
X_aug = df_augmented.drop(['Category', 'MalwareType'], axis=1)
y_aug = df_augmented['MalwareType']

# Encode labels
label_map = {'Benign': 0, 'Ransomware': 1, 'Spyware': 2, 'Trojan': 3}
y_encoded = np.array([label_map[label] for label in y_aug])

# Train/test split
X_train, X_test, y_train, y_test = train_test_split(
    X_aug, y_encoded, test_size=0.2, random_state=42, stratify=y_encoded
)

# Scale
scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)

# Train RF
rf = RandomForestClassifier(n_estimators=200, max_depth=25, random_state=42, n_jobs=-1)
rf.fit(X_train_scaled, y_train)

train_acc = rf.score(X_train_scaled, y_train) * 100
test_acc = rf.score(X_test_scaled, y_test) * 100

print(f"\nRandom Forest Performance:")
print(f"  With ORIGINAL features only: 87.0% (from previous analysis)")
print(f"  With AUGMENTED features:     {test_acc:.2f}%")

improvement = test_acc - 87.0
if improvement > 0:
    print(f"  ✓ Improvement: +{improvement:.2f}%")
else:
    print(f"  → No significant improvement")

# Top features
importances = rf.feature_importances_
feature_names = X_aug.columns.tolist()
top_30 = np.argsort(importances)[-30:][::-1]

print(f"\nTop 30 features (including engineered):")
for idx in top_30:
    feat_name = feature_names[idx]
    is_engineered = feat_name in engineered_features
    marker = "🆕" if is_engineered else "  "
    print(f"  {marker} {feat_name:<55s}: {importances[idx]:.4f}")

# Count engineered features in top 30
engineered_in_top30 = sum([1 for idx in top_30 if feature_names[idx] in engineered_features])
print(f"\nEngineered features in top 30: {engineered_in_top30}/{30}")

# ============================================================================
# 8. SAVE AUGMENTED DATASET
# ============================================================================
print("\n" + "=" * 100)
print("8. SAVING AUGMENTED DATASET")
print("=" * 100)

# Save
output_path = 'data/augmented_dataset.csv'
df_augmented.to_csv(output_path, index=False)

print(f"\n✓ Augmented dataset saved to: {output_path}")
print(f"  Shape: {df_augmented.shape}")
print(f"  Features: {df_augmented.shape[1] - 2}")

# Save feature names for reference
feature_info = {
    'original_features': X_original.columns.tolist(),
    'engineered_features': list(engineered_features.keys()),
    'total_features': df_augmented.shape[1] - 2,
    'performance_improvement': improvement
}

import json
with open('results/feature_engineering_summary.json', 'w') as f:
    json.dump(feature_info, f, indent=2)

print(f"✓ Feature info saved to: results/feature_engineering_summary.json")

print("\n" + "=" * 100)
print("FEATURE ENGINEERING COMPLETE!")
print("=" * 100)
print(f"\n✓ Created {len(engineered_features)} new features")
print(f"✓ Total features: {df_augmented.shape[1] - 2}")
print(f"✓ Performance: {test_acc:.2f}% (vs 87.0% baseline)")
print(f"\nNext step: Train specialized ransomware detection model")
print("=" * 100)
