"""
SYNTHETIC RANSOMWARE SAMPLE GENERATION
=======================================

Generate realistic synthetic ransomware samples that exhibit:
1. High file access patterns (encryption behavior)
2. Code injection signatures
3. Registry manipulation
4. Process hiding attempts
5. Cryptographic memory patterns

This augments the dataset to improve ransomware detection accuracy.
"""

import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler

print("=" * 100)
print("GENERATING SYNTHETIC RANSOMWARE SAMPLES")
print("=" * 100)

# Load augmented dataset
df = pd.read_csv('data/augmented_dataset.csv')

print(f"\nOriginal dataset: {df.shape}")

# Separate by class
benign = df[df['MalwareType'] == 'Benign']
ransomware = df[df['MalwareType'] == 'Ransomware']
spyware = df[df['MalwareType'] == 'Spyware']
trojan = df[df['MalwareType'] == 'Trojan']

print(f"\nClass distribution:")
print(f"  Benign:     {len(benign)}")
print(f"  Ransomware: {len(ransomware)}")
print(f"  Spyware:    {len(spyware)}")
print(f"  Trojan:     {len(trojan)}")

# ============================================================================
# 1. IDENTIFY RANSOMWARE-SPECIFIC PATTERNS
# ============================================================================
print("\n" + "=" * 100)
print("1. ANALYZING RANSOMWARE-SPECIFIC PATTERNS")
print("=" * 100)

# Calculate statistics for ransomware
ransomware_features = ransomware.drop(['Category', 'MalwareType'], axis=1)

# Key ransomware characteristics
key_features = [
    'handles.nfile',  # High file access
    'malfind.ninjections',  # Code injection
    'handles.nkey',  # Registry manipulation
    'ransomware_suspicion_score',  # Our engineered feature
    'encryption_behavior_proxy',  # Our engineered feature
    'file_access_burst',  # Our engineered feature
]

print("\nRansomware statistics for key features:")
for feat in key_features:
    if feat in ransomware_features.columns:
        mean = ransomware_features[feat].mean()
        std = ransomware_features[feat].std()
        p75 = ransomware_features[feat].quantile(0.75)
        p90 = ransomware_features[feat].quantile(0.90)
        print(f"  {feat:<40s}: mean={mean:8.2f}, std={std:8.2f}, p75={p75:8.2f}, p90={p90:8.2f}")

# ============================================================================
# 2. GENERATE SYNTHETIC SAMPLES - METHOD 1: AUGMENTED REAL SAMPLES
# ============================================================================
print("\n" + "=" * 100)
print("2. GENERATING SYNTHETIC SAMPLES - AUGMENTATION METHOD")
print("=" * 100)

n_synthetic = 5000
print(f"\nGenerating {n_synthetic} synthetic ransomware samples...")

synthetic_samples = []

for i in range(n_synthetic):
    # Randomly select a base ransomware sample
    base_idx = np.random.randint(len(ransomware))
    base_sample = ransomware_features.iloc[base_idx].copy()

    # Apply realistic perturbations
    for col in base_sample.index:
        if col in ransomware_features.columns:
            mean = ransomware_features[col].mean()
            std = ransomware_features[col].std()

            # Add gaussian noise
            noise = np.random.normal(0, std * 0.15)  # 15% std noise
            base_sample[col] = base_sample[col] + noise

            # Clip to reasonable ranges (no negative values)
            if base_sample[col] < 0:
                base_sample[col] = abs(base_sample[col])

    # Amplify ransomware-specific behaviors
    if 'handles.nfile' in base_sample.index:
        # Ransomware encrypts files -> high file access
        base_sample['handles.nfile'] *= np.random.uniform(1.1, 1.5)

    if 'malfind.ninjections' in base_sample.index:
        # Ransomware injects code
        base_sample['malfind.ninjections'] = max(base_sample['malfind.ninjections'],
                                                   np.random.uniform(5, 15))

    if 'handles.nkey' in base_sample.index:
        # Ransomware modifies registry
        base_sample['handles.nkey'] *= np.random.uniform(1.1, 1.3)

    if 'ransomware_suspicion_score' in base_sample.index:
        # Amplify suspicion score
        base_sample['ransomware_suspicion_score'] *= np.random.uniform(1.2, 1.5)

    if 'encryption_behavior_proxy' in base_sample.index:
        # Amplify encryption proxy
        base_sample['encryption_behavior_proxy'] *= np.random.uniform(1.2, 1.5)

    synthetic_samples.append(base_sample)

# Convert to DataFrame
df_synthetic = pd.DataFrame(synthetic_samples)

# Add labels
df_synthetic['Category'] = 'Ransomware-Synthetic'
df_synthetic['MalwareType'] = 'Ransomware'

print(f"✓ Generated {len(df_synthetic)} synthetic samples")

# ============================================================================
# 3. GENERATE SYNTHETIC SAMPLES - METHOD 2: HYBRID SAMPLES
# ============================================================================
print("\n" + "=" * 100)
print("3. GENERATING HYBRID RANSOMWARE SAMPLES")
print("=" * 100)

n_hybrid = 3000
print(f"\nGenerating {n_hybrid} hybrid samples (ransomware + trojan traits)...")

hybrid_samples = []

for i in range(n_hybrid):
    # Mix ransomware and trojan characteristics
    ransomware_idx = np.random.randint(len(ransomware))
    trojan_idx = np.random.randint(len(trojan))

    ransomware_sample = ransomware_features.iloc[ransomware_idx]
    trojan_sample = trojan.drop(['Category', 'MalwareType'], axis=1).iloc[trojan_idx]

    # Blend features (70% ransomware, 30% trojan)
    hybrid_sample = 0.7 * ransomware_sample + 0.3 * trojan_sample

    # Enhance ransomware-specific traits
    if 'file_access_burst' in hybrid_sample.index:
        hybrid_sample['file_access_burst'] = 1.0  # Always high

    if 'crypto_api_proxy' in hybrid_sample.index:
        hybrid_sample['crypto_api_proxy'] = 1.0  # Always high

    hybrid_samples.append(hybrid_sample)

df_hybrid = pd.DataFrame(hybrid_samples)
df_hybrid['Category'] = 'Ransomware-Hybrid'
df_hybrid['MalwareType'] = 'Ransomware'

print(f"✓ Generated {len(df_hybrid)} hybrid samples")

# ============================================================================
# 4. COMBINE ALL DATA
# ============================================================================
print("\n" + "=" * 100)
print("4. COMBINING ORIGINAL + SYNTHETIC DATA")
print("=" * 100)

# Combine original + synthetic + hybrid
df_final = pd.concat([df, df_synthetic, df_hybrid], ignore_index=True)

print(f"\nFinal dataset shape: {df_final.shape}")
print(f"\nClass distribution:")
for malware_type in ['Benign', 'Ransomware', 'Spyware', 'Trojan']:
    count = (df_final['MalwareType'] == malware_type).sum()
    pct = 100 * count / len(df_final)
    print(f"  {malware_type:12s}: {count:6d} ({pct:5.2f}%)")

# Calculate increase
original_ransomware = len(ransomware)
final_ransomware = (df_final['MalwareType'] == 'Ransomware').sum()
increase = final_ransomware - original_ransomware
increase_pct = 100 * increase / original_ransomware

print(f"\n✓ Ransomware samples increased by {increase} (+{increase_pct:.1f}%)")

# ============================================================================
# 5. VALIDATE SYNTHETIC DATA QUALITY
# ============================================================================
print("\n" + "=" * 100)
print("5. VALIDATING SYNTHETIC DATA QUALITY")
print("=" * 100)

# Check if synthetic samples are realistic
real_ransomware_features = ransomware.drop(['Category', 'MalwareType'], axis=1)
synthetic_features = df_synthetic.drop(['Category', 'MalwareType'], axis=1)

print("\nComparing real vs synthetic ransomware:")
print(f"{'Feature':<40s} {'Real Mean':>12s} {'Synth Mean':>12s} {'Difference':>12s}")
print("-" * 80)

for col in key_features:
    if col in real_ransomware_features.columns:
        real_mean = real_ransomware_features[col].mean()
        synth_mean = synthetic_features[col].mean()
        diff = abs((synth_mean - real_mean) / (real_mean + 1e-10)) * 100

        status = "✓" if diff < 30 else "⚠"
        print(f"{status} {col:<38s} {real_mean:>12.2f} {synth_mean:>12.2f} {diff:>11.1f}%")

# ============================================================================
# 6. SAVE ENHANCED DATASET
# ============================================================================
print("\n" + "=" * 100)
print("6. SAVING ENHANCED DATASET")
print("=" * 100)

output_path = 'data/enhanced_dataset.csv'
df_final.to_csv(output_path, index=False)

print(f"\n✓ Enhanced dataset saved to: {output_path}")
print(f"  Original samples:  {len(df)}")
print(f"  Synthetic samples: {len(df_synthetic)}")
print(f"  Hybrid samples:    {len(df_hybrid)}")
print(f"  Total samples:     {len(df_final)}")

# Save generation info
import json

generation_info = {
    'original_samples': len(df),
    'synthetic_ransomware': len(df_synthetic),
    'hybrid_ransomware': len(df_hybrid),
    'total_samples': len(df_final),
    'ransomware_increase': increase,
    'ransomware_increase_pct': increase_pct,
    'final_class_distribution': {
        'Benign': int((df_final['MalwareType'] == 'Benign').sum()),
        'Ransomware': int((df_final['MalwareType'] == 'Ransomware').sum()),
        'Spyware': int((df_final['MalwareType'] == 'Spyware').sum()),
        'Trojan': int((df_final['MalwareType'] == 'Trojan').sum())
    }
}

with open('results/synthetic_generation_info.json', 'w') as f:
    json.dump(generation_info, f, indent=2)

print(f"✓ Generation info saved to: results/synthetic_generation_info.json")

print("\n" + "=" * 100)
print("SYNTHETIC DATA GENERATION COMPLETE!")
print("=" * 100)
print(f"\n✓ Enhanced dataset with {len(df_final)} samples")
print(f"✓ Ransomware samples: {original_ransomware} → {final_ransomware} (+{increase_pct:.1f}%)")
print(f"\nNext step: Train production model on enhanced dataset")
print("=" * 100)
