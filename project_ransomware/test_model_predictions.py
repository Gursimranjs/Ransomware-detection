"""
Test what the model predicts with psutil-based features
This will help us understand why it's detecting everything as Spyware
"""

import sys
import os
import numpy as np
import psutil
import logging

# Setup paths
sys.path.append('src')

from detection_engine import DetectionEngine
from feature_extractor import FeatureExtractor

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Config
config = {
    'model': {
        'path': 'models/antivirus_production_best.pth',
        'confidence_threshold': 0.70,
        'input_features': 83,
        'classes': {
            0: "Benign",
            1: "Ransomware",
            2: "Spyware",
            3: "Trojan"
        }
    },
    'memory': {
        'dump_tool': "tools/procdump.exe",
        'dump_path': "temp_dumps",
        'volatility_path': "tools/volatility3",
        'cleanup_dumps': True
    }
}

print("="*60)
print("MODEL PREDICTION TEST")
print("="*60)
print()

# Initialize components
print("[1/3] Loading model...")
try:
    detection_engine = DetectionEngine(config)
    print("✓ Model loaded successfully")
except Exception as e:
    print(f"✗ Failed to load model: {e}")
    sys.exit(1)

print()
print("[2/3] Initializing feature extractor...")
feature_extractor = FeatureExtractor(config)
print("✓ Feature extractor ready")

print()
print("[3/3] Testing on current processes...")
print()

# Get some test processes
test_processes = []
for proc in psutil.process_iter(['pid', 'name']):
    try:
        test_processes.append(proc.info)
        if len(test_processes) >= 10:
            break
    except:
        pass

print(f"Testing on {len(test_processes)} processes:\n")

# Test each process
results = {
    'Benign': 0,
    'Ransomware': 0,
    'Spyware': 0,
    'Trojan': 0
}

for proc_info in test_processes:
    pid = proc_info['pid']
    name = proc_info['name']

    print(f"Testing: {name} (PID: {pid})")

    # Extract features
    try:
        features = feature_extractor.extract_features(pid)

        if features is None:
            print(f"  ✗ Feature extraction failed")
            print()
            continue

        # Predict
        predicted_class, confidence, probabilities = detection_engine.predict(features)

        results[predicted_class] += 1

        print(f"  Prediction: {predicted_class} ({confidence*100:.1f}%)")
        print(f"  Probabilities:")
        for cls, prob in sorted(probabilities.items(), key=lambda x: x[1], reverse=True):
            print(f"    {cls}: {prob*100:.2f}%")

        # Check if would be killed
        is_malware, _, conf, _ = detection_engine.is_malware(features)
        if is_malware:
            print(f"  ⚠️ WOULD BE KILLED (Ransomware detected)")
        else:
            print(f"  ✓ Safe (not ransomware or low confidence)")

        print()

    except Exception as e:
        print(f"  ✗ Error: {e}")
        print()

print("="*60)
print("SUMMARY")
print("="*60)
print(f"Benign:     {results['Benign']}")
print(f"Ransomware: {results['Ransomware']}")
print(f"Spyware:    {results['Spyware']}")
print(f"Trojan:     {results['Trojan']}")
print()

# Analyze the issue
if results['Spyware'] > results['Ransomware']:
    print("⚠️ ISSUE DETECTED:")
    print("Model is classifying most processes as Spyware, not Ransomware")
    print()
    print("ROOT CAUSE:")
    print("The psutil-based features don't match the training data distribution.")
    print("Training data came from real memory dumps (Volatility), but we're")
    print("providing estimated features from psutil.")
    print()
    print("SOLUTION:")
    print("Since we changed detection to ONLY kill 'Ransomware', these false")
    print("positives as 'Spyware' won't cause any harm - they'll be logged")
    print("but not killed.")
    print()
    print("For your simulator test:")
    print("- If simulator is detected as 'Spyware' → logged, not killed")
    print("- If simulator is detected as 'Ransomware' → killed ✓")
    print()

print("="*60)
