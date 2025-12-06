# Project Structure

## 📁 Directory Organization

```
project_ransomware/
│
├── 📄 README.md                          # Main project documentation
├── 📄 INSTALLATION_GUIDE.md              # Setup and usage instructions
├── 📄 PROJECT_STRUCTURE.md               # This file
│
├── 🔧 Core Application Files
│   ├── gui_app_standalone.py             # Main GUI application (production)
│   ├── ransomware_simulator.py           # Safe ransomware behavior simulator
│   ├── train_antivirus_production.py     # ML model training script
│   └── test_model_predictions.py         # Model testing utility
│
├── 🏗️ Build Scripts
│   ├── build_final.bat                   # Build protector for Windows
│   ├── build_simulator.bat               # Build simulator for Windows
│   └── create_separate_packages.sh       # Create distribution packages
│
├── ⚙️ Configuration
│   ├── config.yaml                       # System configuration
│   └── requirements.txt                  # Python dependencies
│
├── 📊 data/                              # Training & test datasets
│   ├── Obfuscated-MalMem2022.csv        # Original CIC-MalMem-2022 dataset
│   └── enhanced_dataset.csv              # Engineered features dataset
│
├── 🔬 data_engineering/                  # Data preparation pipeline
│   ├── 01_analyze_ransomware_signatures.py
│   ├── 02_feature_engineering.py
│   └── 03_generate_synthetic_ransomware.py
│
├── 🤖 models/                            # Trained ML models
│   └── antivirus_production_best.pth    # Production CNN+Attention model
│
├── 📈 results/                           # Training results & metrics
│   ├── antivirus_training_results.json
│   ├── data_analysis.json
│   ├── feature_engineering_summary.json
│   ├── optimal_results.json
│   ├── production_grade_results.json
│   ├── ransomware_signature_analysis.json
│   └── synthetic_generation_info.json
│
└── 🔍 src/                               # Detection system modules
    ├── behavioral_filter.py              # Heuristic threat detection
    ├── cnn_attention_model.py            # Neural network architecture
    ├── detection_engine.py               # ML inference engine
    ├── feature_extractor.py              # Process feature extraction
    ├── model.py                          # Model wrapper
    ├── monitor.py                        # Process monitoring
    ├── realtime_agent.py                 # Real-time detection agent
    ├── response_system.py                # Threat response actions
    └── utils.py                          # Utility functions
```

---

## 🎯 File Purposes

### Application Files

**`gui_app_standalone.py`**
- Main ransomware detection GUI application
- Real-time process monitoring
- User confirmation popups
- Threat neutralization
- **Run this for protection**

**`ransomware_simulator.py`**
- Safe behavioral simulator
- Mimics ransomware patterns without encryption
- **Run this for testing**

**`train_antivirus_production.py`**
- Complete ML model training pipeline
- Trains CNN+Attention model
- Saves best model checkpoint
- **Professor will review this for thesis**

**`test_model_predictions.py`**
- Test model predictions on live processes
- Debug feature extraction
- Verify model behavior

---

### Data Pipeline

**`data_engineering/01_analyze_ransomware_signatures.py`**
- Analyzes ransomware vs benign patterns
- Statistical analysis of features
- Identifies discriminative features

**`data_engineering/02_feature_engineering.py`**
- Creates 28 engineered features
- Combines with 55 original features
- Generates enhanced dataset (83 features total)

**`data_engineering/03_generate_synthetic_ransomware.py`**
- SMOTE-based data augmentation
- Balances dataset classes
- Improves model generalization

---

### Detection Modules

**`src/monitor.py`**
- Scans Windows processes every 2 seconds
- Detects new process creation
- Extracts basic process info (PID, name, I/O stats)

**`src/behavioral_filter.py`**
- Fast heuristic screening (< 1 sec)
- Risk scoring based on:
  - File write patterns
  - CPU usage
  - Memory consumption
  - Process names
  - Suspicious behaviors

**`src/feature_extractor.py`**
- Extracts 83 features from processes
- Uses psutil for live process analysis
- Handles permission errors gracefully

**`src/detection_engine.py`**
- Loads trained CNN+Attention model
- Runs ML inference on extracted features
- Classifies: Benign, Ransomware, Spyware, Trojan
- **Only flags Ransomware** (others ignored)

**`src/response_system.py`**
- Terminates malicious processes
- Quarantines executable files
- Logs detection events
- Generates audit trails

---

## 🔄 Execution Flow

### 1. Training Phase (Done Once)
```
data/
  ↓
data_engineering/ (Feature engineering)
  ↓
train_antivirus_production.py
  ↓
models/antivirus_production_best.pth
```

### 2. Detection Phase (Runtime)
```
gui_app_standalone.py
  ↓
monitor.py → Detect new process
  ↓
behavioral_filter.py → Quick risk check
  ↓
feature_extractor.py → Extract 83 features
  ↓
detection_engine.py → ML prediction
  ↓
response_system.py → Kill if ransomware
```

### 3. Testing Phase
```
Run: gui_app_standalone.py (as admin)
  ↓
Run: ransomware_simulator.exe
  ↓
Popup appears → Click KILL
  ↓
Process terminated ✓
```

---

## 📦 Build Outputs

**After running build scripts:**

```
RansomwareProtector_Complete/
├── RansomwareProtector.exe      # Main executable (~250 MB)
├── models/
│   └── antivirus_production_best.pth
├── logs/                         # Runtime logs
└── quarantine/                   # Quarantined threats

dist/
└── ransomware_simulator.exe      # Simulator (~10 MB)
```

---

## 🎓 For Thesis Review

### Professor Should Check:

1. **Data Pipeline** (`data_engineering/`)
   - Feature engineering approach
   - Data augmentation strategy

2. **Model Training** (`train_antivirus_production.py`)
   - CNN+Attention architecture
   - Training methodology
   - Evaluation metrics

3. **Detection System** (`src/`)
   - Real-time monitoring
   - Hybrid detection (behavioral + ML)
   - Threat response logic

4. **Results** (`results/`)
   - Performance metrics
   - Training history
   - Analysis results

5. **Application** (`gui_app_standalone.py`)
   - User interface
   - Real-time operation
   - Production readiness

---

## 🔑 Key Metrics (From `results/`)

| Metric | Value |
|--------|-------|
| Overall Accuracy | 86.24% |
| Malware Detection Rate | 100% |
| False Positive Rate | 0% |
| Ransomware F1-Score | 81.03% |
| Production Score | 92.41% |

---

## 🚀 Quick Start

### For Thesis Defense Demo:

```bash
# 1. Build protector (one time)
build_final.bat

# 2. Build simulator (one time)
build_simulator.bat

# 3. Run protector
cd RansomwareProtector_Complete
RansomwareProtector.exe  # As admin

# 4. Test with simulator
cd ..\dist
ransomware_simulator.exe
```

**Detection happens in 2-4 seconds!**

---

This structure represents a complete end-to-end ransomware detection system suitable for Master's thesis evaluation.
