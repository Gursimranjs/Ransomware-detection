#!/bin/bash

echo "================================================"
echo "Creating Separate Packages"
echo "================================================"

# Clean old packages
rm -rf RansomwareProtector_Package RansomwareSimulator_Package
rm -f RansomwareProtector.zip RansomwareSimulator.zip

# ===================================
# PACKAGE 1: PROTECTOR (Main Product)
# ===================================
echo ""
echo "[1/2] Creating Protector Package..."

mkdir -p RansomwareProtector_Package

# Copy protector source
cp gui_app_standalone.py RansomwareProtector_Package/
cp build_final.bat RansomwareProtector_Package/
cp verify_before_build.bat RansomwareProtector_Package/

# Copy dependencies
cp -r models RansomwareProtector_Package/
cp -r src RansomwareProtector_Package/

# Create README
cat > RansomwareProtector_Package/README.md << 'EOF'
# Ransomware Protector - Installation

## Quick Setup (5 minutes)

### Step 1: Install Dependencies
```powershell
py -m pip install pyinstaller pyyaml torch numpy scikit-learn psutil
```

### Step 2: Build
```powershell
cmd /c build_final.bat
```
Wait ~2-3 minutes for build to complete.

### Step 3: Run (as Administrator!)
```powershell
cd RansomwareProtector_Complete
# Right-click RansomwareProtector.exe
# Click "Run as administrator"
# Click START button
```

## Features
- Real-time ransomware detection
- AI-powered analysis (CNN + Attention model)
- User confirmation before killing processes
- Quarantine infected files
- Behavioral + ML hybrid detection

## System Requirements
- Windows 10/11 (64-bit)
- 8 GB RAM minimum
- Python 3.9+ (for building)
- Administrator privileges (for running)

---
**Master's Thesis Project** | AI-Powered Ransomware Detection
EOF

# Create ZIP
echo "Creating RansomwareProtector.zip..."
zip -r RansomwareProtector.zip RansomwareProtector_Package/

# ===================================
# PACKAGE 2: SIMULATOR (Testing Tool)
# ===================================
echo ""
echo "[2/2] Creating Simulator Package..."

mkdir -p RansomwareSimulator_Package

# Copy simulator source
cp ransomware_simulator.py RansomwareSimulator_Package/
cp build_simulator.bat RansomwareSimulator_Package/

# Create README
cat > RansomwareSimulator_Package/README.md << 'EOF'
# Ransomware Simulator - Testing Tool

⚠️ **SAFE TEST TOOL** - Does NOT encrypt files!

## Quick Setup (1 minute)

### Step 1: Install PyInstaller
```powershell
py -m pip install pyinstaller
```

### Step 2: Build
```powershell
cmd /c build_simulator.bat
```
Wait ~30 seconds.

### Step 3: Run
```powershell
cd dist
.\ransomware_simulator.exe
# Press ENTER to start simulation
```

## What It Does

**Simulates ransomware behavior WITHOUT harming files:**
- Creates test files in temp directory
- Simulates file enumeration
- Mimics rapid I/O patterns
- Triggers encryption-like memory operations
- Creates fake ransom note

**100% SAFE** - All activity isolated to temp folder!

## For Testing

1. Start RansomwareProtector
2. Click START
3. Run this simulator
4. Watch detection happen in 2-4 seconds!

---
**Use this to test your ransomware detection system**
EOF

# Create run script for convenience
cat > RansomwareSimulator_Package/RUN_SIMULATOR.bat << 'EOF'
@echo off
echo ============================================
echo   Ransomware Simulator - Safe Test Tool
echo ============================================
echo.
echo This is a SAFE behavioral simulator.
echo No files will be encrypted or harmed.
echo.
echo Make sure RansomwareProtector is running!
echo.
pause

cd dist
ransomware_simulator.exe
EOF

# Create ZIP
echo "Creating RansomwareSimulator.zip..."
zip -r RansomwareSimulator.zip RansomwareSimulator_Package/

echo ""
echo "================================================"
echo "Packages Created Successfully!"
echo "================================================"
echo ""
echo "📦 RansomwareProtector.zip"
du -sh RansomwareProtector.zip
echo "   → Main product (install once)"
echo ""
echo "📦 RansomwareSimulator.zip"
du -sh RansomwareSimulator.zip
echo "   → Testing tool (lightweight)"
echo ""
echo "================================================"
echo ""
echo "USAGE:"
echo ""
echo "1. Download RansomwareProtector.zip"
echo "   → Extract and build ONCE"
echo "   → Install on your main system"
echo ""
echo "2. Download RansomwareSimulator.zip"
echo "   → Extract and build ONCE"
echo "   → Transfer .exe to test machines"
echo "   → Or share with others to test"
echo ""
echo "================================================"
