# 🛡️ Ransomware Detection System - Installation Guide

## NEW: Simplified Installation (Separate Packages)

Instead of one big package, we now have **TWO separate packages** for easier setup:

---

## 📦 Package 1: RansomwareProtector.zip (1.9 MB)

**What:** The main antivirus application
**Setup once on:** Your Windows PC where you want protection
**Size:** 1.9 MB

### Quick Setup:

```powershell
# 1. Download RansomwareProtector.zip
# 2. Extract it
# 3. Open PowerShell in extracted folder

# Install dependencies
py -m pip install pyinstaller pyyaml torch numpy scikit-learn psutil

# Build (wait 2-3 minutes)
cmd /c build_final.bat

# Run (as administrator)
cd RansomwareProtector_Complete
# Right-click RansomwareProtector.exe → Run as administrator
# Click START
```

**You're protected!** ✅

---

## 📦 Package 2: RansomwareSimulator.zip (8 KB)

**What:** Safe testing tool that mimics ransomware behavior
**Setup once on:** Any machine (or share with others)
**Size:** Only 8 KB!

### Quick Setup:

```powershell
# 1. Download RansomwareSimulator.zip
# 2. Extract it
# 3. Open PowerShell in extracted folder

# Install PyInstaller
py -m pip install pyinstaller

# Build (wait 30 seconds)
cmd /c build_simulator.bat

# Run
cd dist
.\ransomware_simulator.exe
```

**Testing ready!** ✅

---

## 🎯 For Your Thesis Demo

### Setup Plan:

**Main Machine (Your Windows PC):**
1. Download **RansomwareProtector.zip**
2. Build and install it once
3. Keep it running during demo

**Test Machine (VM or another laptop):**
1. Download **RansomwareSimulator.zip** (tiny!)
2. Build it once
3. Copy `dist\ransomware_simulator.exe` to USB drive
4. Transfer to VM during demo

### Demo Flow:

```
Your Laptop              →  USB/Network  →  VM (Isolated)
(Protector running)                          ↓
                                    Run simulator.exe
                                             ↓
                            Detection happens in 2-4 seconds!
                                             ↓
                                    Popup appears → Click KILL
                                             ↓
                                    Process terminated! ✅
```

---

## 💡 Benefits of Separate Packages

### ✅ Protector (1.9 MB)
- Setup **once** on your main machine
- Contains ML model (large file)
- Full installation process
- **Keep this private** (your thesis work)

### ✅ Simulator (8 KB)
- **Super lightweight!**
- Build once, share everywhere
- No dependencies in the .exe
- **Shareable** with classmates/professors for testing
- Can email it (only 10 MB after build)

---

## 📥 Download Links

You can host these separately:

1. **Google Drive - RansomwareProtector.zip**
   - Share with: Only you
   - Purpose: Main installation

2. **Google Drive - RansomwareSimulator.zip**
   - Share with: Anyone with link
   - Purpose: Testing/demo

---

## 🚀 One-Time Setup vs Repeated Use

### First Time (Setup):

**Protector:**
```powershell
Extract → Install dependencies → Build → Done!
(5 minutes total)
```

**Simulator:**
```powershell
Extract → Install PyInstaller → Build → Done!
(1 minute total)
```

### Every Time After (Just Run):

**Protector:**
```powershell
Run RansomwareProtector.exe (as admin) → Click START
(5 seconds)
```

**Simulator:**
```powershell
Run ransomware_simulator.exe → Press ENTER
(2 seconds)
```

---

## 📊 Size Comparison

| Package | Source ZIP | After Build | Distribution |
|---------|-----------|-------------|--------------|
| **Protector** | 1.9 MB | ~250 MB | One .exe + model |
| **Simulator** | 8 KB | ~10 MB | One .exe only |

---

## 🎓 For Presentation

**Show this workflow:**

1. **Pre-demo:**
   - Protector already installed and running
   - Simulator already built

2. **During demo:**
   - Insert USB with simulator.exe
   - Copy to VM
   - Run it → Detection happens
   - Popup appears
   - Click KILL → Terminated!

**Total demo time: ~30 seconds** 🎯

---

## ⚡ Quick Reference

### Protector Commands:
```powershell
# Build (once)
py -m pip install pyinstaller pyyaml torch numpy scikit-learn psutil
cmd /c build_final.bat

# Run (every time)
cd RansomwareProtector_Complete
.\RansomwareProtector.exe  # As admin!
```

### Simulator Commands:
```powershell
# Build (once)
py -m pip install pyinstaller
cmd /c build_simulator.bat

# Run (every time)
cd dist
.\ransomware_simulator.exe
```

---

## 🔍 Troubleshooting

### Protector Issues:
- **"Model not found"** → Run from `RansomwareProtector_Complete` folder
- **"Feature extraction failed"** → Run as administrator
- **Windows Defender flagged** → Now whitelisted! ✅

### Simulator Issues:
- **Not detected** → Make sure Protector is running with START clicked
- **Takes too long** → Detection happens in 2-4 seconds (scan interval)
- **Process not killed** → Check if you clicked KILL button

---

## 📝 Summary

**Before (Old Way):**
- One big package (2 MB)
- Everything mixed together
- Confusing setup

**Now (New Way):**
- ✅ Protector: 1.9 MB (main product)
- ✅ Simulator: 8 KB (testing tool)
- ✅ Separate, clear purpose
- ✅ Easy to share simulator
- ✅ Professional setup

**Much better for thesis presentation!** 🎓

---

Good luck with your demo! 🚀
