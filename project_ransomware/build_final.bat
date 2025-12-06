@echo off
:: FINAL BUILD SCRIPT
:: Run this AFTER verify_before_build.bat passes

echo ============================================================
echo   RANSOMWARE PROTECTOR - FINAL BUILD
echo ============================================================
echo.
echo This will:
echo   1. Clean old builds
echo   2. Build RansomwareProtector.exe
echo   3. Create distribution package
echo   4. Create ZIP file
echo.
echo Estimated time: 15 minutes
echo.
pause

:: Step 1: Clean
echo.
echo [1/5] Cleaning old builds...
if exist build rmdir /s /q build
if exist dist rmdir /s /q dist
if exist *.spec del /q *.spec
if exist RansomwareProtector_Complete rmdir /s /q RansomwareProtector_Complete
echo   Done
echo.

:: Step 2: Build
echo [2/5] Building executable (this takes ~10 minutes)...
echo   Please wait...
echo.

py -m PyInstaller ^
  --onefile ^
  --windowed ^
  --add-data "models;models" ^
  --add-data "src;src" ^
  --hidden-import torch ^
  --hidden-import torch.nn ^
  --hidden-import pandas ^
  --hidden-import numpy ^
  --hidden-import sklearn ^
  --hidden-import sklearn.preprocessing ^
  --hidden-import psutil ^
  --hidden-import yaml ^
  --hidden-import tkinter ^
  --hidden-import queue ^
  --hidden-import threading ^
  --name RansomwareProtector ^
  --uac-admin ^
  --clean ^
  --noconfirm ^
  gui_app_standalone.py

if %errorLevel% neq 0 (
    echo.
    echo   BUILD FAILED!
    echo   Check errors above
    pause
    exit /b 1
)

echo   Done
echo.

:: Step 3: Create package
echo [3/5] Creating distribution package...

mkdir RansomwareProtector_Complete
copy dist\RansomwareProtector.exe RansomwareProtector_Complete\ >nul

mkdir RansomwareProtector_Complete\models
copy models\antivirus_production_best.pth RansomwareProtector_Complete\models\ >nul

mkdir RansomwareProtector_Complete\logs
mkdir RansomwareProtector_Complete\quarantine

:: Create README
(
echo RANSOMWARE PROTECTOR
echo ====================
echo.
echo Installation:
echo 1. Right-click RansomwareProtector.exe
echo 2. Click "Run as administrator"
echo 3. Click "Yes" when Windows asks
echo 4. Protection starts automatically!
echo.
echo Requirements:
echo - Windows 10/11 ^(64-bit^)
echo - 8 GB RAM minimum
echo - Administrator privileges
echo.
echo IMPORTANT: Keep the models/ folder next to the .exe file!
echo.
) > RansomwareProtector_Complete\README.txt

echo   Done
echo.

:: Step 4: Test
echo [4/5] Testing executable...
echo   Starting RansomwareProtector.exe for 5 seconds...
start "" RansomwareProtector_Complete\RansomwareProtector.exe
timeout /t 5 /nobreak >nul
taskkill /F /IM RansomwareProtector.exe >nul 2>&1
echo   Test complete
echo.

:: Step 5: Create ZIP
echo [5/5] Creating ZIP file...
powershell -command "Compress-Archive -Path 'RansomwareProtector_Complete' -DestinationPath 'RansomwareProtector_v1.0_Final.zip' -Force"
echo   Done
echo.

:: Summary
echo ============================================================
echo   BUILD COMPLETE!
echo ============================================================
echo.
echo Created:
dir RansomwareProtector_v1.0_Final.zip
echo.
echo Package contents:
dir RansomwareProtector_Complete\RansomwareProtector.exe
dir RansomwareProtector_Complete\models\antivirus_production_best.pth
echo.
echo NEXT STEPS:
echo   1. Test: RansomwareProtector_Complete\RansomwareProtector.exe
echo   2. Upload: RansomwareProtector_v1.0_Final.zip to Google Drive
echo   3. Share download link with users
echo.
pause
