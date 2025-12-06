@echo off
echo ================================================
echo Building Ransomware Simulator Executable
echo ================================================

REM Build the simulator
py -m PyInstaller --onefile --console ransomware_simulator.py

echo.
echo ================================================
echo Build Complete!
echo ================================================
echo Executable location: dist\ransomware_simulator.exe
echo.
echo USAGE:
echo 1. Copy dist\ransomware_simulator.exe to test machine
echo 2. Make sure RansomwareProtector is running
echo 3. Run ransomware_simulator.exe
echo 4. Watch RansomwareProtector detect and kill it!
echo ================================================
pause
