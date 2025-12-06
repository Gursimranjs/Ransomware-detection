"""
Ransomware Behavioral Simulator - SAFE TEST PROGRAM
====================================================
This program mimics ransomware behavior patterns WITHOUT actually encrypting files.
Safe for testing antivirus/anti-ransomware detection systems.

Behavioral patterns simulated:
- Rapid file access (reads/writes)
- High I/O operations
- Suspicious file patterns (many small files)
- Memory-intensive operations
- Network + file activity patterns
"""

import os
import sys
import time
import random
import threading
import tempfile
from pathlib import Path

class RansomwareSimulator:
    """Simulates ransomware behavior safely"""

    def __init__(self):
        # Create isolated test directory
        self.test_dir = Path(tempfile.mkdtemp(prefix="ransim_test_"))
        print(f"[SIMULATOR] Test directory: {self.test_dir}")
        print("[SIMULATOR] This is a SAFE test - no real files will be harmed")
        print("-" * 60)

        self.running = True
        self.file_count = 0
        self.write_count = 0

    def simulate_file_enumeration(self):
        """Simulates scanning for target files (ransomware reconnaissance)"""
        print("[BEHAVIOR 1] Simulating file enumeration...")

        # Create test files
        extensions = ['.txt', '.doc', '.pdf', '.jpg', '.xlsx', '.ppt']
        for i in range(50):
            ext = random.choice(extensions)
            test_file = self.test_dir / f"test_file_{i}{ext}"
            test_file.write_text(f"Test data {i}" * 100)
            self.file_count += 1

        print(f"[✓] Created {self.file_count} test files")

    def simulate_rapid_file_access(self):
        """Simulates rapid read/write pattern (encryption simulation)"""
        print("[BEHAVIOR 2] Simulating rapid file I/O (encryption pattern)...")

        # Rapid read-write cycles
        for i in range(200):
            test_file = self.test_dir / f"rapid_io_{i}.tmp"

            # Write
            test_file.write_bytes(os.urandom(4096))
            self.write_count += 1

            # Read
            _ = test_file.read_bytes()

            # Modify
            test_file.write_bytes(os.urandom(4096))
            self.write_count += 1

            if i % 50 == 0:
                print(f"  [I/O] Processed {i}/200 operations...")

        print(f"[✓] Completed {self.write_count} write operations")

    def simulate_file_extension_changes(self):
        """Simulates changing file extensions (ransomware encryption marker)"""
        print("[BEHAVIOR 3] Simulating extension modification...")

        for file in self.test_dir.glob("test_file_*"):
            # Simulate adding .encrypted extension
            new_name = file.with_suffix(file.suffix + ".encrypted")
            file.rename(new_name)

        print("[✓] Modified file extensions")

    def simulate_memory_intensive_ops(self):
        """Simulates memory-intensive operations (encryption algorithms)"""
        print("[BEHAVIOR 4] Simulating encryption-like memory operations...")

        # Allocate and manipulate large memory blocks
        data_blocks = []
        for i in range(20):
            # Simulate encryption buffer
            block = bytearray(os.urandom(1024 * 1024))  # 1 MB blocks

            # Simulate encryption operations (XOR, byte manipulation)
            for j in range(0, len(block), 16):
                block[j:j+16] = bytes([b ^ 0xAA for b in block[j:j+16]])

            data_blocks.append(block)

            if i % 5 == 0:
                print(f"  [MEMORY] Processed {i}/20 memory blocks...")

        print(f"[✓] Processed {len(data_blocks)} memory blocks")

    def simulate_network_activity(self):
        """Simulates network-like activity (C2 communication pattern)"""
        print("[BEHAVIOR 5] Simulating network activity pattern...")

        # Simulate periodic beacons
        for i in range(10):
            # Create activity that looks like network communication
            beacon_file = self.test_dir / f"beacon_{i}.dat"
            beacon_file.write_bytes(os.urandom(256))
            time.sleep(0.1)
            beacon_file.unlink()

        print("[✓] Completed network-like activity")

    def create_ransom_note(self):
        """Creates a fake ransom note (harmless text file)"""
        print("[BEHAVIOR 6] Creating ransom note simulation...")

        note = """
========================================
    RANSOMWARE SIMULATION - TEST ONLY
========================================

This is a SAFE behavioral test.
No real encryption has occurred.

This simulator was created to test
anti-ransomware detection systems.

All files are safe and can be deleted.
========================================
"""
        note_file = self.test_dir / "README_SIMULATOR.txt"
        note_file.write_text(note)

        print("[✓] Created simulation notice")

    def continuous_background_activity(self):
        """Runs continuous background I/O (keeps process active)"""
        print("[BACKGROUND] Starting continuous activity...")

        while self.running:
            # Continuous file operations
            temp_file = self.test_dir / f"bg_activity_{random.randint(1, 100)}.tmp"
            temp_file.write_bytes(os.urandom(2048))
            time.sleep(0.5)  # Slower to allow detection

            if temp_file.exists():
                temp_file.unlink()

    def run_simulation(self):
        """Execute full ransomware behavior simulation"""
        print("\n" + "=" * 60)
        print("RANSOMWARE BEHAVIORAL SIMULATOR - SAFE TEST MODE")
        print("=" * 60)
        print("This program will mimic ransomware behavior patterns")
        print("to test your anti-ransomware detection system.")
        print("No real files will be encrypted or harmed.")
        print("=" * 60 + "\n")

        input("Press ENTER to start simulation...")

        try:
            # Start background thread (mimics persistent malware)
            bg_thread = threading.Thread(target=self.continuous_background_activity, daemon=True)
            bg_thread.start()

            # Execute behavioral phases
            self.simulate_file_enumeration()
            time.sleep(2)

            self.simulate_rapid_file_access()
            time.sleep(2)

            self.simulate_file_extension_changes()
            time.sleep(2)

            self.simulate_memory_intensive_ops()
            time.sleep(2)

            self.simulate_network_activity()
            time.sleep(2)

            self.create_ransom_note()

            print("\n" + "=" * 60)
            print("SIMULATION COMPLETE")
            print("=" * 60)
            print(f"Total files created: {self.file_count}")
            print(f"Total write operations: {self.write_count}")
            print(f"Test directory: {self.test_dir}")
            print("\nIf your anti-ransomware is working, this process")
            print("should be DETECTED and TERMINATED soon.")
            print("=" * 60 + "\n")

            # Keep running to allow detection
            print("Keeping process active for detection...")
            print("Press Ctrl+C to stop manually")
            print("\nWaiting for detection (running for 60 seconds)...\n")

            # Keep process alive for 60 seconds to allow detection
            for i in range(60):
                print(f"[ACTIVE] Running... {60-i} seconds remaining", end='\r')
                time.sleep(1)

        except KeyboardInterrupt:
            print("\n[SIMULATOR] Stopped by user")
            self.cleanup()
        except Exception as e:
            print(f"\n[SIMULATOR] Stopped: {e}")
            self.cleanup()

    def cleanup(self):
        """Clean up test files"""
        self.running = False
        print("\n[CLEANUP] Removing test files...")

        try:
            import shutil
            shutil.rmtree(self.test_dir)
            print("[✓] Cleanup complete")
        except Exception as e:
            print(f"[!] Cleanup error: {e}")
            print(f"    Please manually delete: {self.test_dir}")

def main():
    """Entry point"""
    simulator = RansomwareSimulator()
    simulator.run_simulation()

if __name__ == "__main__":
    main()
