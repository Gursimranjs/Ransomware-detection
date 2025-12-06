"""
Behavioral Filter
Fast heuristic-based pre-screening to identify suspicious processes
Only processes flagged here proceed to expensive ML analysis
"""

import logging
import os
from typing import Dict, Tuple
from datetime import datetime

class BehavioralFilter:
    def __init__(self, config: dict):
        self.config = config
        self.cpu_threshold = config['behavioral']['cpu_threshold']
        self.file_threshold = config['behavioral']['file_access_threshold']

        self.logger = logging.getLogger(__name__)

        # Track process behavior over time
        self.process_history = {}  # {pid: [snapshots]}

    def is_suspicious(self, process_info: Dict) -> Tuple[bool, str, float]:
        """
        Analyze process behavior to determine if it's suspicious

        Returns:
            (is_suspicious, reason, risk_score)
        """
        pid = process_info['pid']
        name = process_info['name']
        risk_score = 0.0
        reasons = []

        # === RULE 1: High CPU Usage ===
        if process_info.get('cpu_percent', 0) > self.cpu_threshold:
            risk_score += 25
            reasons.append(f"High CPU: {process_info['cpu_percent']:.1f}%")

        # === RULE 2: Excessive File Operations ===
        write_count = process_info.get('write_count', 0)
        if write_count > self.file_threshold:
            risk_score += 30
            reasons.append(f"High file writes: {write_count}")

        # === RULE 3: Suspicious File Extensions ===
        exe_path = process_info.get('exe', '').lower()
        suspicious_extensions = ['.tmp', '.dat', '.bin', 'appdata', 'temp']
        if any(ext in exe_path for ext in suspicious_extensions):
            risk_score += 15
            reasons.append("Suspicious file location")

        # === RULE 4: Unsigned/Unknown Executable ===
        # Check if executable is in common system directories
        system_dirs = ['c:\\windows\\', 'c:\\program files\\']
        if not any(dir in exe_path for dir in system_dirs):
            risk_score += 10
            reasons.append("Non-system executable")

        # === RULE 5: Rapid File Access Pattern ===
        read_count = process_info.get('read_count', 0)
        if read_count > 200 and write_count > 100:
            risk_score += 20
            reasons.append("Rapid read+write pattern")

        # === RULE 6: Many Open File Handles ===
        open_files = process_info.get('open_files', 0)
        if open_files > 50:
            risk_score += 15
            reasons.append(f"Many open files: {open_files}")

        # === RULE 7: Network Activity + File Operations ===
        connections = process_info.get('connections', 0)
        if connections > 5 and write_count > 50:
            risk_score += 25
            reasons.append("Network + file activity")

        # === RULE 8: High Memory Usage ===
        memory_mb = process_info.get('memory_mb', 0)
        if memory_mb > 500:  # >500 MB
            risk_score += 10
            reasons.append(f"High memory: {memory_mb:.0f} MB")

        # === RULE 9: Rapid Process Spawn ===
        # Track if process creates many child processes quickly
        # (This would need process tree tracking - simplified for now)

        # === RULE 10: Suspicious Process Names ===
        suspicious_names = [
            'crypt', 'encrypt', 'ransom', 'locker', 'payload',
            'dropper', 'injector', 'keylog', 'stealer', 'simulator'
        ]
        if any(sus in name.lower() for sus in suspicious_names):
            risk_score += 40
            reasons.append("Suspicious process name")

        # Normalize risk score to 0-100
        risk_score = min(risk_score, 100)

        # Decision threshold
        is_suspicious = risk_score >= 50  # 50+ = suspicious

        reason_text = "; ".join(reasons) if reasons else "Low risk"

        if is_suspicious:
            self.logger.warning(
                f"🚨 SUSPICIOUS PROCESS DETECTED\n"
                f"   Name: {name} (PID: {pid})\n"
                f"   Risk Score: {risk_score:.0f}/100\n"
                f"   Reasons: {reason_text}"
            )
        else:
            self.logger.debug(
                f"✓ Process {name} (PID: {pid}) appears benign (Risk: {risk_score:.0f}/100)"
            )

        return is_suspicious, reason_text, risk_score

    def analyze_behavioral_pattern(self, pid: int, process_info: Dict) -> Dict:
        """
        Analyze process behavior over time by comparing current state
        with historical snapshots

        Returns:
            Behavioral analysis results
        """
        # Store current snapshot
        if pid not in self.process_history:
            self.process_history[pid] = []

        snapshot = {
            'timestamp': datetime.now().timestamp(),
            'cpu': process_info.get('cpu_percent', 0),
            'memory_mb': process_info.get('memory_mb', 0),
            'write_count': process_info.get('write_count', 0),
            'read_count': process_info.get('read_count', 0),
        }

        self.process_history[pid].append(snapshot)

        # Keep only last 10 snapshots
        if len(self.process_history[pid]) > 10:
            self.process_history[pid].pop(0)

        # Analyze trends if we have enough history
        analysis = {
            'has_history': len(self.process_history[pid]) >= 3,
            'cpu_trend': 'stable',
            'io_trend': 'stable',
            'acceleration': False
        }

        if len(self.process_history[pid]) >= 3:
            history = self.process_history[pid]

            # CPU trend
            cpu_values = [s['cpu'] for s in history[-3:]]
            if cpu_values[-1] > cpu_values[-2] > cpu_values[-3]:
                analysis['cpu_trend'] = 'increasing'
            elif cpu_values[-1] < cpu_values[-2] < cpu_values[-3]:
                analysis['cpu_trend'] = 'decreasing'

            # IO trend
            io_values = [s['write_count'] for s in history[-3:]]
            if io_values[-1] > io_values[-2] * 2:  # Doubling writes
                analysis['io_trend'] = 'accelerating'
                analysis['acceleration'] = True

        return analysis

    def cleanup_history(self, active_pids: set):
        """Remove history for processes that no longer exist"""
        dead_pids = set(self.process_history.keys()) - active_pids
        for pid in dead_pids:
            del self.process_history[pid]


if __name__ == "__main__":
    # Test the behavioral filter
    import yaml

    with open('../config.yaml', 'r') as f:
        config = yaml.safe_load(f)

    filter = BehavioralFilter(config)

    # Test case 1: Benign process
    benign = {
        'pid': 1234,
        'name': 'notepad.exe',
        'exe': 'C:\\Windows\\System32\\notepad.exe',
        'cpu_percent': 5.0,
        'memory_mb': 50.0,
        'write_count': 10,
        'read_count': 5,
        'open_files': 2,
        'connections': 0
    }

    suspicious, reason, score = filter.is_suspicious(benign)
    print(f"\nTest 1 - Benign Process:")
    print(f"  Suspicious: {suspicious}")
    print(f"  Risk Score: {score}/100")
    print(f"  Reason: {reason}")

    # Test case 2: Ransomware-like behavior
    ransomware = {
        'pid': 6666,
        'name': 'cryptolocker.exe',
        'exe': 'C:\\Users\\Downloads\\cryptolocker.exe',
        'cpu_percent': 85.0,
        'memory_mb': 350.0,
        'write_count': 350,
        'read_count': 400,
        'open_files': 120,
        'connections': 3
    }

    suspicious, reason, score = filter.is_suspicious(ransomware)
    print(f"\nTest 2 - Ransomware-like Process:")
    print(f"  Suspicious: {suspicious}")
    print(f"  Risk Score: {score}/100")
    print(f"  Reason: {reason}")
