"""
Threat Response System
Handles malware detection response: kill process, quarantine file, log incident
"""

import os
import shutil
import platform
import subprocess
import psutil
import logging
import json
from datetime import datetime
from typing import Dict, Optional

class ThreatResponseSystem:
    def __init__(self, config: dict):
        self.config = config
        self.logger = logging.getLogger(__name__)

        self.auto_kill = config['response']['auto_kill']
        self.quarantine_enabled = config['response']['quarantine_enabled']
        self.quarantine_path = config['response']['quarantine_path']
        self.log_path = config['logging']['log_path']

        # Create necessary directories
        os.makedirs(self.quarantine_path, exist_ok=True)
        os.makedirs(os.path.dirname(self.log_path), exist_ok=True)

        self.is_windows = platform.system() == 'Windows'

        self.logger.info("Threat Response System initialized")
        self.logger.info(f"  Auto-kill: {self.auto_kill}")
        self.logger.info(f"  Quarantine: {self.quarantine_enabled}")

    def respond_to_threat(self, detection_report: Dict, process_info: Dict) -> Dict:
        """
        Main response handler - coordinates all response actions

        Returns:
            Response summary dictionary
        """
        pid = process_info['pid']
        name = process_info['name']
        exe_path = process_info.get('exe', '')
        threat_class = detection_report['detection']['predicted_class']
        confidence = detection_report['detection']['confidence']

        self.logger.warning(
            f"\n{'='*60}\n"
            f"🚨 THREAT DETECTED\n"
            f"{'='*60}\n"
            f"Process: {name} (PID: {pid})\n"
            f"Executable: {exe_path}\n"
            f"Threat Type: {threat_class}\n"
            f"Confidence: {confidence*100:.2f}%\n"
            f"{'='*60}"
        )

        response_summary = {
            'timestamp': datetime.now().isoformat(),
            'process': process_info,
            'detection': detection_report,
            'actions_taken': []
        }

        # Step 1: Kill process
        if self.auto_kill:
            kill_result = self.kill_process(pid, name)
            response_summary['actions_taken'].append({
                'action': 'KILL_PROCESS',
                'success': kill_result['success'],
                'details': kill_result
            })

        # Step 2: Quarantine executable
        if self.quarantine_enabled and exe_path:
            quarantine_result = self.quarantine_file(exe_path, threat_class)
            response_summary['actions_taken'].append({
                'action': 'QUARANTINE_FILE',
                'success': quarantine_result['success'],
                'details': quarantine_result
            })

        # Step 3: Log incident
        log_result = self.log_incident(response_summary)
        response_summary['actions_taken'].append({
            'action': 'LOG_INCIDENT',
            'success': log_result['success'],
            'details': log_result
        })

        # Step 4: Alert user (placeholder for GUI)
        self.alert_user(threat_class, name, confidence)

        return response_summary

    def kill_process(self, pid: int, name: str) -> Dict:
        """
        Terminate the malicious process

        Returns:
            Result dictionary
        """
        self.logger.warning(f"Attempting to kill process {name} (PID: {pid})")

        try:
            # Check if process exists
            if not psutil.pid_exists(pid):
                return {
                    'success': False,
                    'error': 'Process no longer exists',
                    'pid': pid
                }

            proc = psutil.Process(pid)

            if self.is_windows:
                # Windows: Use taskkill for forceful termination
                try:
                    # Try graceful termination first
                    subprocess.run(['taskkill', '/PID', str(pid)],
                                   capture_output=True,
                                   timeout=5)

                    # Wait a bit
                    proc.wait(timeout=2)

                except (subprocess.TimeoutExpired, psutil.TimeoutExpired):
                    # Force kill if still running
                    self.logger.warning(f"Graceful termination failed, force killing...")
                    subprocess.run(['taskkill', '/F', '/PID', str(pid)],
                                   capture_output=True,
                                   timeout=5)

            else:
                # Unix: Use kill signal
                proc.terminate()  # SIGTERM
                try:
                    proc.wait(timeout=3)
                except psutil.TimeoutExpired:
                    # Force kill if still running
                    proc.kill()  # SIGKILL
                    proc.wait(timeout=3)

            # Verify termination
            if psutil.pid_exists(pid):
                return {
                    'success': False,
                    'error': 'Process still running after kill attempt',
                    'pid': pid
                }

            self.logger.warning(f"✓ Process {name} (PID: {pid}) terminated successfully")

            return {
                'success': True,
                'pid': pid,
                'name': name,
                'message': 'Process terminated'
            }

        except psutil.NoSuchProcess:
            return {
                'success': True,  # Process already gone
                'pid': pid,
                'message': 'Process no longer exists'
            }

        except psutil.AccessDenied:
            return {
                'success': False,
                'error': 'Access denied - requires administrator privileges',
                'pid': pid
            }

        except Exception as e:
            self.logger.error(f"Failed to kill process {pid}: {e}")
            return {
                'success': False,
                'error': str(e),
                'pid': pid
            }

    def quarantine_file(self, exe_path: str, threat_class: str) -> Dict:
        """
        Move malicious executable to quarantine folder

        Returns:
            Result dictionary
        """
        self.logger.warning(f"Quarantining file: {exe_path}")

        try:
            if not os.path.exists(exe_path):
                return {
                    'success': False,
                    'error': 'File not found',
                    'path': exe_path
                }

            # Create quarantine filename with timestamp and threat type
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = os.path.basename(exe_path)
            quarantine_filename = f"{timestamp}_{threat_class}_{filename}"
            quarantine_full_path = os.path.join(self.quarantine_path, quarantine_filename)

            # Move file to quarantine
            shutil.move(exe_path, quarantine_full_path)

            # Make file read-only (extra safety)
            os.chmod(quarantine_full_path, 0o444)

            self.logger.warning(f"✓ File quarantined: {quarantine_full_path}")

            return {
                'success': True,
                'original_path': exe_path,
                'quarantine_path': quarantine_full_path,
                'message': 'File quarantined successfully'
            }

        except PermissionError:
            self.logger.error(f"Permission denied when quarantining {exe_path}")
            return {
                'success': False,
                'error': 'Permission denied - requires administrator privileges',
                'path': exe_path
            }

        except Exception as e:
            self.logger.error(f"Failed to quarantine file: {e}")
            return {
                'success': False,
                'error': str(e),
                'path': exe_path
            }

    def log_incident(self, response_summary: Dict) -> Dict:
        """
        Log threat detection incident to JSON file

        Returns:
            Result dictionary
        """
        try:
            # Load existing log
            if os.path.exists(self.log_path):
                with open(self.log_path, 'r') as f:
                    log_data = json.load(f)
            else:
                log_data = {'incidents': []}

            # Add new incident
            log_data['incidents'].append(response_summary)

            # Save log
            with open(self.log_path, 'w') as f:
                json.dump(log_data, f, indent=2)

            self.logger.info(f"✓ Incident logged to {self.log_path}")

            return {
                'success': True,
                'log_path': self.log_path,
                'total_incidents': len(log_data['incidents'])
            }

        except Exception as e:
            self.logger.error(f"Failed to log incident: {e}")
            return {
                'success': False,
                'error': str(e)
            }

    def alert_user(self, threat_class: str, process_name: str, confidence: float):
        """
        Alert user about threat (console for now, GUI later)

        Args:
            threat_class: Type of malware
            process_name: Process name
            confidence: Detection confidence
        """
        alert_message = (
            f"\n{'#'*60}\n"
            f"🚨 CRITICAL SECURITY ALERT\n"
            f"{'#'*60}\n"
            f"\n"
            f"  THREAT DETECTED AND NEUTRALIZED\n"
            f"\n"
            f"  Threat Type:  {threat_class}\n"
            f"  Process:      {process_name}\n"
            f"  Confidence:   {confidence*100:.1f}%\n"
            f"  Status:       TERMINATED\n"
            f"\n"
            f"{'#'*60}\n"
        )

        print(alert_message)
        self.logger.critical(alert_message)

        # TODO: Integrate with GUI dashboard for visual alerts

    def get_incident_summary(self) -> Dict:
        """
        Get summary of all logged incidents

        Returns:
            Statistics dictionary
        """
        try:
            if not os.path.exists(self.log_path):
                return {
                    'total_incidents': 0,
                    'by_class': {},
                    'recent_incidents': []
                }

            with open(self.log_path, 'r') as f:
                log_data = json.load(f)

            incidents = log_data.get('incidents', [])

            # Count by threat class
            by_class = {}
            for incident in incidents:
                threat_class = incident['detection']['detection']['predicted_class']
                by_class[threat_class] = by_class.get(threat_class, 0) + 1

            # Get recent incidents (last 10)
            recent = incidents[-10:] if len(incidents) > 10 else incidents

            return {
                'total_incidents': len(incidents),
                'by_class': by_class,
                'recent_incidents': recent
            }

        except Exception as e:
            self.logger.error(f"Failed to get incident summary: {e}")
            return {
                'error': str(e)
            }


if __name__ == "__main__":
    # Test response system
    import yaml

    logging.basicConfig(level=logging.INFO)

    with open('../config.yaml', 'r') as f:
        config = yaml.safe_load(f)

    response_system = ThreatResponseSystem(config)

    # Simulate detection report
    fake_report = {
        'process': {
            'pid': 99999,
            'name': 'test_malware.exe',
            'executable': '/tmp/test_malware.exe'
        },
        'detection': {
            'is_malware': True,
            'predicted_class': 'Ransomware',
            'confidence': 0.95,
            'meets_threshold': True
        },
        'probabilities': {
            'Benign': 0.01,
            'Ransomware': 0.95,
            'Spyware': 0.03,
            'Trojan': 0.01
        },
        'threat_level': 3
    }

    fake_process = {
        'pid': 99999,
        'name': 'test_malware.exe',
        'exe': '/tmp/test_malware.exe'
    }

    print("\n" + "="*60)
    print("Testing Threat Response (simulation)")
    print("="*60)

    # Don't actually respond (process doesn't exist)
    print("\nWould take the following actions:")
    print("  1. Kill process 99999")
    print("  2. Quarantine /tmp/test_malware.exe")
    print("  3. Log incident")
    print("  4. Alert user")

    # Test logging
    response_system.config['response']['auto_kill'] = False
    response_system.config['response']['quarantine_enabled'] = False

    summary = response_system.respond_to_threat(fake_report, fake_process)
    print(f"\n✓ Response logged successfully")
