"""
Process Monitor
Continuously scans running processes and detects suspicious activity
"""

import psutil
import time
from datetime import datetime
from typing import List, Dict, Set
import logging

class ProcessMonitor:
    def __init__(self, config: dict):
        self.config = config
        self.scan_interval = config['monitoring']['scan_interval']
        self.whitelist = set(config['whitelist'])
        self.known_processes: Set[int] = set()

        # Setup logging
        logging.basicConfig(
            level=logging.INFO if config['logging']['verbose'] else logging.WARNING,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)

    def get_all_processes(self) -> List[Dict]:
        """Get information about all running processes"""
        processes = []

        for proc in psutil.process_iter(['pid', 'name', 'exe', 'cpu_percent',
                                         'memory_percent', 'num_threads',
                                         'create_time']):
            try:
                pinfo = proc.info

                # Skip whitelisted processes
                if pinfo['name'] in self.whitelist:
                    continue

                # Skip system processes with no executable path
                if not pinfo['exe']:
                    continue

                # Get additional metrics
                try:
                    # CPU usage (need to call twice for accurate reading)
                    cpu_percent = proc.cpu_percent(interval=0.1)

                    # Memory info
                    mem_info = proc.memory_info()

                    # IO counters (file operations)
                    try:
                        io_counters = proc.io_counters()
                        read_count = io_counters.read_count
                        write_count = io_counters.write_count
                    except (psutil.AccessDenied, AttributeError):
                        read_count = 0
                        write_count = 0

                    # Open files
                    try:
                        open_files = len(proc.open_files())
                    except (psutil.AccessDenied, OSError):
                        open_files = 0

                    # Network connections
                    try:
                        connections = len(proc.connections())
                    except (psutil.AccessDenied, OSError):
                        connections = 0

                    processes.append({
                        'pid': pinfo['pid'],
                        'name': pinfo['name'],
                        'exe': pinfo['exe'],
                        'cpu_percent': cpu_percent,
                        'memory_percent': pinfo['memory_percent'],
                        'memory_mb': mem_info.rss / (1024 * 1024),  # MB
                        'num_threads': pinfo['num_threads'],
                        'create_time': pinfo['create_time'],
                        'read_count': read_count,
                        'write_count': write_count,
                        'open_files': open_files,
                        'connections': connections,
                        'timestamp': datetime.now().isoformat()
                    })

                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue

            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

        return processes

    def detect_new_processes(self, current_processes: List[Dict]) -> List[Dict]:
        """Identify newly started processes since last scan"""
        current_pids = {p['pid'] for p in current_processes}
        new_pids = current_pids - self.known_processes

        # Update known processes
        self.known_processes = current_pids

        # Return info about new processes
        new_processes = [p for p in current_processes if p['pid'] in new_pids]

        if new_processes:
            self.logger.info(f"Detected {len(new_processes)} new process(es)")
            for proc in new_processes:
                self.logger.info(f"  → {proc['name']} (PID: {proc['pid']})")

        return new_processes

    def get_process_by_pid(self, pid: int) -> Dict:
        """Get detailed information about specific process"""
        try:
            proc = psutil.Process(pid)

            # Comprehensive process info
            info = {
                'pid': pid,
                'name': proc.name(),
                'exe': proc.exe(),
                'cmdline': ' '.join(proc.cmdline()),
                'cwd': proc.cwd() if hasattr(proc, 'cwd') else None,
                'status': proc.status(),
                'username': proc.username() if hasattr(proc, 'username') else None,
                'create_time': proc.create_time(),
                'cpu_percent': proc.cpu_percent(interval=0.1),
                'memory_percent': proc.memory_percent(),
                'num_threads': proc.num_threads(),
                'parent_pid': proc.ppid(),
            }

            # Memory details
            mem_info = proc.memory_info()
            info['memory_rss_mb'] = mem_info.rss / (1024 * 1024)
            info['memory_vms_mb'] = mem_info.vms / (1024 * 1024)

            # IO counters
            try:
                io = proc.io_counters()
                info['io_read_count'] = io.read_count
                info['io_write_count'] = io.write_count
                info['io_read_bytes'] = io.read_bytes
                info['io_write_bytes'] = io.write_bytes
            except (psutil.AccessDenied, AttributeError):
                info['io_read_count'] = 0
                info['io_write_count'] = 0
                info['io_read_bytes'] = 0
                info['io_write_bytes'] = 0

            # Open files
            try:
                info['open_files'] = [f.path for f in proc.open_files()]
            except (psutil.AccessDenied, OSError):
                info['open_files'] = []

            # Network connections
            try:
                info['connections'] = [
                    {'local': f"{c.laddr.ip}:{c.laddr.port}",
                     'remote': f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else None,
                     'status': c.status}
                    for c in proc.connections()
                ]
            except (psutil.AccessDenied, OSError):
                info['connections'] = []

            return info

        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
            self.logger.error(f"Cannot access process {pid}: {e}")
            return None

    def start_monitoring(self, callback_new_process=None, callback_suspicious=None):
        """
        Start continuous monitoring loop

        Args:
            callback_new_process: Function to call when new process detected
            callback_suspicious: Function to call when suspicious process detected
        """
        self.logger.info("Starting process monitoring...")
        self.logger.info(f"Scan interval: {self.scan_interval} seconds")

        try:
            while True:
                # Get all current processes
                current_processes = self.get_all_processes()

                # Detect new processes
                new_processes = self.detect_new_processes(current_processes)

                # Notify about new processes
                if callback_new_process and new_processes:
                    for proc in new_processes:
                        callback_new_process(proc)

                # Check all processes for suspicious behavior
                if callback_suspicious:
                    for proc in current_processes:
                        # Basic heuristics for suspicion
                        if (proc['cpu_percent'] > self.config['behavioral']['cpu_threshold'] or
                            proc['write_count'] > self.config['behavioral']['file_access_threshold']):
                            callback_suspicious(proc)

                # Wait before next scan
                time.sleep(self.scan_interval)

        except KeyboardInterrupt:
            self.logger.info("Monitoring stopped by user")
        except Exception as e:
            self.logger.error(f"Monitoring error: {e}")
            raise


if __name__ == "__main__":
    # Test the monitor
    import yaml

    with open('../config.yaml', 'r') as f:
        config = yaml.safe_load(f)

    monitor = ProcessMonitor(config)

    def on_new_process(proc):
        print(f"\n🆕 NEW PROCESS: {proc['name']} (PID: {proc['pid']})")
        print(f"   Executable: {proc['exe']}")
        print(f"   CPU: {proc['cpu_percent']:.1f}%")
        print(f"   Memory: {proc['memory_mb']:.1f} MB")

    def on_suspicious(proc):
        print(f"\n⚠️  SUSPICIOUS: {proc['name']} (PID: {proc['pid']})")
        print(f"   CPU: {proc['cpu_percent']:.1f}%")
        print(f"   File writes: {proc['write_count']}")

    monitor.start_monitoring(
        callback_new_process=on_new_process,
        callback_suspicious=on_suspicious
    )
