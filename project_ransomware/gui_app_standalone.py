"""
Ransomware Protector - Standalone GUI Application
Works as both script and executable - creates config automatically
"""

import sys
import os
import threading
import queue
import logging
from datetime import datetime
from pathlib import Path

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import yaml

# Get the correct base path (works for both script and .exe)
if getattr(sys, 'frozen', False):
    # Running as compiled executable
    BASE_PATH = sys._MEIPASS
    WORK_DIR = os.path.dirname(sys.executable)
else:
    # Running as script
    BASE_PATH = os.path.dirname(os.path.abspath(__file__))
    WORK_DIR = BASE_PATH

# Change to working directory FIRST
os.chdir(WORK_DIR)

# NOW create logs directory and setup logging (after we're in the right directory)
os.makedirs('logs', exist_ok=True)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('logs/app_debug.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Add src to path
sys.path.append(os.path.join(BASE_PATH, 'src'))

from monitor import ProcessMonitor
from behavioral_filter import BehavioralFilter
from feature_extractor import FeatureExtractor
from detection_engine import DetectionEngine
from response_system import ThreatResponseSystem

# Default configuration
DEFAULT_CONFIG = {
    'monitoring': {
        'scan_interval': 2,  # FASTER - check every 2 seconds for real-time detection
        'enable_behavioral_filter': True,
        'enable_ml_analysis': True  # ENABLED - use ML model for detection
    },
    'behavioral': {
        'cpu_threshold': 70,
        'file_access_threshold': 100,
        'suspicious_patterns': [
            'rapid_encryption',
            'mass_file_modification',
            'registry_tampering',
            'network_encryption_traffic'
        ]
    },
    'model': {
        'path': 'models/antivirus_production_best.pth',  # Relative to working directory
        'confidence_threshold': 0.70,  # 70%+ confidence required
        'input_features': 83,
        'classes': {
            0: "Benign",
            1: "Ransomware",
            2: "Spyware",
            3: "Trojan"
        }
    },
    'response': {
        'auto_kill': True,  # ENABLED - kill detected ransomware
        'quarantine_enabled': True,
        'quarantine_path': "quarantine",
        'priority_threats': ["Ransomware", "Trojan", "Spyware"]
    },
    'logging': {
        'enabled': True,
        'log_path': "logs/detections.json",
        'report_path': "reports",
        'verbose': True
    },
    'dashboard': {
        'enabled': True,
        'refresh_rate': 1,
        'show_benign_processes': False,
        'max_log_entries': 100
    },
    'memory': {
        'dump_tool': "tools/procdump.exe",
        'dump_path': "temp_dumps",
        'volatility_path': "tools/volatility3",
        'cleanup_dumps': True
    },
    'whitelist': [
        "System",
        "svchost.exe",
        "explorer.exe",
        "python.exe",
        "RansomwareProtector.exe",
        "MsMpEng.exe",              # Windows Defender
        "NisSrv.exe",               # Windows Defender Network Inspection
        "SecurityHealthService.exe", # Windows Security
        "MpDefenderCoreService.exe"  # Windows Defender Core
    ]
}

class RansomwareProtectorApp:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Ransomware Protector - Real-Time Protection")
        self.root.geometry("900x700")
        self.root.configure(bg='#1e1e1e')

        # Load or create config
        self.config = self.load_config()

        # Ensure output directories exist
        for dir_name in ['logs', 'quarantine', 'temp_dumps', 'reports', 'models']:
            os.makedirs(dir_name, exist_ok=True)

        # Initialize components
        self.monitor = None
        self.behavioral_filter = None
        self.feature_extractor = None
        self.detection_engine = None
        self.response_system = None

        # State
        self.is_running = False
        self.stats = {
            'scanned': 0,
            'suspicious': 0,
            'threats': 0,
            'neutralized': 0,
            'start_time': None
        }

        # Message queue for thread-safe GUI updates
        self.message_queue = queue.Queue()

        # Setup GUI
        self.setup_gui()

        # Auto-start
        self.start_protection()

        # Start message processor
        self.process_messages()

    def load_config(self):
        """Load config from file or use defaults"""
        config_path = os.path.join(BASE_PATH, 'config.yaml')

        if os.path.exists(config_path):
            try:
                with open(config_path, 'r') as f:
                    return yaml.safe_load(f)
            except:
                pass

        # Use default config and save it
        try:
            with open('config.yaml', 'w') as f:
                yaml.dump(DEFAULT_CONFIG, f)
        except:
            pass

        return DEFAULT_CONFIG

    def setup_gui(self):
        """Create the GUI layout"""

        # === HEADER ===
        header = tk.Frame(self.root, bg='#2d2d2d', height=80)
        header.pack(fill=tk.X, padx=0, pady=0)

        title_label = tk.Label(
            header,
            text="🛡️ RANSOMWARE PROTECTOR",
            font=('Arial', 24, 'bold'),
            bg='#2d2d2d',
            fg='#00ff00'
        )
        title_label.pack(pady=20)

        # === STATUS BAR ===
        self.status_frame = tk.Frame(self.root, bg='#2d2d2d', height=50)
        self.status_frame.pack(fill=tk.X, padx=10, pady=5)

        self.status_label = tk.Label(
            self.status_frame,
            text="● INITIALIZING...",
            font=('Arial', 14, 'bold'),
            bg='#2d2d2d',
            fg='#ffaa00'
        )
        self.status_label.pack(side=tk.LEFT, padx=10)

        # === STATISTICS ===
        stats_frame = tk.Frame(self.root, bg='#1e1e1e')
        stats_frame.pack(fill=tk.X, padx=10, pady=10)

        # Stats boxes
        self.stat_boxes = {}
        stats_info = [
            ('scanned', 'Processes Scanned', '#4a9eff'),
            ('suspicious', 'Suspicious Flagged', '#ffaa00'),
            ('threats', 'Threats Detected', '#ff4444'),
            ('neutralized', 'Threats Neutralized', '#00ff00')
        ]

        for i, (key, label, color) in enumerate(stats_info):
            box = tk.Frame(stats_frame, bg='#2d2d2d', relief=tk.RAISED, borderwidth=2)
            box.pack(side=tk.LEFT, expand=True, fill=tk.BOTH, padx=5)

            tk.Label(
                box,
                text=label,
                font=('Arial', 10),
                bg='#2d2d2d',
                fg='#cccccc'
            ).pack(pady=5)

            value_label = tk.Label(
                box,
                text='0',
                font=('Arial', 28, 'bold'),
                bg='#2d2d2d',
                fg=color
            )
            value_label.pack(pady=5)

            self.stat_boxes[key] = value_label

        # === CONTROLS ===
        controls_frame = tk.Frame(self.root, bg='#1e1e1e')
        controls_frame.pack(fill=tk.X, padx=10, pady=10)

        self.start_btn = tk.Button(
            controls_frame,
            text="▶ START",
            font=('Arial', 12, 'bold'),
            bg='#00aa00',
            fg='white',
            command=self.start_protection,
            padx=20,
            pady=10,
            relief=tk.RAISED,
            borderwidth=3
        )
        self.start_btn.pack(side=tk.LEFT, padx=5)

        self.stop_btn = tk.Button(
            controls_frame,
            text="■ STOP",
            font=('Arial', 12, 'bold'),
            bg='#aa0000',
            fg='white',
            command=self.stop_protection,
            padx=20,
            pady=10,
            relief=tk.RAISED,
            borderwidth=3,
            state=tk.DISABLED
        )
        self.stop_btn.pack(side=tk.LEFT, padx=5)

        tk.Button(
            controls_frame,
            text="📊 VIEW LOGS",
            font=('Arial', 12),
            bg='#4a9eff',
            fg='white',
            command=self.view_logs,
            padx=20,
            pady=10
        ).pack(side=tk.LEFT, padx=5)

        tk.Button(
            controls_frame,
            text="🗂️ QUARANTINE",
            font=('Arial', 12),
            bg='#ff8800',
            fg='white',
            command=self.view_quarantine,
            padx=20,
            pady=10
        ).pack(side=tk.LEFT, padx=5)

        # === ACTIVITY LOG ===
        log_frame = tk.Frame(self.root, bg='#1e1e1e')
        log_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        tk.Label(
            log_frame,
            text="📝 Activity Log",
            font=('Arial', 12, 'bold'),
            bg='#1e1e1e',
            fg='#cccccc'
        ).pack(anchor=tk.W)

        self.log_text = scrolledtext.ScrolledText(
            log_frame,
            font=('Consolas', 10),
            bg='#0a0a0a',
            fg='#00ff00',
            insertbackground='white',
            relief=tk.SUNKEN,
            borderwidth=2
        )
        self.log_text.pack(fill=tk.BOTH, expand=True, pady=5)

        # === FOOTER ===
        footer = tk.Frame(self.root, bg='#2d2d2d', height=30)
        footer.pack(fill=tk.X)

        tk.Label(
            footer,
            text="AI-Powered Real-Time Malware Detection | Master's Thesis Project 2024",
            font=('Arial', 8),
            bg='#2d2d2d',
            fg='#888888'
        ).pack(pady=5)

        # Window close handler
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

    def log(self, message, level='INFO'):
        """Thread-safe logging to GUI"""
        self.message_queue.put(('log', message, level))

    def update_stat(self, key, value):
        """Thread-safe stat update"""
        self.message_queue.put(('stat', key, value))

    def update_status(self, text, color):
        """Thread-safe status update"""
        self.message_queue.put(('status', text, color))

    def process_messages(self):
        """Process queued messages for GUI updates"""
        try:
            while True:
                msg_type, *args = self.message_queue.get_nowait()

                if msg_type == 'log':
                    message, level = args
                    timestamp = datetime.now().strftime('%H:%M:%S')

                    # Color by level
                    colors = {
                        'INFO': '#00ff00',
                        'WARNING': '#ffaa00',
                        'ERROR': '#ff4444',
                        'CRITICAL': '#ff0000'
                    }
                    color = colors.get(level, '#00ff00')

                    self.log_text.insert(tk.END, f"[{timestamp}] ", 'timestamp')
                    self.log_text.insert(tk.END, f"{message}\n", level)
                    self.log_text.tag_config('timestamp', foreground='#888888')
                    self.log_text.tag_config(level, foreground=color)
                    self.log_text.see(tk.END)

                elif msg_type == 'stat':
                    key, value = args
                    if key in self.stat_boxes:
                        self.stat_boxes[key].config(text=str(value))

                elif msg_type == 'status':
                    text, color = args
                    self.status_label.config(text=text, fg=color)

        except queue.Empty:
            pass

        # Schedule next check
        self.root.after(100, self.process_messages)

    def start_protection(self):
        """Start the antivirus protection"""
        if self.is_running:
            return

        self.log("Starting Ransomware Protector...", 'INFO')
        self.update_status("● STARTING...", '#ffaa00')

        try:
            # Initialize components
            self.log("Initializing components...", 'INFO')

            self.monitor = ProcessMonitor(self.config)
            self.log("✓ Process Monitor initialized", 'INFO')

            self.behavioral_filter = BehavioralFilter(self.config)
            self.log("✓ Behavioral Filter initialized", 'INFO')

            self.feature_extractor = FeatureExtractor(self.config)
            self.log("✓ Feature Extractor initialized", 'INFO')

            try:
                self.detection_engine = DetectionEngine(self.config)
                self.log("✓ ML Detection Engine initialized", 'INFO')
            except Exception as e:
                self.log(f"⚠️ ML Engine failed (demo mode): {str(e)[:50]}", 'WARNING')
                self.detection_engine = None

            self.response_system = ThreatResponseSystem(self.config)
            self.log("✓ Threat Response System initialized", 'INFO')

            self.stats['start_time'] = datetime.now()
            self.is_running = True

            # Update UI
            self.start_btn.config(state=tk.DISABLED)
            self.stop_btn.config(state=tk.NORMAL)
            self.update_status("● PROTECTED - MONITORING ACTIVE", '#00ff00')

            self.log("="*60, 'INFO')
            self.log("🛡️ PROTECTION ACTIVE - System is now protected", 'INFO')
            self.log("="*60, 'INFO')

            # Start monitoring in background thread
            monitor_thread = threading.Thread(target=self.monitoring_loop, daemon=True)
            monitor_thread.start()

        except Exception as e:
            self.log(f"ERROR: Failed to start protection: {e}", 'ERROR')
            self.update_status("● ERROR", '#ff0000')
            messagebox.showerror("Error", f"Failed to start protection:\n{e}")

    def monitoring_loop(self):
        """Background monitoring loop - FULL DETECTION"""
        self.log("Monitoring loop started - scanning for threats", 'INFO')

        import time
        while self.is_running:
            try:
                # Get current processes
                processes = self.monitor.get_all_processes()

                # Detect new processes
                new_processes = self.monitor.detect_new_processes(processes)

                # Analyze each new process
                for proc in new_processes:
                    self.on_new_process(proc)

                # Wait before next scan
                time.sleep(self.config['monitoring']['scan_interval'])

            except Exception as e:
                self.log(f"Monitoring error: {str(e)[:100]}", 'ERROR')
                time.sleep(5)

    def on_new_process(self, process_info):
        """Handle new process detection - FULL PIPELINE"""
        pid = process_info['pid']
        name = process_info['name']

        self.stats['scanned'] += 1
        self.update_stat('scanned', self.stats['scanned'])

        self.log(f"🔍 NEW PROCESS: {name} (PID: {pid})", 'INFO')

        # STEP 1: Behavioral Filter
        is_suspicious, reason, risk_score = self.behavioral_filter.is_suspicious(process_info)

        if not is_suspicious:
            self.log(f"  ✓ Benign (Risk: {risk_score:.0f}/100)", 'INFO')
            return

        # SUSPICIOUS!
        self.stats['suspicious'] += 1
        self.update_stat('suspicious', self.stats['suspicious'])

        self.log(f"  ⚠️ SUSPICIOUS (Risk: {risk_score:.0f}/100)", 'WARNING')
        self.log(f"  Reason: {reason}", 'WARNING')

        # STEP 2: Feature Extraction
        self.log(f"  🔬 Extracting features...", 'INFO')

        try:
            features = self.feature_extractor.extract_features(pid)
        except Exception as e:
            self.log(f"  ✗ Feature extraction error: {str(e)}", 'ERROR')
            return

        if features is None:
            self.log(f"  ✗ Feature extraction failed - check logs for details", 'ERROR')
            return

        self.log(f"  ✓ Extracted {len(features)} features", 'INFO')

        # STEP 3: ML Detection
        if self.detection_engine is None:
            self.log(f"  ⚠️ ML engine not available (demo mode)", 'WARNING')
            return

        self.log(f"  🤖 Analyzing with AI model...", 'INFO')

        try:
            is_malware, predicted_class, confidence, probabilities = \
                self.detection_engine.is_malware(features)

            # Show probabilities
            self.log(f"  Prediction probabilities:", 'INFO')
            for class_name, prob in sorted(probabilities.items(), key=lambda x: x[1], reverse=True):
                self.log(f"    {class_name}: {prob*100:.2f}%", 'INFO')

            # HYBRID DETECTION: Override ML prediction if behavioral + name match ransomware
            # This is needed because psutil features are estimates, not real memory dumps
            ransomware_keywords = ['ransom', 'crypt', 'encrypt', 'locker', 'simulator']
            has_ransomware_name = any(keyword in name.lower() for keyword in ransomware_keywords)

            # If high risk (95+) + ransomware-like name + ML says malware → classify as Ransomware
            if risk_score >= 95 and has_ransomware_name and predicted_class != "Benign":
                self.log(f"  🎯 Behavioral + Name match: Overriding to Ransomware", 'WARNING')
                predicted_class = "Ransomware"
                is_malware = True
                confidence = max(confidence, risk_score / 100)  # Use higher confidence

            if not is_malware:
                self.log(f"  ✓ Classified as: {predicted_class} ({confidence*100:.1f}%)", 'INFO')
                return

            # MALWARE DETECTED!
            self.stats['threats'] += 1
            self.update_stat('threats', self.stats['threats'])

            self.log("="*60, 'CRITICAL')
            self.log(f"🚨 MALWARE DETECTED: {predicted_class}", 'CRITICAL')
            self.log(f"   Process: {name} (PID: {pid})", 'CRITICAL')
            self.log(f"   Confidence: {confidence*100:.1f}%", 'CRITICAL')
            self.log("="*60, 'CRITICAL')

            # Show alert popup with kill confirmation
            detection_report = self.detection_engine.generate_detection_report(features, process_info)
            self.root.after(0, lambda: self.show_threat_alert_with_action(
                name, predicted_class, confidence, pid, detection_report, process_info
            ))

        except Exception as e:
            self.log(f"  ✗ Detection error: {str(e)[:100]}", 'ERROR')

    def show_threat_alert_with_action(self, process_name, threat_class, confidence, pid, detection_report, process_info):
        """Show popup alert with action buttons - ASK USER what to do"""
        alert = tk.Toplevel(self.root)
        alert.title("⚠️ THREAT DETECTED")
        alert.geometry("550x420")
        alert.configure(bg='#1a1a1a')
        alert.transient(self.root)
        alert.grab_set()

        # Center the window
        alert.update_idletasks()
        x = (alert.winfo_screenwidth() // 2) - (550 // 2)
        y = (alert.winfo_screenheight() // 2) - (420 // 2)
        alert.geometry(f'550x420+{x}+{y}')

        # Make window stay on top
        alert.attributes('-topmost', True)
        alert.focus_force()

        # Alert content
        tk.Label(
            alert,
            text="🚨 RANSOMWARE DETECTED",
            font=('Arial', 18, 'bold'),
            bg='#2d2d2d',
            fg='#ff4444'
        ).pack(pady=20)

        # Threat details
        details_frame = tk.Frame(alert, bg='#2d2d2d')
        details_frame.pack(pady=10)

        tk.Label(
            details_frame,
            text=f"Threat Type: {threat_class}",
            font=('Arial', 13),
            bg='#2d2d2d',
            fg='#ffaa00'
        ).pack(pady=5)

        tk.Label(
            details_frame,
            text=f"Process: {process_name}",
            font=('Arial', 13, 'bold'),
            bg='#2d2d2d',
            fg='white'
        ).pack(pady=5)

        tk.Label(
            details_frame,
            text=f"PID: {pid}",
            font=('Arial', 12),
            bg='#2d2d2d',
            fg='#888888'
        ).pack(pady=2)

        tk.Label(
            details_frame,
            text=f"Confidence: {confidence*100:.1f}%",
            font=('Arial', 13),
            bg='#2d2d2d',
            fg='white'
        ).pack(pady=5)

        # Warning message
        tk.Label(
            alert,
            text="⚠️ This process may harm your system!",
            font=('Arial', 12),
            bg='#2d2d2d',
            fg='#ffaa00'
        ).pack(pady=10)

        tk.Label(
            alert,
            text="Do you want to terminate this process?",
            font=('Arial', 13, 'bold'),
            bg='#2d2d2d',
            fg='white'
        ).pack(pady=5)

        # Action buttons
        button_frame = tk.Frame(alert, bg='#2d2d2d')
        button_frame.pack(pady=20)

        def kill_threat():
            """Kill the threat and close alert - Run in background thread to prevent GUI lag"""
            alert.destroy()
            self.log(f"  ⚡ User confirmed - Neutralizing threat...", 'WARNING')

            # Run threat response in background thread to keep GUI responsive
            def neutralize():
                try:
                    response_summary = self.response_system.respond_to_threat(detection_report, process_info)

                    if any(a['success'] for a in response_summary['actions_taken'] if a['action'] == 'KILL_PROCESS'):
                        self.stats['neutralized'] += 1
                        self.update_stat('neutralized', self.stats['neutralized'])
                        self.log(f"  ✓ Threat neutralized", 'INFO')
                        self.log(f"  ✓ Process terminated (PID: {pid})", 'INFO')
                        self.log(f"  ✓ File quarantined", 'INFO')
                    else:
                        self.log(f"  ✗ Failed to neutralize threat", 'ERROR')
                except Exception as e:
                    self.log(f"  ✗ Error neutralizing threat: {e}", 'ERROR')

            # Run in background thread
            threading.Thread(target=neutralize, daemon=True).start()

        def ignore_threat():
            """Ignore the threat"""
            alert.destroy()
            self.log(f"  ⚠️ User chose to ignore threat - Process still running", 'WARNING')
            self.log(f"  ⚠️ WARNING: {process_name} (PID: {pid}) not terminated", 'WARNING')

        # KILL button (red, dangerous) - Improved with hover effect
        kill_btn = tk.Button(
            button_frame,
            text="🔴 KILL PROCESS",
            font=('Arial', 14, 'bold'),
            bg='#cc0000',
            fg='white',
            activebackground='#ff0000',
            activeforeground='white',
            command=kill_threat,
            padx=30,
            pady=15,
            relief=tk.RAISED,
            borderwidth=4,
            cursor='hand2'
        )
        kill_btn.pack(side=tk.LEFT, padx=15)

        # IGNORE button (gray, safer) - Improved with hover effect
        ignore_btn = tk.Button(
            button_frame,
            text="⚪ IGNORE",
            font=('Arial', 14),
            bg='#444444',
            fg='white',
            activebackground='#666666',
            activeforeground='white',
            command=ignore_threat,
            padx=30,
            pady=15,
            relief=tk.RAISED,
            borderwidth=4,
            cursor='hand2'
        )
        ignore_btn.pack(side=tk.LEFT, padx=15)

    def stop_protection(self):
        """Stop the antivirus protection"""
        if not self.is_running:
            return

        self.log("Stopping protection...", 'WARNING')
        self.is_running = False

        # Update UI
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        self.update_status("● STOPPED", '#ff4444')

        self.log("="*60, 'WARNING')
        self.log("🛑 PROTECTION STOPPED - System is no longer protected", 'WARNING')
        self.log("="*60, 'WARNING')

    def view_logs(self):
        """Open logs folder"""
        logs_path = os.path.abspath('logs')
        if os.path.exists(logs_path):
            os.startfile(logs_path)
        else:
            messagebox.showinfo("Logs", "No logs found yet")

    def view_quarantine(self):
        """Open quarantine folder"""
        quarantine_path = os.path.abspath('quarantine')
        if os.path.exists(quarantine_path):
            os.startfile(quarantine_path)
        else:
            messagebox.showinfo("Quarantine", "Quarantine folder is empty")

    def on_closing(self):
        """Handle window close"""
        if self.is_running:
            if messagebox.askyesno("Confirm Exit", "Protection is active. Are you sure you want to exit?"):
                self.stop_protection()
                self.root.destroy()
        else:
            self.root.destroy()

    def run(self):
        """Start the GUI application"""
        self.root.mainloop()

if __name__ == '__main__':
    app = RansomwareProtectorApp()
    app.run()
