"""
Process Monitor Module
Monitors running processes for suspicious screen capture behavior
"""

import psutil
import time
import os
from typing import Dict, List, Set
from datetime import datetime
import threading


class ProcessInfo:
    """Information about a monitored process"""

    def __init__(self, pid: int, name: str, exe: str = None, cmdline: List[str] = None):
        self.pid = pid
        self.name = name
        self.exe = exe or ""
        self.cmdline = cmdline or []
        self.create_time = time.time()
        self.last_seen = time.time()
        self.suspicious_count = 0
        self.risk_score = 0
        self.flags = set()

    def add_flag(self, flag: str):
        """Add a suspicious flag to the process"""
        self.flags.add(flag)
        self.suspicious_count += 1
        self.calculate_risk_score()

    def calculate_risk_score(self):
        """Calculate risk score based on flags"""
        score = 0

        # Base score from suspicious count
        score += min(self.suspicious_count * 2, 30)

        # Flag-based scoring
        flag_scores = {
            "hidden_window": 4,
            "no_window": 3,
            "suspicious_name": 7,  # ✅ INCREASED! Now generates HIGH alerts
            "unsigned": 2,
            "temp_location": 4,
            "suspicious_parent": 4,
            "api_hooking": 6,
            "network_activity": 3,
            "rapid_screenshots": 7,
            "suspicious_cmdline": 5,
            "suspicious_extension": 6,
            "high_memory_usage": 2
        }

        for flag in self.flags:
            score += flag_scores.get(flag, 1)

        self.risk_score = min(score, 10)

    def to_dict(self) -> Dict:
        """Convert to dictionary"""
        return {
            "pid": self.pid,
            "name": self.name,
            "exe": self.exe,
            "cmdline": " ".join(self.cmdline),
            "risk_score": self.risk_score,
            "flags": list(self.flags),
            "suspicious_count": self.suspicious_count,
            "uptime": time.time() - self.create_time
        }


class ProcessMonitor:
    """Monitors system processes for suspicious screen capture activity"""

    def __init__(self, config: Dict, logger):
        """
        Initialize the process monitor

        Args:
            config: Configuration dictionary
            logger: Logger instance
        """
        self.config = config
        self.logger = logger
        self.running = False
        self.monitored_processes: Dict[int, ProcessInfo] = {}
        self.alert_callback = None
        self.suspicious_names = set(config.get("suspicious_processes", []))
        self.whitelist = set(config.get("whitelist", []))

        # Known screenshot utilities and patterns
        self.screenshot_patterns = [
            "screenshot", "capture", "snap", "record", "screen",
            "snip", "grab", "shot", "psr", "gyazo", "puush",
            "lightshot", "picpick", "faststone", "irfanview",
            "clipboardimage", "ocr", "imagewatch", "screenrec"
        ]

        # Track screenshot frequency per process
        self.screenshot_frequency = {}

        # Enhanced behavioral patterns
        self.suspicious_cmdline_patterns = [
            "screenshot", "capture", "--screenshot", "-screenshot",
            "/screenshot", "screencap", "printscreen", "/grab",
            "--capture", "-c", "--snap"
        ]

    def start(self):
        """Start the process monitor"""
        if self.running:
            self.logger.warning("Process monitor already running")
            return

        self.running = True
        self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.monitor_thread.start()
        self.logger.info("Process monitor started")

    def stop(self):
        """Stop the process monitor"""
        self.running = False
        if hasattr(self, 'monitor_thread'):
            self.monitor_thread.join(timeout=5)
        self.logger.info("Process monitor stopped")

    def set_alert_callback(self, callback):
        """Set callback function for alerts"""
        self.alert_callback = callback

    def _monitor_loop(self):
        """Main monitoring loop"""
        scan_interval = self.config.get("scan_interval", 5)

        while self.running:
            try:
                self._scan_processes()
                time.sleep(scan_interval)
            except Exception as e:
                self.logger.error(f"Error in process monitor loop: {e}", exc_info=True)
                time.sleep(scan_interval)

    def _scan_processes(self):
        """Scan all running processes"""
        current_pids = set()

        try:
            for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline']):
                try:
                    pid = proc.info['pid']
                    name = proc.info['name']
                    exe = proc.info.get('exe', '')
                    cmdline = proc.info.get('cmdline', [])

                    current_pids.add(pid)

                    # Skip whitelisted processes
                    if name in self.whitelist:
                        continue

                    # Update or create process info
                    if pid not in self.monitored_processes:
                        proc_info = ProcessInfo(pid, name, exe, cmdline)
                        self.monitored_processes[pid] = proc_info
                        self._analyze_process(proc, proc_info)
                    else:
                        self.monitored_processes[pid].last_seen = time.time()

                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue

            # Remove dead processes
            dead_pids = set(self.monitored_processes.keys()) - current_pids
            for pid in dead_pids:
                del self.monitored_processes[pid]

        except Exception as e:
            self.logger.error(f"Error scanning processes: {e}")

    def _analyze_process(self, proc: psutil.Process, proc_info: ProcessInfo):
        """
        Analyze a process for suspicious behavior (Enhanced version)

        Args:
            proc: psutil Process object
            proc_info: ProcessInfo object
        """
        try:
            # Check if process name is suspicious
            if proc_info.name.lower() in self.suspicious_names:
                proc_info.add_flag("suspicious_name")
                self._create_alert(proc_info, "Known screenshot utility detected")

            # Check for screenshot-related patterns in name or path
            name_lower = proc_info.name.lower()
            for pattern in self.screenshot_patterns:
                if pattern in name_lower:
                    proc_info.add_flag("suspicious_name")
                    self._create_alert(proc_info, f"Process name contains '{pattern}'")
                    break

            # Enhanced: Check command line arguments for screenshot indicators
            cmdline_str = " ".join(proc_info.cmdline).lower()
            for pattern in self.suspicious_cmdline_patterns:
                if pattern in cmdline_str:
                    proc_info.add_flag("suspicious_cmdline")
                    self._create_alert(proc_info, f"Suspicious command line argument detected: '{pattern}'")
                    break

            # Check if executable is in TEMP directory
            if proc_info.exe and ("temp" in proc_info.exe.lower() or "tmp" in proc_info.exe.lower()):
                proc_info.add_flag("temp_location")
                self._create_alert(proc_info, "Process running from temporary directory")

            # Enhanced: Check for suspicious file extensions in path
            if proc_info.exe and any(ext in proc_info.exe.lower() for ext in ['.scr', '.pif', '.bat', '.vbs']):
                proc_info.add_flag("suspicious_extension")
                self._create_alert(proc_info, "Process has suspicious file extension")

            # Enhanced: Monitor memory usage patterns (high memory could indicate image buffering)
            try:
                memory_info = proc.memory_info()
                memory_mb = memory_info.rss / (1024 * 1024)
                if memory_mb > 500:  # More than 500MB
                    proc_info.add_flag("high_memory_usage")
                    self.logger.debug(f"Process {proc_info.name} using {memory_mb:.2f}MB of memory")
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

            # Enhanced: Check for network connections (potential exfiltration)
            try:
                connections = proc.connections()
                if connections:
                    proc_info.add_flag("network_activity")
                    external_connections = [c for c in connections if c.status == 'ESTABLISHED']
                    if external_connections:
                        self._create_alert(proc_info, f"Process has {len(external_connections)} active network connections")
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

            # Check for hidden window (Windows-specific)
            if os.name == 'nt':
                try:
                    import win32gui
                    import win32process

                    def enum_windows_callback(hwnd, results):
                        _, found_pid = win32process.GetWindowThreadProcessId(hwnd)
                        if found_pid == proc_info.pid:
                            if not win32gui.IsWindowVisible(hwnd):
                                results.append(hwnd)

                    hidden_windows = []
                    win32gui.EnumWindows(enum_windows_callback, hidden_windows)

                    if hidden_windows:
                        proc_info.add_flag("hidden_window")
                        self._create_alert(proc_info, "Process has hidden windows")

                except ImportError:
                    pass  # pywin32 not available

            # Check parent process
            try:
                parent = proc.parent()
                if parent and parent.name() in ["powershell.exe", "cmd.exe", "wscript.exe", "bash.exe", "python.exe"]:
                    proc_info.add_flag("suspicious_parent")
                    self._create_alert(proc_info, f"Process spawned by {parent.name()}")
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

            # Enhanced: Check for unsigned executables (Windows-specific)
            if os.name == 'nt' and proc_info.exe:
                try:
                    import subprocess
                    result = subprocess.run(
                        ['powershell', '-Command', f'Get-AuthenticodeSignature "{proc_info.exe}"'],
                        capture_output=True, text=True, timeout=5
                    )
                    if 'NotSigned' in result.stdout:
                        proc_info.add_flag("unsigned")
                        self.logger.debug(f"Process {proc_info.name} is unsigned")
                except:
                    pass

        except Exception as e:
            self.logger.error(f"Error analyzing process {proc_info.name}: {e}")

    def _create_alert(self, proc_info: ProcessInfo, reason: str):
        """
        Create an alert for suspicious process

        Args:
            proc_info: ProcessInfo object
            reason: Reason for alert
        """
        alert = {
            "timestamp": datetime.now(),
            "type": "process",
            "severity": self._calculate_severity(proc_info.risk_score),
            "process": proc_info.to_dict(),
            "reason": reason,
            "message": f"Suspicious process detected: {proc_info.name} (PID: {proc_info.pid}) - {reason}",
            "mitre_technique": "T1113"
        }

        self.logger.warning(alert["message"])

        if self.alert_callback:
            self.alert_callback(alert)

    def _calculate_severity(self, risk_score: int) -> str:
        """Calculate severity level from risk score"""
        if risk_score >= 9:
            return "critical"
        elif risk_score >= 7:
            return "high"
        elif risk_score >= 4:
            return "medium"
        else:
            return "low"

    def get_suspicious_processes(self) -> List[ProcessInfo]:
        """Get list of suspicious processes"""
        return [p for p in self.monitored_processes.values() if p.risk_score >= 3]

    def get_all_processes(self) -> List[ProcessInfo]:
        """Get list of all monitored processes"""
        return list(self.monitored_processes.values())

    def get_process_by_pid(self, pid: int) -> ProcessInfo:
        """Get process info by PID"""
        return self.monitored_processes.get(pid)

    def kill_process(self, pid: int) -> bool:
        """
        Kill a suspicious process

        Args:
            pid: Process ID

        Returns:
            bool: True if successful
        """
        try:
            proc = psutil.Process(pid)
            proc.kill()
            self.logger.warning(f"Killed process {pid}")
            return True
        except Exception as e:
            self.logger.error(f"Failed to kill process {pid}: {e}")
            return False

    def get_statistics(self) -> Dict:
        """Get monitoring statistics"""
        total = len(self.monitored_processes)
        suspicious = len(self.get_suspicious_processes())

        risk_distribution = {
            "low": 0,
            "medium": 0,
            "high": 0,
            "critical": 0
        }

        for proc in self.monitored_processes.values():
            severity = self._calculate_severity(proc.risk_score)
            risk_distribution[severity] += 1

        return {
            "total_processes": total,
            "suspicious_processes": suspicious,
            "risk_distribution": risk_distribution,
            "monitoring_since": datetime.now()
        }
