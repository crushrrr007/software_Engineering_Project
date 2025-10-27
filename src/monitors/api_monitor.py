"""
API Monitor Module
Monitors Windows API calls related to screen capture
"""

import time
import threading
from typing import Dict, List
from datetime import datetime, timedelta
from collections import defaultdict, deque


class APICallRecord:
    """Record of an API call"""

    def __init__(self, api_name: str, dll_name: str, pid: int, process_name: str):
        self.api_name = api_name
        self.dll_name = dll_name
        self.pid = pid
        self.process_name = process_name
        self.timestamp = datetime.now()

    def to_dict(self) -> Dict:
        """Convert to dictionary"""
        return {
            "api_name": self.api_name,
            "dll_name": self.dll_name,
            "pid": self.pid,
            "process_name": self.process_name,
            "timestamp": self.timestamp.isoformat()
        }


class APIMonitor:
    """Monitors Windows API calls for screen capture activities"""

    def __init__(self, config: Dict, logger):
        """
        Initialize the API monitor

        Args:
            config: Configuration dictionary
            logger: Logger instance
        """
        self.config = config
        self.logger = logger
        self.running = False
        self.alert_callback = None

        # API call history (process_name -> deque of call records)
        self.call_history = defaultdict(lambda: deque(maxlen=1000))

        # API call counters (process_name -> api_name -> count)
        self.call_counters = defaultdict(lambda: defaultdict(int))

        # Monitored APIs
        self.monitored_apis = {
            "gdi32.dll": ["BitBlt", "StretchBlt", "CreateCompatibleDC",
                          "CreateCompatibleBitmap", "GetDIBits"],
            "user32.dll": ["GetDC", "GetWindowDC", "GetDCEx", "ReleaseDC", "PrintWindow"]
        }

        # Pattern detection
        self.pattern_window = config.get("pattern_window", 60)  # seconds
        self.call_threshold = config.get("call_threshold", 30)  # calls per minute

    def start(self):
        """Start the API monitor"""
        if self.running:
            self.logger.warning("API monitor already running")
            return

        self.running = True
        self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.monitor_thread.start()
        self.logger.info("API monitor started")

    def stop(self):
        """Stop the API monitor"""
        self.running = False
        if hasattr(self, 'monitor_thread'):
            self.monitor_thread.join(timeout=5)
        self.logger.info("API monitor stopped")

    def set_alert_callback(self, callback):
        """Set callback function for alerts"""
        self.alert_callback = callback

    def _monitor_loop(self):
        """Main monitoring loop"""
        while self.running:
            try:
                self._analyze_patterns()
                self._cleanup_old_records()
                time.sleep(5)
            except Exception as e:
                self.logger.error(f"Error in API monitor loop: {e}", exc_info=True)
                time.sleep(5)

    def record_api_call(self, api_name: str, dll_name: str, pid: int, process_name: str):
        """
        Record an API call

        Args:
            api_name: Name of the API function
            dll_name: Name of the DLL
            pid: Process ID
            process_name: Process name
        """
        record = APICallRecord(api_name, dll_name, pid, process_name)
        self.call_history[process_name].append(record)
        self.call_counters[process_name][api_name] += 1

        self.logger.debug(f"API call recorded: {process_name} -> {dll_name}!{api_name}")

        # Check for immediate suspicious patterns
        self._check_suspicious_call(record)

    def _check_suspicious_call(self, record: APICallRecord):
        """
        Check if an API call is immediately suspicious

        Args:
            record: APICallRecord object
        """
        # Check if this is a screen capture API
        if record.api_name in ["BitBlt", "GetDC", "GetWindowDC", "GetDIBits"]:
            # Get recent calls from this process
            recent_calls = self._get_recent_calls(record.process_name, seconds=10)

            # If multiple capture API calls in short time
            capture_calls = [c for c in recent_calls
                           if c.api_name in ["BitBlt", "GetDC", "GetWindowDC", "GetDIBits"]]

            if len(capture_calls) >= 3:
                self._create_alert(
                    record,
                    "rapid_api_calls",
                    f"Rapid screen capture API calls detected: {len(capture_calls)} calls in 10 seconds"
                )

    def _analyze_patterns(self):
        """Analyze API call patterns for suspicious behavior"""
        cutoff_time = datetime.now() - timedelta(seconds=self.pattern_window)

        for process_name, call_deque in self.call_history.items():
            # Count recent calls
            recent_calls = [c for c in call_deque if c.timestamp > cutoff_time]

            if not recent_calls:
                continue

            # Count screen capture API calls
            capture_calls = [c for c in recent_calls
                           if c.api_name in ["BitBlt", "StretchBlt", "GetDC", "GetWindowDC"]]

            # Alert if threshold exceeded
            if len(capture_calls) > self.call_threshold:
                self._create_alert(
                    recent_calls[-1],
                    "api_threshold_exceeded",
                    f"Excessive screen capture API calls: {len(capture_calls)} calls in {self.pattern_window} seconds"
                )

            # Check for suspicious API sequences
            self._check_api_sequences(recent_calls)

    def _check_api_sequences(self, calls: List[APICallRecord]):
        """
        Check for suspicious API call sequences

        Args:
            calls: List of API call records
        """
        # Pattern: GetDC -> CreateCompatibleDC -> CreateCompatibleBitmap -> BitBlt
        # This is a common screenshot sequence

        if len(calls) < 4:
            return

        # Look for the pattern in the last calls
        pattern_sequence = ["GetDC", "CreateCompatibleDC", "CreateCompatibleBitmap", "BitBlt"]

        for i in range(len(calls) - 3):
            sequence = [calls[i+j].api_name for j in range(4)]

            if sequence == pattern_sequence:
                time_span = (calls[i+3].timestamp - calls[i].timestamp).total_seconds()

                if time_span < 2:  # Completed in less than 2 seconds
                    self._create_alert(
                        calls[i+3],
                        "screenshot_sequence_detected",
                        f"Classic screenshot API sequence detected (completed in {time_span:.2f}s)"
                    )

    def _get_recent_calls(self, process_name: str, seconds: int = 60) -> List[APICallRecord]:
        """
        Get recent API calls from a process

        Args:
            process_name: Process name
            seconds: Time window in seconds

        Returns:
            List of recent API call records
        """
        cutoff_time = datetime.now() - timedelta(seconds=seconds)
        calls = self.call_history.get(process_name, deque())
        return [c for c in calls if c.timestamp > cutoff_time]

    def _cleanup_old_records(self):
        """Remove old API call records"""
        cutoff_time = datetime.now() - timedelta(minutes=30)

        for process_name in list(self.call_history.keys()):
            call_deque = self.call_history[process_name]

            # Remove old records
            while call_deque and call_deque[0].timestamp < cutoff_time:
                call_deque.popleft()

            # Remove empty entries
            if not call_deque:
                del self.call_history[process_name]

    def _create_alert(self, record: APICallRecord, alert_type: str, message: str):
        """
        Create an alert for suspicious API activity

        Args:
            record: APICallRecord object
            alert_type: Type of alert
            message: Alert message
        """
        # Calculate severity based on alert type
        severity_map = {
            "rapid_api_calls": "medium",
            "api_threshold_exceeded": "high",
            "screenshot_sequence_detected": "high",
            "suspicious_api_pattern": "medium"
        }

        alert = {
            "timestamp": datetime.now(),
            "type": "api_monitor",
            "severity": severity_map.get(alert_type, "medium"),
            "alert_type": alert_type,
            "process": {
                "pid": record.pid,
                "name": record.process_name
            },
            "api_call": {
                "api_name": record.api_name,
                "dll_name": record.dll_name
            },
            "message": message,
            "mitre_technique": "T1113"
        }

        self.logger.warning(f"[API Monitor] {message}")

        if self.alert_callback:
            self.alert_callback(alert)

    def get_statistics(self) -> Dict:
        """Get API monitoring statistics"""
        total_processes = len(self.call_history)
        total_calls = sum(len(calls) for calls in self.call_history.values())

        # Top API callers
        top_callers = sorted(
            [(proc, len(calls)) for proc, calls in self.call_history.items()],
            key=lambda x: x[1],
            reverse=True
        )[:10]

        # Most called APIs
        api_counts = defaultdict(int)
        for counters in self.call_counters.values():
            for api_name, count in counters.items():
                api_counts[api_name] += count

        top_apis = sorted(api_counts.items(), key=lambda x: x[1], reverse=True)[:10]

        return {
            "total_processes_monitored": total_processes,
            "total_api_calls_recorded": total_calls,
            "top_callers": [{"process": proc, "calls": count} for proc, count in top_callers],
            "top_apis": [{"api": api, "calls": count} for api, count in top_apis],
            "monitoring_since": datetime.now()
        }

    def get_process_calls(self, process_name: str) -> List[Dict]:
        """
        Get API calls for a specific process

        Args:
            process_name: Process name

        Returns:
            List of API call records
        """
        calls = self.call_history.get(process_name, deque())
        return [call.to_dict() for call in calls]

    def is_monitored_api(self, dll_name: str, api_name: str) -> bool:
        """
        Check if an API is being monitored

        Args:
            dll_name: DLL name
            api_name: API function name

        Returns:
            bool: True if monitored
        """
        return api_name in self.monitored_apis.get(dll_name, [])


# Simulated API hook for demonstration
class APIHook:
    """
    Simulated API hook for demonstration purposes
    In production, this would use actual API hooking techniques
    """

    def __init__(self, api_monitor: APIMonitor):
        self.api_monitor = api_monitor
        self.hooked = False

    def install_hooks(self):
        """Install API hooks (simulated)"""
        self.hooked = True
        self.api_monitor.logger.info("API hooks installed (simulated)")
        return True

    def remove_hooks(self):
        """Remove API hooks (simulated)"""
        self.hooked = False
        self.api_monitor.logger.info("API hooks removed")
        return True

    def simulate_api_call(self, dll_name: str, api_name: str, pid: int, process_name: str):
        """
        Simulate an API call detection (for testing)

        Args:
            dll_name: DLL name
            api_name: API function name
            pid: Process ID
            process_name: Process name
        """
        if self.hooked:
            self.api_monitor.record_api_call(api_name, dll_name, pid, process_name)
