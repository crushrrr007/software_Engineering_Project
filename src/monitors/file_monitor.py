"""
File System Monitor Module
Monitors file system for suspicious screenshot file creation
"""

import os
import time
import threading
from typing import Dict, List, Set
from datetime import datetime, timedelta
from collections import defaultdict, deque
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler, FileCreatedEvent


class FileCreationRecord:
    """Record of a file creation event"""

    def __init__(self, file_path: str, file_size: int = 0):
        self.file_path = file_path
        self.file_name = os.path.basename(file_path)
        self.directory = os.path.dirname(file_path)
        self.file_size = file_size
        self.timestamp = datetime.now()
        self.extension = os.path.splitext(file_path)[1].lower()

    def to_dict(self) -> Dict:
        """Convert to dictionary"""
        return {
            "file_path": self.file_path,
            "file_name": self.file_name,
            "directory": self.directory,
            "file_size": self.file_size,
            "extension": self.extension,
            "timestamp": self.timestamp.isoformat()
        }


class ScreenshotFileHandler(FileSystemEventHandler):
    """Handler for file system events"""

    def __init__(self, file_monitor):
        self.file_monitor = file_monitor
        super().__init__()

    def on_created(self, event):
        """Handle file creation events"""
        if isinstance(event, FileCreatedEvent):
            self.file_monitor.handle_file_created(event.src_path)


class FileMonitor:
    """Monitors file system for screenshot file creation"""

    def __init__(self, config: Dict, logger):
        """
        Initialize the file monitor

        Args:
            config: Configuration dictionary
            logger: Logger instance
        """
        self.config = config
        self.logger = logger
        self.running = False
        self.alert_callback = None

        # File creation history
        self.creation_history = deque(maxlen=10000)

        # Directory-based creation tracking
        self.dir_creation_count = defaultdict(int)
        self.recent_creations = defaultdict(deque)

        # Configuration
        self.image_extensions = set(config.get("image_extensions", [
            ".png", ".jpg", ".jpeg", ".bmp", ".gif", ".tiff", ".webp"
        ]))
        self.monitored_paths = self._expand_paths(config.get("monitored_paths", []))
        self.ignore_paths = set(self._expand_paths(config.get("ignore_paths", [])))
        self.rapid_threshold = config.get("rapid_creation_threshold", 5)
        self.rapid_window = config.get("rapid_creation_window", 30)

        # Watchdog observers
        self.observers = []

    def _expand_paths(self, paths: List[str]) -> List[str]:
        """
        Expand environment variables in paths

        Args:
            paths: List of paths with potential env vars

        Returns:
            List of expanded paths
        """
        expanded = []
        for path in paths:
            try:
                expanded_path = os.path.expandvars(path)
                if os.path.exists(expanded_path):
                    expanded.append(expanded_path)
                else:
                    self.logger.warning(f"Path does not exist: {expanded_path}")
            except Exception as e:
                self.logger.error(f"Error expanding path {path}: {e}")
        return expanded

    def start(self):
        """Start the file monitor"""
        if self.running:
            self.logger.warning("File monitor already running")
            return

        self.running = True

        # Start watchdog observers for each monitored path
        for path in self.monitored_paths:
            try:
                observer = Observer()
                event_handler = ScreenshotFileHandler(self)
                observer.schedule(event_handler, path, recursive=True)
                observer.start()
                self.observers.append(observer)
                self.logger.info(f"Monitoring path: {path}")
            except Exception as e:
                self.logger.error(f"Failed to monitor path {path}: {e}")

        # Start cleanup thread
        self.cleanup_thread = threading.Thread(target=self._cleanup_loop, daemon=True)
        self.cleanup_thread.start()

        self.logger.info("File monitor started")

    def stop(self):
        """Stop the file monitor"""
        self.running = False

        # Stop all observers
        for observer in self.observers:
            observer.stop()
            observer.join(timeout=5)

        if hasattr(self, 'cleanup_thread'):
            self.cleanup_thread.join(timeout=5)

        self.logger.info("File monitor stopped")

    def set_alert_callback(self, callback):
        """Set callback function for alerts"""
        self.alert_callback = callback

    def handle_file_created(self, file_path: str):
        """
        Handle file creation event

        Args:
            file_path: Path to created file
        """
        try:
            # Check if it's an image file
            _, ext = os.path.splitext(file_path)
            if ext.lower() not in self.image_extensions:
                return

            # Check if path should be ignored
            if any(ignore in file_path for ignore in self.ignore_paths):
                return

            # Get file info
            file_size = 0
            try:
                file_size = os.path.getsize(file_path)
            except:
                pass

            # Record the creation
            record = FileCreationRecord(file_path, file_size)
            self.creation_history.append(record)

            directory = os.path.dirname(file_path)
            self.recent_creations[directory].append(record)
            self.dir_creation_count[directory] += 1

            self.logger.debug(f"Image file created: {file_path} ({file_size} bytes)")

            # Analyze for suspicious patterns
            self._analyze_creation(record)

        except Exception as e:
            self.logger.error(f"Error handling file creation {file_path}: {e}")

    def _analyze_creation(self, record: FileCreationRecord):
        """
        Analyze file creation for suspicious patterns

        Args:
            record: FileCreationRecord object
        """
        directory = record.directory

        # Check for rapid file creation in same directory
        recent = self._get_recent_creations(directory, self.rapid_window)

        if len(recent) >= self.rapid_threshold:
            self._create_alert(
                record,
                "rapid_file_creation",
                f"Rapid screenshot creation detected: {len(recent)} files in {self.rapid_window} seconds in {directory}"
            )

        # Check for suspicious file names
        suspicious_patterns = ["screenshot", "capture", "snap", "grab", "screen"]
        filename_lower = record.file_name.lower()

        for pattern in suspicious_patterns:
            if pattern in filename_lower:
                self._create_alert(
                    record,
                    "suspicious_filename",
                    f"Suspicious screenshot filename detected: {record.file_name}"
                )
                break

        # Check for suspicious directories
        suspicious_dirs = ["temp", "tmp", "appdata\\local\\temp", "programdata"]
        dir_lower = directory.lower()

        for susp_dir in suspicious_dirs:
            if susp_dir in dir_lower:
                self._create_alert(
                    record,
                    "suspicious_directory",
                    f"Screenshot created in suspicious location: {directory}"
                )
                break

        # Check for sequential naming (screenshot1.png, screenshot2.png, etc.)
        if self._is_sequential_naming(record, recent):
            self._create_alert(
                record,
                "sequential_naming",
                f"Sequential screenshot naming detected in {directory}"
            )

    def _get_recent_creations(self, directory: str, seconds: int) -> List[FileCreationRecord]:
        """
        Get recent file creations in a directory

        Args:
            directory: Directory path
            seconds: Time window in seconds

        Returns:
            List of recent file creation records
        """
        cutoff_time = datetime.now() - timedelta(seconds=seconds)
        recent_deque = self.recent_creations.get(directory, deque())
        return [r for r in recent_deque if r.timestamp > cutoff_time]

    def _is_sequential_naming(self, record: FileCreationRecord,
                            recent: List[FileCreationRecord]) -> bool:
        """
        Check if files have sequential naming pattern

        Args:
            record: Current file creation record
            recent: Recent file creation records

        Returns:
            bool: True if sequential pattern detected
        """
        if len(recent) < 3:
            return False

        # Extract numbers from filenames
        import re
        pattern = re.compile(r'(\d+)')

        numbers = []
        for r in recent[-3:]:
            matches = pattern.findall(r.file_name)
            if matches:
                numbers.append(int(matches[-1]))

        # Check if numbers are sequential
        if len(numbers) >= 3:
            diffs = [numbers[i+1] - numbers[i] for i in range(len(numbers)-1)]
            if all(d == 1 for d in diffs):
                return True

        return False

    def _cleanup_loop(self):
        """Cleanup loop to remove old records"""
        while self.running:
            try:
                self._cleanup_old_records()
                time.sleep(60)  # Run every minute
            except Exception as e:
                self.logger.error(f"Error in cleanup loop: {e}")
                time.sleep(60)

    def _cleanup_old_records(self):
        """Remove old file creation records"""
        cutoff_time = datetime.now() - timedelta(hours=1)

        for directory in list(self.recent_creations.keys()):
            recent_deque = self.recent_creations[directory]

            # Remove old records
            while recent_deque and recent_deque[0].timestamp < cutoff_time:
                recent_deque.popleft()

            # Remove empty entries
            if not recent_deque:
                del self.recent_creations[directory]

    def _create_alert(self, record: FileCreationRecord, alert_type: str, message: str):
        """
        Create an alert for suspicious file activity

        Args:
            record: FileCreationRecord object
            alert_type: Type of alert
            message: Alert message
        """
        severity_map = {
            "rapid_file_creation": "high",
            "suspicious_filename": "medium",
            "suspicious_directory": "medium",
            "sequential_naming": "high"
        }

        alert = {
            "timestamp": datetime.now(),
            "type": "file_monitor",
            "severity": severity_map.get(alert_type, "medium"),
            "alert_type": alert_type,
            "file": record.to_dict(),
            "message": message,
            "mitre_technique": "T1113"
        }

        self.logger.warning(f"[File Monitor] {message}")

        if self.alert_callback:
            self.alert_callback(alert)

    def get_statistics(self) -> Dict:
        """Get file monitoring statistics"""
        total_files = len(self.creation_history)

        # Count by extension
        ext_counts = defaultdict(int)
        for record in self.creation_history:
            ext_counts[record.extension] += 1

        # Top directories
        top_dirs = sorted(
            self.dir_creation_count.items(),
            key=lambda x: x[1],
            reverse=True
        )[:10]

        # Recent files (last hour)
        cutoff = datetime.now() - timedelta(hours=1)
        recent_count = sum(1 for r in self.creation_history if r.timestamp > cutoff)

        return {
            "total_files_tracked": total_files,
            "files_last_hour": recent_count,
            "monitored_paths": self.monitored_paths,
            "extension_distribution": dict(ext_counts),
            "top_directories": [{"path": path, "count": count} for path, count in top_dirs],
            "monitoring_since": datetime.now()
        }

    def get_recent_files(self, limit: int = 50) -> List[Dict]:
        """
        Get recent file creations

        Args:
            limit: Maximum number of records to return

        Returns:
            List of file creation records
        """
        recent = list(self.creation_history)[-limit:]
        return [r.to_dict() for r in recent]
