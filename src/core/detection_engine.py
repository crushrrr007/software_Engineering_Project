"""
Detection Engine Module
Main orchestrator for all detection modules
"""

import yaml
import time
import threading
from typing import Dict
from datetime import datetime

from src.core.alert_manager import AlertManager
from src.monitors.process_monitor import ProcessMonitor
from src.monitors.api_monitor import APIMonitor
from src.monitors.file_monitor import FileMonitor
from src.monitors.network_monitor import NetworkMonitor
from src.utils.mitre_mapper import MITREMapper


class DetectionEngine:
    """Main detection engine that coordinates all monitors"""

    def __init__(self, config_path: str, logger):
        """
        Initialize the detection engine

        Args:
            config_path: Path to configuration file
            logger: Logger instance
        """
        self.logger = logger
        self.config = self._load_config(config_path)
        self.running = False

        # Initialize MITRE mapper
        self.mitre_mapper = MITREMapper()

        # Initialize alert manager
        alert_config = self.config.get("alerts", {})
        alert_config["log_directory"] = self.config.get("logging", {}).get("log_directory", "logs")
        self.alert_manager = AlertManager(alert_config, logger)

        # Initialize monitors
        self.monitors = {}
        self._initialize_monitors()

        # Statistics
        self.start_time = None
        self.stats = {
            "total_detections": 0,
            "by_severity": {"low": 0, "medium": 0, "high": 0, "critical": 0},
            "by_type": {}
        }

    def _load_config(self, config_path: str) -> Dict:
        """
        Load configuration from YAML file

        Args:
            config_path: Path to config file

        Returns:
            Configuration dictionary
        """
        try:
            with open(config_path, 'r') as f:
                config = yaml.safe_load(f)
            self.logger.info(f"Configuration loaded from {config_path}")
            return config
        except Exception as e:
            self.logger.error(f"Failed to load configuration: {e}")
            return {}

    def _initialize_monitors(self):
        """Initialize all detection monitors"""
        # Process Monitor
        if self.config.get("process_monitor", {}).get("enabled", True):
            self.monitors["process"] = ProcessMonitor(
                self.config.get("process_monitor", {}),
                self.logger
            )
            self.monitors["process"].set_alert_callback(self._handle_alert)
            self.logger.info("Process monitor initialized")

        # API Monitor
        if self.config.get("api_monitor", {}).get("enabled", True):
            self.monitors["api"] = APIMonitor(
                self.config.get("api_monitor", {}),
                self.logger
            )
            self.monitors["api"].set_alert_callback(self._handle_alert)
            self.logger.info("API monitor initialized")

        # File Monitor
        if self.config.get("file_monitor", {}).get("enabled", True):
            self.monitors["file"] = FileMonitor(
                self.config.get("file_monitor", {}),
                self.logger
            )
            self.monitors["file"].set_alert_callback(self._handle_alert)
            self.logger.info("File monitor initialized")

        # Network Monitor
        if self.config.get("network_monitor", {}).get("enabled", True):
            self.monitors["network"] = NetworkMonitor(
                self.config.get("network_monitor", {}),
                self.logger
            )
            self.monitors["network"].set_alert_callback(self._handle_alert)
            self.logger.info("Network monitor initialized")

    def start(self):
        """Start the detection engine"""
        if self.running:
            self.logger.warning("Detection engine already running")
            return

        self.running = True
        self.start_time = datetime.now()

        self.logger.info("=" * 80)
        self.logger.info("Starting MalCapture Defender - Detection Engine")
        self.logger.info("=" * 80)

        # Start all monitors
        for name, monitor in self.monitors.items():
            try:
                monitor.start()
                self.logger.info(f"✓ {name.capitalize()} monitor started")
            except Exception as e:
                self.logger.error(f"✗ Failed to start {name} monitor: {e}")

        self.logger.info("=" * 80)
        self.logger.info("Detection engine started successfully")
        self.logger.info(f"Monitoring {len(self.monitors)} detection modules")
        self.logger.info("=" * 80)

    def stop(self):
        """Stop the detection engine"""
        if not self.running:
            return

        self.logger.info("Stopping detection engine...")

        # Stop all monitors
        for name, monitor in self.monitors.items():
            try:
                monitor.stop()
                self.logger.info(f"✓ {name.capitalize()} monitor stopped")
            except Exception as e:
                self.logger.error(f"✗ Error stopping {name} monitor: {e}")

        self.running = False
        self.logger.info("Detection engine stopped")

    def _handle_alert(self, alert_data: Dict):
        """
        Handle alert from any monitor

        Args:
            alert_data: Alert data dictionary
        """
        # Enrich alert with MITRE ATT&CK information
        if "mitre_technique" in alert_data:
            technique = self.mitre_mapper.get_technique(alert_data["mitre_technique"])
            if technique:
                alert_data["mitre_info"] = technique.to_dict()

        # Update statistics
        self.stats["total_detections"] += 1
        severity = alert_data.get("severity", "medium")
        self.stats["by_severity"][severity] += 1

        alert_type = alert_data.get("type", "unknown")
        if alert_type not in self.stats["by_type"]:
            self.stats["by_type"][alert_type] = 0
        self.stats["by_type"][alert_type] += 1

        # Pass to alert manager
        self.alert_manager.add_alert(alert_data)

    def get_statistics(self) -> Dict:
        """Get comprehensive statistics from all components"""
        uptime = (datetime.now() - self.start_time).total_seconds() if self.start_time else 0

        stats = {
            "engine": {
                "running": self.running,
                "uptime_seconds": uptime,
                "uptime_formatted": self._format_uptime(uptime),
                "start_time": self.start_time.isoformat() if self.start_time else None,
                "active_monitors": len([m for m in self.monitors.values()]),
                **self.stats
            },
            "alerts": self.alert_manager.get_statistics(),
            "monitors": {}
        }

        # Get statistics from each monitor
        for name, monitor in self.monitors.items():
            try:
                stats["monitors"][name] = monitor.get_statistics()
            except Exception as e:
                self.logger.error(f"Error getting stats from {name} monitor: {e}")

        return stats

    def _format_uptime(self, seconds: float) -> str:
        """
        Format uptime in human-readable format

        Args:
            seconds: Uptime in seconds

        Returns:
            Formatted string
        """
        days = int(seconds // 86400)
        hours = int((seconds % 86400) // 3600)
        minutes = int((seconds % 3600) // 60)
        secs = int(seconds % 60)

        parts = []
        if days > 0:
            parts.append(f"{days}d")
        if hours > 0:
            parts.append(f"{hours}h")
        if minutes > 0:
            parts.append(f"{minutes}m")
        parts.append(f"{secs}s")

        return " ".join(parts)

    def get_monitor(self, name: str):
        """
        Get a specific monitor

        Args:
            name: Monitor name (process, api, file, network)

        Returns:
            Monitor instance or None
        """
        return self.monitors.get(name)

    def get_alert_manager(self) -> AlertManager:
        """Get the alert manager instance"""
        return self.alert_manager

    def is_running(self) -> bool:
        """Check if detection engine is running"""
        return self.running

    def reload_config(self, config_path: str):
        """
        Reload configuration (requires restart)

        Args:
            config_path: Path to config file
        """
        self.logger.info("Reloading configuration...")
        self.config = self._load_config(config_path)
        self.logger.info("Configuration reloaded (restart required for changes to take effect)")

    def get_recent_detections(self, limit: int = 50) -> list:
        """
        Get recent detections

        Args:
            limit: Maximum number of detections to return

        Returns:
            List of recent alerts
        """
        return [a.to_dict() for a in self.alert_manager.get_alerts(limit=limit)]

    def export_report(self, output_file: str) -> bool:
        """
        Export comprehensive detection report

        Args:
            output_file: Output file path

        Returns:
            bool: True if successful
        """
        try:
            import json

            report = {
                "generated_at": datetime.now().isoformat(),
                "report_type": "MalCapture Defender Detection Report",
                "statistics": self.get_statistics(),
                "recent_alerts": self.get_recent_detections(100),
                "mitre_techniques": [t.to_dict() for t in self.mitre_mapper.get_all_techniques()]
            }

            with open(output_file, 'w') as f:
                json.dump(report, f, indent=2)

            self.logger.info(f"Report exported to {output_file}")
            return True

        except Exception as e:
            self.logger.error(f"Failed to export report: {e}")
            return False
