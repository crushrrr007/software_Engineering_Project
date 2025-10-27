"""
Alert Manager Module
Manages alerts, notifications, and alert history
"""

import os
import json
import time
import threading
from typing import Dict, List, Callable
from datetime import datetime, timedelta
from collections import deque
from pathlib import Path


class Alert:
    """Represents a security alert"""

    def __init__(self, alert_data: Dict):
        self.timestamp = alert_data.get("timestamp", datetime.now())
        self.type = alert_data.get("type", "unknown")
        self.severity = alert_data.get("severity", "medium")
        self.message = alert_data.get("message", "")
        self.alert_type = alert_data.get("alert_type", "")
        self.mitre_technique = alert_data.get("mitre_technique", "")
        self.data = alert_data
        self.acknowledged = False
        self.id = f"{int(time.time() * 1000000)}"  # Unique ID

    def to_dict(self) -> Dict:
        """Convert to dictionary"""
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat() if isinstance(self.timestamp, datetime) else str(self.timestamp),
            "type": self.type,
            "severity": self.severity,
            "message": self.message,
            "alert_type": self.alert_type,
            "mitre_technique": self.mitre_technique,
            "acknowledged": self.acknowledged,
            "data": self.data
        }

    def acknowledge(self):
        """Mark alert as acknowledged"""
        self.acknowledged = True


class AlertManager:
    """Manages security alerts and notifications"""

    def __init__(self, config: Dict, logger):
        """
        Initialize the alert manager

        Args:
            config: Configuration dictionary
            logger: Logger instance
        """
        self.config = config
        self.logger = logger

        # Alert storage
        self.alerts = deque(maxlen=10000)
        self.alert_callbacks: List[Callable] = []

        # Alert aggregation
        self.aggregation_enabled = config.get("aggregation", {}).get("enabled", True)
        self.aggregation_window = config.get("aggregation", {}).get("window", 60)
        self.max_alerts_per_window = config.get("aggregation", {}).get("max_alerts", 10)
        self.recent_alerts = deque(maxlen=100)

        # Alert statistics
        self.stats = {
            "total_alerts": 0,
            "by_severity": {"low": 0, "medium": 0, "high": 0, "critical": 0},
            "by_type": {},
            "by_mitre_technique": {}
        }

        # Alert persistence
        self.log_directory = config.get("log_directory", "logs")
        self._ensure_log_directory()

        # Alert delivery methods
        self.gui_notification = config.get("methods", {}).get("gui_notification", True)
        self.log_file = config.get("methods", {}).get("log_file", True)
        self.sound_alert = config.get("methods", {}).get("sound_alert", False)

    def _ensure_log_directory(self):
        """Ensure log directory exists"""
        Path(self.log_directory).mkdir(parents=True, exist_ok=True)

    def add_alert(self, alert_data: Dict):
        """
        Add a new alert

        Args:
            alert_data: Alert data dictionary
        """
        # Check if we should aggregate
        if self.aggregation_enabled and self._should_suppress(alert_data):
            self.logger.debug(f"Alert suppressed due to aggregation: {alert_data.get('message', '')}")
            return

        # Create alert object
        alert = Alert(alert_data)

        # Add to storage
        self.alerts.append(alert)
        self.recent_alerts.append(alert)

        # Update statistics
        self._update_stats(alert)

        # Log the alert
        self.logger.warning(f"[ALERT] {alert.severity.upper()} - {alert.message}")

        # Persist to file
        if self.log_file:
            self._save_alert_to_file(alert)

        # Trigger callbacks
        self._trigger_callbacks(alert)

    def _should_suppress(self, alert_data: Dict) -> bool:
        """
        Check if alert should be suppressed due to aggregation

        Args:
            alert_data: Alert data

        Returns:
            bool: True if should be suppressed
        """
        cutoff_time = datetime.now() - timedelta(seconds=self.aggregation_window)

        # Count similar alerts in the time window
        similar_count = 0
        alert_type = alert_data.get("alert_type", "")

        for recent_alert in self.recent_alerts:
            if recent_alert.timestamp > cutoff_time:
                if recent_alert.alert_type == alert_type:
                    similar_count += 1

        return similar_count >= self.max_alerts_per_window

    def _update_stats(self, alert: Alert):
        """
        Update alert statistics

        Args:
            alert: Alert object
        """
        self.stats["total_alerts"] += 1
        self.stats["by_severity"][alert.severity] += 1

        if alert.type not in self.stats["by_type"]:
            self.stats["by_type"][alert.type] = 0
        self.stats["by_type"][alert.type] += 1

        if alert.mitre_technique:
            if alert.mitre_technique not in self.stats["by_mitre_technique"]:
                self.stats["by_mitre_technique"][alert.mitre_technique] = 0
            self.stats["by_mitre_technique"][alert.mitre_technique] += 1

    def _save_alert_to_file(self, alert: Alert):
        """
        Save alert to log file

        Args:
            alert: Alert object
        """
        try:
            date_str = datetime.now().strftime("%Y%m%d")
            log_file = os.path.join(self.log_directory, f"alerts_{date_str}.json")

            # Append to file
            with open(log_file, "a") as f:
                json.dump(alert.to_dict(), f)
                f.write("\n")

        except Exception as e:
            self.logger.error(f"Failed to save alert to file: {e}")

    def _trigger_callbacks(self, alert: Alert):
        """
        Trigger registered callbacks

        Args:
            alert: Alert object
        """
        for callback in self.alert_callbacks:
            try:
                callback(alert)
            except Exception as e:
                self.logger.error(f"Error in alert callback: {e}", exc_info=True)

    def register_callback(self, callback: Callable):
        """
        Register a callback function for alerts

        Args:
            callback: Callback function that receives Alert object
        """
        self.alert_callbacks.append(callback)
        self.logger.info(f"Registered alert callback: {callback.__name__}")

    def get_alerts(self, severity: str = None, limit: int = 100) -> List[Alert]:
        """
        Get alerts with optional filtering

        Args:
            severity: Filter by severity (low, medium, high, critical)
            limit: Maximum number of alerts to return

        Returns:
            List of Alert objects
        """
        alerts = list(self.alerts)

        if severity:
            alerts = [a for a in alerts if a.severity == severity]

        # Sort by timestamp (newest first)
        alerts.sort(key=lambda a: a.timestamp, reverse=True)

        return alerts[:limit]

    def get_recent_alerts(self, minutes: int = 60) -> List[Alert]:
        """
        Get alerts from the last N minutes

        Args:
            minutes: Time window in minutes

        Returns:
            List of Alert objects
        """
        cutoff_time = datetime.now() - timedelta(minutes=minutes)
        return [a for a in self.alerts if a.timestamp > cutoff_time]

    def get_statistics(self) -> Dict:
        """Get alert statistics"""
        return {
            **self.stats,
            "alert_count_last_hour": len(self.get_recent_alerts(60)),
            "alert_count_last_24h": len(self.get_recent_alerts(1440)),
            "recent_critical": len([a for a in self.get_recent_alerts(60) if a.severity == "critical"]),
            "recent_high": len([a for a in self.get_recent_alerts(60) if a.severity == "high"])
        }

    def acknowledge_alert(self, alert_id: str) -> bool:
        """
        Acknowledge an alert

        Args:
            alert_id: Alert ID

        Returns:
            bool: True if successful
        """
        for alert in self.alerts:
            if alert.id == alert_id:
                alert.acknowledge()
                self.logger.info(f"Alert acknowledged: {alert_id}")
                return True
        return False

    def clear_old_alerts(self, days: int = 30):
        """
        Clear alerts older than specified days

        Args:
            days: Number of days to retain
        """
        cutoff_time = datetime.now() - timedelta(days=days)

        before_count = len(self.alerts)

        # Remove old alerts
        self.alerts = deque(
            (a for a in self.alerts if a.timestamp > cutoff_time),
            maxlen=self.alerts.maxlen
        )

        after_count = len(self.alerts)
        removed = before_count - after_count

        if removed > 0:
            self.logger.info(f"Cleared {removed} old alerts (older than {days} days)")

    def export_alerts(self, output_file: str, start_date: datetime = None,
                     end_date: datetime = None) -> bool:
        """
        Export alerts to file

        Args:
            output_file: Output file path
            start_date: Start date filter
            end_date: End date filter

        Returns:
            bool: True if successful
        """
        try:
            alerts = list(self.alerts)

            # Apply date filters
            if start_date:
                alerts = [a for a in alerts if a.timestamp >= start_date]
            if end_date:
                alerts = [a for a in alerts if a.timestamp <= end_date]

            # Export to JSON
            with open(output_file, "w") as f:
                json.dump([a.to_dict() for a in alerts], f, indent=2)

            self.logger.info(f"Exported {len(alerts)} alerts to {output_file}")
            return True

        except Exception as e:
            self.logger.error(f"Failed to export alerts: {e}")
            return False

    def get_alert_by_id(self, alert_id: str) -> Alert:
        """
        Get alert by ID

        Args:
            alert_id: Alert ID

        Returns:
            Alert object or None
        """
        for alert in self.alerts:
            if alert.id == alert_id:
                return alert
        return None
