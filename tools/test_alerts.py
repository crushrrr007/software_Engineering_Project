"""
Test script to manually generate alerts
Run this to test if the alert system is working
"""

import sys
import os
import logging
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from datetime import datetime
from core.alert_manager import AlertManager

def main():
    """Generate test alerts"""
    print("=" * 80)
    print("MalCapture Defender - Alert Test Script")
    print("=" * 80)
    print()

    # Initialize simple logger
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger("AlertTest")

    # Initialize alert manager with minimal config
    config = {
        "log_directory": "logs",
        "methods": {
            "gui_notification": True,
            "log_file": True,
            "sound_alert": False,
            "desktop_notification": True
        },
        "aggregation": {
            "enabled": False  # Disable aggregation for testing
        }
    }

    alert_manager = AlertManager(config, logger)

    print("Creating test alerts...")
    print()

    # Test Alert 1 - Critical
    alert1 = {
        "timestamp": datetime.now(),
        "type": "process",
        "severity": "critical",
        "message": "TEST ALERT: Critical - Screenshot utility detected",
        "alert_type": "screenshot_tool",
        "mitre_technique": "T1113"
    }
    alert_manager.add_alert(alert1)
    print("✓ Created CRITICAL alert")

    # Test Alert 2 - High
    alert2 = {
        "timestamp": datetime.now(),
        "type": "process",
        "severity": "high",
        "message": "TEST ALERT: High - Suspicious process behavior",
        "alert_type": "suspicious_behavior",
        "mitre_technique": "T1113"
    }
    alert_manager.add_alert(alert2)
    print("✓ Created HIGH alert")

    # Test Alert 3 - Medium
    alert3 = {
        "timestamp": datetime.now(),
        "type": "file",
        "severity": "medium",
        "message": "TEST ALERT: Medium - Rapid file creation detected",
        "alert_type": "file_activity",
        "mitre_technique": "T1113"
    }
    alert_manager.add_alert(alert3)
    print("✓ Created MEDIUM alert")

    # Test Alert 4 - Low
    alert4 = {
        "timestamp": datetime.now(),
        "type": "network",
        "severity": "low",
        "message": "TEST ALERT: Low - Network activity detected",
        "alert_type": "network_activity",
        "mitre_technique": "T1113"
    }
    alert_manager.add_alert(alert4)
    print("✓ Created LOW alert")

    print()
    print("=" * 80)
    print("Test alerts created successfully!")
    print()

    # Retrieve and display alerts
    alerts = alert_manager.get_alerts(limit=100)
    print(f"Total alerts in manager: {len(alerts)}")
    print()

    if alerts:
        print("Alert details:")
        print("-" * 80)
        for i, alert in enumerate(alerts[:10], 1):
            print(f"{i}. [{alert.severity.upper()}] {alert.message}")
            print(f"   Type: {alert.type} | Time: {alert.timestamp}")
            print(f"   MITRE: {alert.mitre_technique}")
            print()

    # Show statistics
    stats = alert_manager.get_statistics()
    print("Alert Statistics:")
    print("-" * 80)
    print(f"Total: {stats['total_alerts']}")
    print(f"By Severity: {stats['by_severity']}")
    print()

    print("=" * 80)
    print("Now run the GUI to see if these alerts appear in the alert tab!")
    print("Command: cd src && python main.py")
    print("=" * 80)

if __name__ == "__main__":
    main()
