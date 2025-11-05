"""
Test script to verify alerts are loaded from disk
"""

import sys
import os
import logging
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from core.alert_manager import AlertManager

def main():
    """Test alert loading from disk"""
    print("=" * 80)
    print("Testing Alert Loading from Disk")
    print("=" * 80)
    print()

    # Initialize simple logger
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger("AlertLoadTest")

    # Initialize alert manager with minimal config
    config = {
        "log_directory": "logs",
        "methods": {
            "gui_notification": False,
            "log_file": True,
            "sound_alert": False,
            "desktop_notification": False
        },
        "aggregation": {
            "enabled": False
        }
    }

    print("Initializing AlertManager (should load alerts from disk)...")
    alert_manager = AlertManager(config, logger)

    print()
    print("=" * 80)

    # Retrieve and display alerts
    alerts = alert_manager.get_alerts(limit=100)
    print(f"✓ Total alerts loaded: {len(alerts)}")
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
    else:
        print("⚠ No alerts found!")
        print()
        print("To create test alerts, run: python test_alerts.py")

    print()
    print("=" * 80)
    print("✓ Alert loading test complete!")
    print()
    print("Now the GUI should show these alerts in the Alert tab.")
    print("=" * 80)

if __name__ == "__main__":
    main()
