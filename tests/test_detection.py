"""
Test Suite for MalCapture Defender
Tests detection capabilities with simulated activities
"""

import sys
import os
import time

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from utils.logger import get_logger


def test_api_monitor():
    """Test API monitoring functionality"""
    print("\n" + "="*60)
    print("TEST: API Monitor")
    print("="*60)

    from monitors.api_monitor import APIMonitor, APIHook

    logger = get_logger("test_api_monitor")
    config = {
        "pattern_window": 60,
        "call_threshold": 30
    }

    monitor = APIMonitor(config, logger)
    monitor.start()

    # Simulate API calls
    print("\n[*] Simulating suspicious API calls...")
    hook = APIHook(monitor)
    hook.install_hooks()

    # Simulate rapid BitBlt calls (screenshot activity)
    for i in range(10):
        hook.simulate_api_call("gdi32.dll", "BitBlt", 1234, "suspicious.exe")
        hook.simulate_api_call("user32.dll", "GetDC", 1234, "suspicious.exe")
        time.sleep(0.1)

    print(f"[+] Simulated {20} API calls")

    # Wait for detection
    time.sleep(2)

    # Get statistics
    stats = monitor.get_statistics()
    print(f"\n[*] API Monitor Statistics:")
    print(f"    Total processes monitored: {stats['total_processes_monitored']}")
    print(f"    Total API calls recorded: {stats['total_api_calls_recorded']}")

    monitor.stop()
    print("\n[✓] API Monitor test completed")


def test_file_monitor():
    """Test file system monitoring"""
    print("\n" + "="*60)
    print("TEST: File Monitor")
    print("="*60)

    from monitors.file_monitor import FileMonitor
    import tempfile

    logger = get_logger("test_file_monitor")

    # Use temp directory for testing
    temp_dir = tempfile.gettempdir()

    config = {
        "image_extensions": [".png", ".jpg", ".jpeg"],
        "monitored_paths": [temp_dir],
        "ignore_paths": [],
        "rapid_creation_threshold": 3,
        "rapid_creation_window": 10
    }

    monitor = FileMonitor(config, logger)

    # Register alert callback
    alerts = []
    def alert_callback(alert):
        alerts.append(alert)
        print(f"\n[!] ALERT: {alert['message']}")

    monitor.set_alert_callback(alert_callback)
    monitor.start()

    print(f"\n[*] Monitoring directory: {temp_dir}")
    print("[*] Simulating rapid screenshot creation...")

    # Simulate rapid file creation
    test_files = []
    for i in range(5):
        test_file = os.path.join(temp_dir, f"test_screenshot_{i}.png")
        try:
            with open(test_file, 'wb') as f:
                f.write(b"fake image data")
            test_files.append(test_file)
            print(f"    Created: {test_file}")
            time.sleep(0.5)
        except Exception as e:
            print(f"    Error creating file: {e}")

    # Wait for detection
    time.sleep(3)

    # Cleanup
    for test_file in test_files:
        try:
            if os.path.exists(test_file):
                os.remove(test_file)
        except:
            pass

    monitor.stop()

    print(f"\n[*] File Monitor Statistics:")
    stats = monitor.get_statistics()
    print(f"    Total files tracked: {stats['total_files_tracked']}")
    print(f"    Alerts generated: {len(alerts)}")

    print("\n[✓] File Monitor test completed")


def test_process_monitor():
    """Test process monitoring"""
    print("\n" + "="*60)
    print("TEST: Process Monitor")
    print("="*60)

    from monitors.process_monitor import ProcessMonitor

    logger = get_logger("test_process_monitor")
    config = {
        "suspicious_processes": ["psr.exe", "snippet.exe"],
        "whitelist": ["System", "explorer.exe"],
        "scan_interval": 2
    }

    monitor = ProcessMonitor(config, logger)

    alerts = []
    def alert_callback(alert):
        alerts.append(alert)
        print(f"\n[!] ALERT: {alert['message']}")

    monitor.set_alert_callback(alert_callback)
    monitor.start()

    print("\n[*] Scanning running processes...")
    time.sleep(5)

    stats = monitor.get_statistics()
    suspicious = monitor.get_suspicious_processes()

    print(f"\n[*] Process Monitor Statistics:")
    print(f"    Total processes: {stats['total_processes']}")
    print(f"    Suspicious processes: {stats['suspicious_processes']}")
    print(f"    Alerts generated: {len(alerts)}")

    if suspicious:
        print(f"\n[*] Suspicious processes found:")
        for proc in suspicious[:5]:
            print(f"    - {proc.name} (PID: {proc.pid}, Risk: {proc.risk_score})")

    monitor.stop()
    print("\n[✓] Process Monitor test completed")


def test_mitre_mapper():
    """Test MITRE ATT&CK mapping"""
    print("\n" + "="*60)
    print("TEST: MITRE ATT&CK Mapper")
    print("="*60)

    from utils.mitre_mapper import MITREMapper

    mapper = MITREMapper()

    # Test technique retrieval
    print("\n[*] Testing T1113 (Screen Capture) retrieval...")
    t1113 = mapper.get_technique("T1113")
    print(f"    Technique: {t1113.name}")
    print(f"    Tactic: {t1113.tactic.value}")
    print(f"    Severity: {t1113.severity}")
    print(f"    URL: {t1113.url}")

    # Test detection mapping
    print("\n[*] Testing detection type mapping...")
    techniques = mapper.map_detection("screenshot")
    print(f"    Mapped techniques for 'screenshot': {[t.technique_id for t in techniques]}")

    # Test alert formatting
    print("\n[*] Testing alert formatting with MITRE info...")
    alert = "Suspicious screenshot detected from process: test.exe"
    formatted = mapper.format_alert_with_mitre(alert, "screenshot")
    print(formatted)

    print("\n[✓] MITRE Mapper test completed")


def test_alert_manager():
    """Test alert management"""
    print("\n" + "="*60)
    print("TEST: Alert Manager")
    print("="*60)

    from core.alert_manager import AlertManager
    from datetime import datetime

    logger = get_logger("test_alert_manager")
    config = {
        "aggregation": {
            "enabled": True,
            "window": 60,
            "max_alerts": 10
        },
        "methods": {
            "gui_notification": False,
            "log_file": True,
            "sound_alert": False
        },
        "log_directory": "logs"
    }

    manager = AlertManager(config, logger)

    print("\n[*] Creating test alerts...")

    # Create various alerts
    alerts_data = [
        {
            "type": "process",
            "severity": "high",
            "message": "Suspicious process detected: malware.exe",
            "mitre_technique": "T1113"
        },
        {
            "type": "api_monitor",
            "severity": "medium",
            "message": "Rapid API calls detected",
            "mitre_technique": "T1113"
        },
        {
            "type": "file_monitor",
            "severity": "critical",
            "message": "Rapid screenshot creation detected",
            "mitre_technique": "T1113"
        }
    ]

    for alert_data in alerts_data:
        manager.add_alert(alert_data)
        time.sleep(0.5)

    # Get statistics
    stats = manager.get_statistics()
    print(f"\n[*] Alert Manager Statistics:")
    print(f"    Total alerts: {stats['total_alerts']}")
    print(f"    By severity: {stats['by_severity']}")
    print(f"    Recent (last hour): {stats['alert_count_last_hour']}")

    # Get recent alerts
    recent = manager.get_recent_alerts(60)
    print(f"\n[*] Recent alerts ({len(recent)}):")
    for alert in recent[:3]:
        print(f"    - [{alert.severity}] {alert.message}")

    print("\n[✓] Alert Manager test completed")


def run_all_tests():
    """Run all tests"""
    print("\n" + "="*60)
    print(" MalCapture Defender - Test Suite")
    print("="*60)

    tests = [
        ("MITRE Mapper", test_mitre_mapper),
        ("Alert Manager", test_alert_manager),
        ("API Monitor", test_api_monitor),
        ("Process Monitor", test_process_monitor),
        ("File Monitor", test_file_monitor)
    ]

    passed = 0
    failed = 0

    for name, test_func in tests:
        try:
            test_func()
            passed += 1
        except Exception as e:
            print(f"\n[✗] {name} test FAILED: {e}")
            import traceback
            traceback.print_exc()
            failed += 1

    print("\n" + "="*60)
    print(f" Test Summary: {passed} passed, {failed} failed")
    print("="*60)


if __name__ == "__main__":
    run_all_tests()
