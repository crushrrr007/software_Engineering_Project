"""
MalCapture Defender - Main Application Entry Point
Detection system for malicious screen capture activities
Based on MITRE ATT&CK T1113 - Screen Capture
"""

import sys
import os
import argparse
from pathlib import Path

# Add src directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from utils.logger import get_logger
from core.detection_engine import DetectionEngine


def check_admin_privileges():
    """Check if running with administrator privileges"""
    try:
        if os.name == 'nt':  # Windows
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        else:  # Unix-like
            return os.geteuid() == 0
    except:
        return False


def run_cli_mode(engine, logger):
    """Run in CLI mode without GUI"""
    logger.info("Running in CLI mode (no GUI)")
    logger.info("Press Ctrl+C to stop monitoring...")

    try:
        engine.start()

        # Keep running until interrupted
        import time
        while engine.is_running():
            time.sleep(1)

    except KeyboardInterrupt:
        logger.info("\nShutting down...")
        engine.stop()
        logger.info("MalCapture Defender stopped")


def run_gui_mode(engine, logger):
    """Run in GUI mode with dashboard"""
    logger.info("Starting GUI mode...")

    try:
        from PyQt5.QtWidgets import QApplication
        from gui.dashboard import DashboardWindow

        # Start detection engine
        engine.start()

        # Create Qt application
        app = QApplication(sys.argv)
        app.setApplicationName("MalCapture Defender")

        # Create and show dashboard
        dashboard = DashboardWindow(engine)
        dashboard.show()

        # Run application
        sys.exit(app.exec_())

    except ImportError as e:
        logger.error(f"Failed to import GUI components: {e}")
        logger.error("Please install PyQt5: pip install PyQt5")
        logger.info("Falling back to CLI mode...")
        run_cli_mode(engine, logger)
    except Exception as e:
        logger.error(f"Error in GUI mode: {e}", exc_info=True)
        engine.stop()


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="MalCapture Defender - Malicious Screen Capture Detection System",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Run with GUI (default)
  python main.py

  # Run in CLI mode only
  python main.py --no-gui

  # Use custom config file
  python main.py --config custom_config.yaml

  # Export report and exit
  python main.py --export-report report.json --no-run

For more information, visit: https://github.com/yourusername/Detection-of-Malicious-Screen-Capture
        """
    )

    parser.add_argument(
        '--config',
        default='config.yaml',
        help='Path to configuration file (default: config.yaml)'
    )

    parser.add_argument(
        '--no-gui',
        action='store_true',
        help='Run in CLI mode without GUI'
    )

    parser.add_argument(
        '--export-report',
        metavar='FILE',
        help='Export detection report to file and exit'
    )

    parser.add_argument(
        '--no-run',
        action='store_true',
        help='Do not start monitoring (used with --export-report)'
    )

    parser.add_argument(
        '--version',
        action='version',
        version='MalCapture Defender v1.0.0'
    )

    args = parser.parse_args()

    # Initialize logger
    logger = get_logger("MalCapture", log_dir="logs")

    # Print banner
    print("=" * 80)
    print("  __  __       _  ____            _                  ")
    print(" |  \\/  | __ _| |/ ___|__ _ _ __ | |_ _   _ _ __ ___ ")
    print(" | |\\/| |/ _` | | |   / _` | '_ \\| __| | | | '__/ _ \\")
    print(" | |  | | (_| | | |__| (_| | |_) | |_| |_| | | |  __/")
    print(" |_|  |_|\\__,_|_|\\____\\__,_| .__/ \\__|\\__,_|_|  \\___|")
    print("                           |_|                        ")
    print("                    Defender")
    print()
    print("  Malicious Screen Capture Detection System")
    print("  MITRE ATT&CK T1113 - Screen Capture")
    print("  Version 1.0.0")
    print("=" * 80)
    print()

    # Check for admin privileges
    if not check_admin_privileges():
        logger.warning("⚠ Not running with administrator privileges")
        logger.warning("Some detection features may be limited")
        logger.info("For full functionality, run as Administrator/root")
        print()

    # Check if config file exists
    if not os.path.exists(args.config):
        logger.error(f"Configuration file not found: {args.config}")
        logger.info("Please create a configuration file or use --config to specify a different path")
        return 1

    # Initialize detection engine
    try:
        logger.info(f"Loading configuration from: {args.config}")
        engine = DetectionEngine(args.config, logger)
    except Exception as e:
        logger.error(f"Failed to initialize detection engine: {e}", exc_info=True)
        return 1

    # Handle export report
    if args.export_report:
        logger.info(f"Exporting report to: {args.export_report}")
        if not args.no_run:
            engine.start()
            import time
            logger.info("Collecting data for 30 seconds...")
            time.sleep(30)
            engine.stop()

        if engine.export_report(args.export_report):
            logger.info("✓ Report exported successfully")
            return 0
        else:
            logger.error("✗ Failed to export report")
            return 1

    # Run the application
    try:
        if args.no_gui:
            run_cli_mode(engine, logger)
        else:
            run_gui_mode(engine, logger)

        return 0

    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=True)
        return 1


if __name__ == "__main__":
    sys.exit(main())
