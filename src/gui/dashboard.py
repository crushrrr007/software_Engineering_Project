"""
GUI Dashboard for MalCapture Defender
Provides real-time monitoring and alert visualization
"""

import sys
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout,
                            QHBoxLayout, QLabel, QTableWidget, QTableWidgetItem,
                            QTextEdit, QPushButton, QTabWidget, QGroupBox,
                            QHeaderView, QMessageBox)
from PyQt5.QtCore import QTimer, Qt
from PyQt5.QtGui import QColor, QFont
from datetime import datetime


class DashboardWindow(QMainWindow):
    """Main dashboard window"""

    def __init__(self, detection_engine):
        super().__init__()
        self.detection_engine = detection_engine
        self.alert_manager = detection_engine.get_alert_manager()

        self.init_ui()
        self.setup_timers()

    def init_ui(self):
        """Initialize the UI"""
        self.setWindowTitle("MalCapture Defender - Malicious Screen Capture Detection")
        self.setGeometry(100, 100, 1400, 900)

        # Set dark theme stylesheet
        self.setStyleSheet("""
            QMainWindow {
                background-color: #1e1e1e;
            }
            QWidget {
                background-color: #2d2d2d;
                color: #ffffff;
                font-family: 'Segoe UI', Arial;
                font-size: 10pt;
            }
            QGroupBox {
                border: 2px solid #3d3d3d;
                border-radius: 5px;
                margin-top: 10px;
                padding-top: 10px;
                font-weight: bold;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px;
            }
            QTableWidget {
                gridline-color: #3d3d3d;
                background-color: #252525;
            }
            QTableWidget::item {
                padding: 5px;
            }
            QHeaderView::section {
                background-color: #3d3d3d;
                padding: 5px;
                border: none;
                font-weight: bold;
            }
            QPushButton {
                background-color: #0d47a1;
                border: none;
                padding: 8px 16px;
                border-radius: 4px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #1565c0;
            }
            QPushButton:pressed {
                background-color: #003c8f;
            }
            QTextEdit {
                background-color: #1e1e1e;
                border: 1px solid #3d3d3d;
                border-radius: 4px;
            }
            QTabWidget::pane {
                border: 1px solid #3d3d3d;
                border-radius: 4px;
            }
            QTabBar::tab {
                background-color: #2d2d2d;
                padding: 8px 16px;
                margin-right: 2px;
            }
            QTabBar::tab:selected {
                background-color: #0d47a1;
            }
        """)

        # Create central widget
        central_widget = QWidget()
        self.setCentralWidget(central_widget)

        # Main layout
        main_layout = QVBoxLayout()
        central_widget.setLayout(main_layout)

        # Header
        header = self.create_header()
        main_layout.addWidget(header)

        # Statistics panel
        stats_panel = self.create_stats_panel()
        main_layout.addWidget(stats_panel)

        # Create tabs
        tabs = QTabWidget()

        # Alerts tab
        alerts_tab = self.create_alerts_tab()
        tabs.addTab(alerts_tab, "Alerts")

        # Processes tab
        processes_tab = self.create_processes_tab()
        tabs.addTab(processes_tab, "Processes")

        # Statistics tab
        statistics_tab = self.create_statistics_tab()
        tabs.addTab(statistics_tab, "Statistics")

        main_layout.addWidget(tabs)

        # Status bar
        self.statusBar().showMessage("Ready")

    def create_header(self) -> QWidget:
        """Create header widget"""
        header_widget = QWidget()
        header_layout = QHBoxLayout()
        header_widget.setLayout(header_layout)

        title = QLabel("MalCapture Defender")
        title_font = QFont("Segoe UI", 18, QFont.Bold)
        title.setFont(title_font)
        title.setStyleSheet("color: #2196f3;")

        subtitle = QLabel("MITRE ATT&CK T1113 - Screen Capture Detection")
        subtitle.setStyleSheet("color: #888888;")

        self.status_label = QLabel("● Active")
        self.status_label.setStyleSheet("color: #4caf50; font-weight: bold;")

        header_layout.addWidget(title)
        header_layout.addWidget(subtitle)
        header_layout.addStretch()
        header_layout.addWidget(self.status_label)

        return header_widget

    def create_stats_panel(self) -> QWidget:
        """Create statistics panel"""
        stats_widget = QWidget()
        stats_layout = QHBoxLayout()
        stats_widget.setLayout(stats_layout)

        self.stat_labels = {}

        # Create stat boxes
        stats = [
            ("total_alerts", "Total Alerts", "#2196f3"),
            ("critical", "Critical", "#f44336"),
            ("high", "High", "#ff9800"),
            ("medium", "Medium", "#ffeb3b"),
            ("processes", "Suspicious Processes", "#9c27b0")
        ]

        for key, label, color in stats:
            stat_box = self.create_stat_box(label, "0", color)
            self.stat_labels[key] = stat_box
            stats_layout.addWidget(stat_box)

        return stats_widget

    def create_stat_box(self, label: str, value: str, color: str) -> QGroupBox:
        """Create a statistic box"""
        box = QGroupBox()
        layout = QVBoxLayout()

        value_label = QLabel(value)
        value_label.setAlignment(Qt.AlignCenter)
        value_label.setStyleSheet(f"color: {color}; font-size: 24pt; font-weight: bold;")
        value_label.setObjectName("value")

        text_label = QLabel(label)
        text_label.setAlignment(Qt.AlignCenter)
        text_label.setStyleSheet("color: #aaaaaa;")

        layout.addWidget(value_label)
        layout.addWidget(text_label)
        box.setLayout(layout)

        return box

    def create_alerts_tab(self) -> QWidget:
        """Create alerts tab"""
        tab = QWidget()
        layout = QVBoxLayout()
        tab.setLayout(layout)

        # Controls
        controls = QHBoxLayout()

        refresh_btn = QPushButton("Refresh")
        refresh_btn.clicked.connect(self.refresh_alerts)
        controls.addWidget(refresh_btn)

        clear_btn = QPushButton("Clear Acknowledged")
        clear_btn.clicked.connect(self.clear_acknowledged_alerts)
        controls.addWidget(clear_btn)

        export_btn = QPushButton("Export Report")
        export_btn.clicked.connect(self.export_report)
        controls.addWidget(export_btn)

        controls.addStretch()

        layout.addLayout(controls)

        # Alerts table
        self.alerts_table = QTableWidget()
        self.alerts_table.setColumnCount(5)
        self.alerts_table.setHorizontalHeaderLabels(
            ["Time", "Severity", "Type", "Message", "MITRE Technique"]
        )
        self.alerts_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.alerts_table.setSelectionBehavior(QTableWidget.SelectRows)

        layout.addWidget(self.alerts_table)

        return tab

    def create_processes_tab(self) -> QWidget:
        """Create processes tab"""
        tab = QWidget()
        layout = QVBoxLayout()
        tab.setLayout(layout)

        # Processes table
        self.processes_table = QTableWidget()
        self.processes_table.setColumnCount(5)
        self.processes_table.setHorizontalHeaderLabels(
            ["PID", "Process Name", "Risk Score", "Flags", "Path"]
        )
        self.processes_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)

        layout.addWidget(self.processes_table)

        return tab

    def create_statistics_tab(self) -> QWidget:
        """Create statistics tab"""
        tab = QWidget()
        layout = QVBoxLayout()
        tab.setLayout(layout)

        self.stats_text = QTextEdit()
        self.stats_text.setReadOnly(True)

        layout.addWidget(self.stats_text)

        return tab

    def setup_timers(self):
        """Setup update timers"""
        # Update alerts every 1 second
        self.alert_timer = QTimer()
        self.alert_timer.timeout.connect(self.update_alerts)
        self.alert_timer.start(1000)

        # Update statistics every 2 seconds
        self.stats_timer = QTimer()
        self.stats_timer.timeout.connect(self.update_statistics)
        self.stats_timer.start(2000)

        # Update processes every 5 seconds
        self.process_timer = QTimer()
        self.process_timer.timeout.connect(self.update_processes)
        self.process_timer.start(5000)

    def update_alerts(self):
        """Update alerts table"""
        try:
            alerts = self.alert_manager.get_alerts(limit=100)

            self.alerts_table.setRowCount(len(alerts))

            for i, alert in enumerate(alerts):
                # Time
                time_item = QTableWidgetItem(
                    alert.timestamp.strftime("%H:%M:%S") if isinstance(alert.timestamp, datetime) else str(alert.timestamp)
                )
                self.alerts_table.setItem(i, 0, time_item)

                # Severity
                severity_item = QTableWidgetItem(alert.severity.upper())
                severity_item.setBackground(self.get_severity_color(alert.severity))
                self.alerts_table.setItem(i, 1, severity_item)

                # Type
                type_item = QTableWidgetItem(alert.type)
                self.alerts_table.setItem(i, 2, type_item)

                # Message
                message_item = QTableWidgetItem(alert.message)
                self.alerts_table.setItem(i, 3, message_item)

                # MITRE Technique
                mitre_item = QTableWidgetItem(alert.mitre_technique)
                self.alerts_table.setItem(i, 4, mitre_item)

        except Exception as e:
            print(f"Error updating alerts: {e}")

    def update_processes(self):
        """Update processes table"""
        try:
            process_monitor = self.detection_engine.get_monitor("process")
            if not process_monitor:
                return

            processes = process_monitor.get_suspicious_processes()

            self.processes_table.setRowCount(len(processes))

            for i, proc in enumerate(processes):
                # PID
                pid_item = QTableWidgetItem(str(proc.pid))
                self.processes_table.setItem(i, 0, pid_item)

                # Name
                name_item = QTableWidgetItem(proc.name)
                self.processes_table.setItem(i, 1, name_item)

                # Risk Score
                risk_item = QTableWidgetItem(str(proc.risk_score))
                risk_item.setBackground(self.get_risk_color(proc.risk_score))
                self.processes_table.setItem(i, 2, risk_item)

                # Flags
                flags_item = QTableWidgetItem(", ".join(proc.flags))
                self.processes_table.setItem(i, 3, flags_item)

                # Path
                path_item = QTableWidgetItem(proc.exe)
                self.processes_table.setItem(i, 4, path_item)

        except Exception as e:
            print(f"Error updating processes: {e}")

    def update_statistics(self):
        """Update statistics"""
        try:
            stats = self.detection_engine.get_statistics()

            # Update stat boxes
            alert_stats = stats.get("alerts", {})

            total_alerts = alert_stats.get("total_alerts", 0)
            self.update_stat_box("total_alerts", str(total_alerts))

            severity_stats = alert_stats.get("by_severity", {})
            self.update_stat_box("critical", str(severity_stats.get("critical", 0)))
            self.update_stat_box("high", str(severity_stats.get("high", 0)))
            self.update_stat_box("medium", str(severity_stats.get("medium", 0)))

            process_stats = stats.get("monitors", {}).get("process", {})
            suspicious = process_stats.get("suspicious_processes", 0)
            self.update_stat_box("processes", str(suspicious))

            # Update detailed statistics text
            import json
            from datetime import datetime
            def json_serial(obj):
                """JSON serializer for objects not serializable by default"""
                if isinstance(obj, datetime):
                    return obj.isoformat()
                return str(obj)

            self.stats_text.setPlainText(json.dumps(stats, indent=2, default=json_serial))    
            # Update status
            uptime = stats.get("engine", {}).get("uptime_formatted", "0s")
            self.statusBar().showMessage(f"Monitoring active | Uptime: {uptime}")

        except Exception as e:
            print(f"Error updating statistics: {e}")
            import traceback
            traceback.print_exc()

    def update_stat_box(self, key: str, value: str):
        """Update a stat box value"""
        if key in self.stat_labels:
            box = self.stat_labels[key]
            value_label = box.findChild(QLabel, "value")
            if value_label:
                value_label.setText(value)

    def get_severity_color(self, severity: str) -> QColor:
        """Get color for severity level"""
        colors = {
            "critical": QColor(244, 67, 54, 100),
            "high": QColor(255, 152, 0, 100),
            "medium": QColor(255, 235, 59, 100),
            "low": QColor(76, 175, 80, 100)
        }
        return colors.get(severity, QColor(128, 128, 128, 100))

    def get_risk_color(self, risk_score: int) -> QColor:
        """Get color for risk score"""
        if risk_score >= 9:
            return QColor(244, 67, 54, 100)
        elif risk_score >= 7:
            return QColor(255, 152, 0, 100)
        elif risk_score >= 4:
            return QColor(255, 235, 59, 100)
        else:
            return QColor(76, 175, 80, 100)

    def refresh_alerts(self):
        """Refresh alerts display"""
        self.update_alerts()
        QMessageBox.information(self, "Refresh", "Alerts refreshed")

    def clear_acknowledged_alerts(self):
        """Clear acknowledged alerts"""
        # TODO: Implement
        QMessageBox.information(self, "Clear", "Acknowledged alerts cleared")

    def export_report(self):
        """Export detection report"""
        from datetime import datetime
        filename = f"malcapture_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"

        if self.detection_engine.export_report(filename):
            QMessageBox.information(self, "Export", f"Report exported to {filename}")
        else:
            QMessageBox.warning(self, "Export", "Failed to export report")

    def closeEvent(self, event):
        """Handle window close event"""
        reply = QMessageBox.question(
            self, 'Exit',
            "Are you sure you want to stop monitoring and exit?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )

        if reply == QMessageBox.Yes:
            self.detection_engine.stop()
            event.accept()
        else:
            event.ignore()
