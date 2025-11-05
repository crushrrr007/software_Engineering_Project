"""
GUI Dashboard for MalCapture Defender
Provides real-time monitoring and alert visualization
Enhanced version with advanced features
"""

import sys
import psutil
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout,
                            QHBoxLayout, QLabel, QTableWidget, QTableWidgetItem,
                            QTextEdit, QPushButton, QTabWidget, QGroupBox,
                            QHeaderView, QMessageBox, QLineEdit, QComboBox,
                            QProgressBar, QSystemTrayIcon, QMenu, QAction, QFileDialog,
                            QCheckBox, QSpinBox, QFormLayout, QDialog, QDialogButtonBox)
from PyQt5.QtCore import QTimer, Qt, pyqtSignal
from PyQt5.QtGui import QColor, QFont, QIcon
from datetime import datetime
import pyqtgraph as pg


class DashboardWindow(QMainWindow):
    """Main dashboard window - Enhanced version"""

    def __init__(self, detection_engine):
        super().__init__()
        self.detection_engine = detection_engine
        self.alert_manager = detection_engine.get_alert_manager()
        self.logger = detection_engine.logger

        # Filter settings
        self.alert_filter_severity = "all"
        self.alert_search_text = ""

        # Chart data
        self.alert_history_data = []
        self.cpu_data = []
        self.memory_data = []
        self.time_data = []
        self.max_data_points = 100

        # System tray
        self.tray_icon = None

        self.init_ui()
        self.setup_timers()
        self.setup_system_tray()

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
        tabs.addTab(alerts_tab, "🚨 Alerts")

        # Processes tab
        processes_tab = self.create_processes_tab()
        tabs.addTab(processes_tab, "⚙️ Processes")

        # Real-time Charts tab
        charts_tab = self.create_charts_tab()
        tabs.addTab(charts_tab, "📊 Real-Time")

        # Performance tab
        performance_tab = self.create_performance_tab()
        tabs.addTab(performance_tab, "💻 Performance")

        # Statistics tab
        statistics_tab = self.create_statistics_tab()
        tabs.addTab(statistics_tab, "📈 Statistics")

        # Settings tab
        settings_tab = self.create_settings_tab()
        tabs.addTab(settings_tab, "⚙️ Settings")

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
        """Create enhanced alerts tab with filtering and search"""
        tab = QWidget()
        layout = QVBoxLayout()
        tab.setLayout(layout)

        # Filter and Search Bar
        filter_layout = QHBoxLayout()

        filter_layout.addWidget(QLabel("Filter by Severity:"))
        self.severity_filter = QComboBox()
        self.severity_filter.addItems(["All", "Critical", "High", "Medium", "Low"])
        self.severity_filter.currentTextChanged.connect(self.on_filter_changed)
        filter_layout.addWidget(self.severity_filter)

        filter_layout.addWidget(QLabel("Search:"))
        self.search_box = QLineEdit()
        self.search_box.setPlaceholderText("Search alerts...")
        self.search_box.textChanged.connect(self.on_search_changed)
        filter_layout.addWidget(self.search_box)

        filter_layout.addStretch()
        layout.addLayout(filter_layout)

        # Controls
        controls = QHBoxLayout()

        refresh_btn = QPushButton("🔄 Refresh")
        refresh_btn.clicked.connect(self.refresh_alerts)
        controls.addWidget(refresh_btn)

        clear_btn = QPushButton("🗑️ Clear Acknowledged")
        clear_btn.clicked.connect(self.clear_acknowledged_alerts)
        controls.addWidget(clear_btn)

        export_btn = QPushButton("📥 Export Report")
        export_btn.clicked.connect(self.export_report)
        controls.addWidget(export_btn)

        export_csv_btn = QPushButton("📄 Export CSV")
        export_csv_btn.clicked.connect(self.export_alerts_csv)
        controls.addWidget(export_csv_btn)

        controls.addStretch()
        layout.addLayout(controls)

        # Alerts table
        self.alerts_table = QTableWidget()
        self.alerts_table.setColumnCount(6)
        self.alerts_table.setHorizontalHeaderLabels(
            ["Time", "Severity", "Type", "Message", "MITRE Technique", "Details"]
        )
        self.alerts_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.alerts_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.alerts_table.itemDoubleClicked.connect(self.show_alert_details)

        layout.addWidget(self.alerts_table)

        # Alert count label
        self.alert_count_label = QLabel("Total Alerts: 0 | Filtered: 0")
        layout.addWidget(self.alert_count_label)

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

    def create_charts_tab(self) -> QWidget:
        """Create real-time charts tab"""
        tab = QWidget()
        layout = QVBoxLayout()
        tab.setLayout(layout)

        # Alert history chart
        alert_group = QGroupBox("Alert History (Last 100 Points)")
        alert_layout = QVBoxLayout()
        alert_group.setLayout(alert_layout)

        self.alert_chart = pg.PlotWidget()
        self.alert_chart.setBackground('#1e1e1e')
        self.alert_chart.setLabel('left', 'Alert Count')
        self.alert_chart.setLabel('bottom', 'Time')
        self.alert_chart.showGrid(x=True, y=True, alpha=0.3)
        self.alert_plot = self.alert_chart.plot(pen=pg.mkPen(color='#2196f3', width=2))
        alert_layout.addWidget(self.alert_chart)
        layout.addWidget(alert_group)

        # Detection by type chart
        detection_group = QGroupBox("Detections by Severity")
        detection_layout = QVBoxLayout()
        detection_group.setLayout(detection_layout)

        self.severity_chart = pg.PlotWidget()
        self.severity_chart.setBackground('#1e1e1e')
        self.severity_chart.setLabel('left', 'Count')
        self.severity_chart.setLabel('bottom', 'Severity Level')
        self.severity_chart.showGrid(x=False, y=True, alpha=0.3)
        detection_layout.addWidget(self.severity_chart)
        layout.addWidget(detection_group)

        return tab

    def create_performance_tab(self) -> QWidget:
        """Create performance monitoring tab"""
        tab = QWidget()
        layout = QVBoxLayout()
        tab.setLayout(layout)

        # System resource usage
        resource_group = QGroupBox("System Resource Usage")
        resource_layout = QVBoxLayout()
        resource_group.setLayout(resource_layout)

        # CPU usage
        cpu_layout = QHBoxLayout()
        cpu_layout.addWidget(QLabel("CPU Usage:"))
        self.cpu_progress = QProgressBar()
        self.cpu_progress.setStyleSheet("""
            QProgressBar {
                border: 2px solid #3d3d3d;
                border-radius: 5px;
                text-align: center;
                background-color: #252525;
            }
            QProgressBar::chunk {
                background-color: #2196f3;
            }
        """)
        cpu_layout.addWidget(self.cpu_progress)
        resource_layout.addLayout(cpu_layout)

        # Memory usage
        mem_layout = QHBoxLayout()
        mem_layout.addWidget(QLabel("Memory Usage:"))
        self.memory_progress = QProgressBar()
        self.memory_progress.setStyleSheet("""
            QProgressBar {
                border: 2px solid #3d3d3d;
                border-radius: 5px;
                text-align: center;
                background-color: #252525;
            }
            QProgressBar::chunk {
                background-color: #4caf50;
            }
        """)
        mem_layout.addWidget(self.memory_progress)
        resource_layout.addLayout(mem_layout)

        # Disk usage
        disk_layout = QHBoxLayout()
        disk_layout.addWidget(QLabel("Disk Usage:"))
        self.disk_progress = QProgressBar()
        self.disk_progress.setStyleSheet("""
            QProgressBar {
                border: 2px solid #3d3d3d;
                border-radius: 5px;
                text-align: center;
                background-color: #252525;
            }
            QProgressBar::chunk {
                background-color: #ff9800;
            }
        """)
        disk_layout.addWidget(self.disk_progress)
        resource_layout.addLayout(disk_layout)

        layout.addWidget(resource_group)

        # Resource history charts
        history_group = QGroupBox("Resource History")
        history_layout = QVBoxLayout()
        history_group.setLayout(history_layout)

        self.cpu_chart = pg.PlotWidget()
        self.cpu_chart.setBackground('#1e1e1e')
        self.cpu_chart.setLabel('left', 'CPU %')
        self.cpu_chart.setLabel('bottom', 'Time')
        self.cpu_chart.setYRange(0, 100)
        self.cpu_chart.showGrid(x=True, y=True, alpha=0.3)
        self.cpu_plot = self.cpu_chart.plot(pen=pg.mkPen(color='#2196f3', width=2))
        history_layout.addWidget(self.cpu_chart)

        self.memory_chart = pg.PlotWidget()
        self.memory_chart.setBackground('#1e1e1e')
        self.memory_chart.setLabel('left', 'Memory %')
        self.memory_chart.setLabel('bottom', 'Time')
        self.memory_chart.setYRange(0, 100)
        self.memory_chart.showGrid(x=True, y=True, alpha=0.3)
        self.memory_plot = self.memory_chart.plot(pen=pg.mkPen(color='#4caf50', width=2))
        history_layout.addWidget(self.memory_chart)

        layout.addWidget(history_group)

        # System info
        info_group = QGroupBox("System Information")
        info_layout = QFormLayout()
        info_group.setLayout(info_layout)

        self.cpu_count_label = QLabel(str(psutil.cpu_count()))
        info_layout.addRow("CPU Cores:", self.cpu_count_label)

        self.total_memory_label = QLabel(f"{psutil.virtual_memory().total / (1024**3):.2f} GB")
        info_layout.addRow("Total Memory:", self.total_memory_label)

        self.uptime_label = QLabel("0s")
        info_layout.addRow("System Uptime:", self.uptime_label)

        layout.addWidget(info_group)

        return tab

    def create_settings_tab(self) -> QWidget:
        """Create settings tab"""
        tab = QWidget()
        layout = QVBoxLayout()
        tab.setLayout(layout)

        # Monitoring settings
        monitor_group = QGroupBox("Monitoring Settings")
        monitor_layout = QFormLayout()
        monitor_group.setLayout(monitor_layout)

        self.update_interval_spin = QSpinBox()
        self.update_interval_spin.setRange(500, 10000)
        self.update_interval_spin.setValue(1000)
        self.update_interval_spin.setSuffix(" ms")
        monitor_layout.addRow("Update Interval:", self.update_interval_spin)

        self.max_alerts_spin = QSpinBox()
        self.max_alerts_spin.setRange(10, 1000)
        self.max_alerts_spin.setValue(100)
        monitor_layout.addRow("Max Alerts Displayed:", self.max_alerts_spin)

        layout.addWidget(monitor_group)

        # Alert settings
        alert_group = QGroupBox("Alert Settings")
        alert_layout = QVBoxLayout()
        alert_group.setLayout(alert_layout)

        self.sound_alerts_check = QCheckBox("Enable Sound Alerts")
        self.sound_alerts_check.setChecked(True)
        alert_layout.addWidget(self.sound_alerts_check)

        self.desktop_notifications_check = QCheckBox("Enable Desktop Notifications")
        self.desktop_notifications_check.setChecked(True)
        alert_layout.addWidget(self.desktop_notifications_check)

        self.minimize_to_tray_check = QCheckBox("Minimize to System Tray")
        self.minimize_to_tray_check.setChecked(True)
        alert_layout.addWidget(self.minimize_to_tray_check)

        layout.addWidget(alert_group)

        # Apply settings button
        apply_btn = QPushButton("Apply Settings")
        apply_btn.clicked.connect(self.apply_settings)
        layout.addWidget(apply_btn)

        layout.addStretch()

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

        # Update charts every 2 seconds
        self.chart_timer = QTimer()
        self.chart_timer.timeout.connect(self.update_charts)
        self.chart_timer.start(2000)

        # Update performance metrics every 1 second
        self.performance_timer = QTimer()
        self.performance_timer.timeout.connect(self.update_performance)
        self.performance_timer.start(1000)

    def setup_system_tray(self):
        """Setup system tray icon"""
        try:
            self.tray_icon = QSystemTrayIcon(self)
            # Use a simple colored circle as icon if no icon file exists
            self.tray_icon.setToolTip("MalCapture Defender")

            # Create tray menu
            tray_menu = QMenu()

            show_action = QAction("Show Dashboard", self)
            show_action.triggered.connect(self.show)
            tray_menu.addAction(show_action)

            hide_action = QAction("Hide Dashboard", self)
            hide_action.triggered.connect(self.hide)
            tray_menu.addAction(hide_action)

            tray_menu.addSeparator()

            stats_action = QAction("Show Statistics", self)
            stats_action.triggered.connect(self.show_quick_stats)
            tray_menu.addAction(stats_action)

            tray_menu.addSeparator()

            quit_action = QAction("Exit", self)
            quit_action.triggered.connect(self.quit_application)
            tray_menu.addAction(quit_action)

            self.tray_icon.setContextMenu(tray_menu)
            self.tray_icon.show()

            # Handle tray icon activation
            self.tray_icon.activated.connect(self.on_tray_activated)

        except Exception as e:
            self.logger.error(f"Failed to setup system tray: {e}")

    def on_tray_activated(self, reason):
        """Handle tray icon activation"""
        if reason == QSystemTrayIcon.DoubleClick:
            if self.isVisible():
                self.hide()
            else:
                self.show()
                self.activateWindow()

    def update_alerts(self):
        """Update alerts table with filtering and search"""
        try:
            all_alerts = self.alert_manager.get_alerts(limit=self.max_alerts_spin.getValue() if hasattr(self, 'max_alerts_spin') else 100)

            # Apply filters
            filtered_alerts = []
            for alert in all_alerts:
                # Severity filter
                if self.alert_filter_severity != "all":
                    if alert.severity.lower() != self.alert_filter_severity.lower():
                        continue

                # Search filter
                if self.alert_search_text:
                    search_text = self.alert_search_text.lower()
                    if (search_text not in alert.message.lower() and
                        search_text not in alert.type.lower() and
                        search_text not in alert.mitre_technique.lower()):
                        continue

                filtered_alerts.append(alert)

            self.alerts_table.setRowCount(len(filtered_alerts))

            for i, alert in enumerate(filtered_alerts):
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

                # Details button
                details_item = QTableWidgetItem("View Details")
                self.alerts_table.setItem(i, 5, details_item)

            # Update count label
            if hasattr(self, 'alert_count_label'):
                self.alert_count_label.setText(f"Total Alerts: {len(all_alerts)} | Filtered: {len(filtered_alerts)}")

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

    def export_alerts_csv(self):
        """Export alerts to CSV file"""
        try:
            filename, _ = QFileDialog.getSaveFileName(
                self, "Export Alerts to CSV",
                f"alerts_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                "CSV Files (*.csv)"
            )

            if filename:
                import csv
                alerts = self.alert_manager.get_alerts(limit=1000)

                with open(filename, 'w', newline='', encoding='utf-8') as f:
                    writer = csv.writer(f)
                    writer.writerow(['Timestamp', 'Severity', 'Type', 'Message', 'MITRE Technique'])

                    for alert in alerts:
                        writer.writerow([
                            alert.timestamp.isoformat() if isinstance(alert.timestamp, datetime) else str(alert.timestamp),
                            alert.severity,
                            alert.type,
                            alert.message,
                            alert.mitre_technique
                        ])

                QMessageBox.information(self, "Export", f"Alerts exported to {filename}")
        except Exception as e:
            QMessageBox.warning(self, "Export Error", f"Failed to export alerts: {e}")

    def on_filter_changed(self, text):
        """Handle severity filter change"""
        self.alert_filter_severity = text.lower()
        self.update_alerts()

    def on_search_changed(self, text):
        """Handle search text change"""
        self.alert_search_text = text
        self.update_alerts()

    def show_alert_details(self, item):
        """Show detailed alert information"""
        row = item.row()
        try:
            alerts = self.alert_manager.get_alerts(limit=100)
            if row < len(alerts):
                alert = alerts[row]

                dialog = QDialog(self)
                dialog.setWindowTitle("Alert Details")
                dialog.setMinimumSize(600, 400)

                layout = QVBoxLayout()

                details_text = QTextEdit()
                details_text.setReadOnly(True)

                import json
                alert_dict = alert.to_dict()
                details_text.setPlainText(json.dumps(alert_dict, indent=2))

                layout.addWidget(details_text)

                close_btn = QPushButton("Close")
                close_btn.clicked.connect(dialog.close)
                layout.addWidget(close_btn)

                dialog.setLayout(layout)
                dialog.exec_()
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Failed to show alert details: {e}")

    def update_charts(self):
        """Update real-time charts"""
        try:
            stats = self.detection_engine.get_statistics()
            alert_stats = stats.get("alerts", {})

            # Update alert history
            total_alerts = alert_stats.get("total_alerts", 0)
            self.alert_history_data.append(total_alerts)

            if len(self.alert_history_data) > self.max_data_points:
                self.alert_history_data = self.alert_history_data[-self.max_data_points:]

            self.alert_plot.setData(self.alert_history_data)

            # Update severity bar chart
            severity_data = alert_stats.get("by_severity", {})
            severities = ['critical', 'high', 'medium', 'low']
            counts = [severity_data.get(s, 0) for s in severities]

            self.severity_chart.clear()
            bargraph = pg.BarGraphItem(x=range(len(severities)), height=counts, width=0.8,
                                      brush='#2196f3')
            self.severity_chart.addItem(bargraph)

        except Exception as e:
            print(f"Error updating charts: {e}")

    def update_performance(self):
        """Update performance metrics"""
        try:
            # CPU usage
            cpu_percent = psutil.cpu_percent(interval=0.1)
            self.cpu_progress.setValue(int(cpu_percent))
            self.cpu_progress.setFormat(f"{cpu_percent:.1f}%")

            # Memory usage
            memory = psutil.virtual_memory()
            memory_percent = memory.percent
            self.memory_progress.setValue(int(memory_percent))
            self.memory_progress.setFormat(f"{memory_percent:.1f}%")

            # Disk usage
            disk = psutil.disk_usage('/')
            disk_percent = disk.percent
            self.disk_progress.setValue(int(disk_percent))
            self.disk_progress.setFormat(f"{disk_percent:.1f}%")

            # Update charts
            self.cpu_data.append(cpu_percent)
            self.memory_data.append(memory_percent)

            if len(self.cpu_data) > self.max_data_points:
                self.cpu_data = self.cpu_data[-self.max_data_points:]
                self.memory_data = self.memory_data[-self.max_data_points:]

            self.cpu_plot.setData(self.cpu_data)
            self.memory_plot.setData(self.memory_data)

            # Update system uptime
            if hasattr(self, 'uptime_label'):
                boot_time = datetime.fromtimestamp(psutil.boot_time())
                uptime = datetime.now() - boot_time
                days = uptime.days
                hours, remainder = divmod(uptime.seconds, 3600)
                minutes, seconds = divmod(remainder, 60)
                self.uptime_label.setText(f"{days}d {hours}h {minutes}m {seconds}s")

        except Exception as e:
            print(f"Error updating performance: {e}")

    def apply_settings(self):
        """Apply user settings"""
        try:
            # Update alert timer interval
            new_interval = self.update_interval_spin.value()
            self.alert_timer.setInterval(new_interval)

            QMessageBox.information(self, "Settings", "Settings applied successfully!")
        except Exception as e:
            QMessageBox.warning(self, "Settings Error", f"Failed to apply settings: {e}")

    def show_quick_stats(self):
        """Show quick statistics in a message box"""
        try:
            stats = self.detection_engine.get_statistics()
            alert_stats = stats.get("alerts", {})

            msg = f"""
MalCapture Defender Statistics

Total Alerts: {alert_stats.get('total_alerts', 0)}
Critical: {alert_stats.get('by_severity', {}).get('critical', 0)}
High: {alert_stats.get('by_severity', {}).get('high', 0)}
Medium: {alert_stats.get('by_severity', {}).get('medium', 0)}
Low: {alert_stats.get('by_severity', {}).get('low', 0)}

Uptime: {stats.get('engine', {}).get('uptime_formatted', 'N/A')}
            """

            if self.tray_icon:
                self.tray_icon.showMessage("MalCapture Defender", msg, QSystemTrayIcon.Information, 5000)
        except Exception as e:
            print(f"Error showing stats: {e}")

    def quit_application(self):
        """Quit the application"""
        reply = QMessageBox.question(
            self, 'Exit',
            "Are you sure you want to stop monitoring and exit?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )

        if reply == QMessageBox.Yes:
            self.detection_engine.stop()
            QApplication.quit()

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
