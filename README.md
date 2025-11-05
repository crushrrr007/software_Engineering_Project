# MalCapture Defender - Malicious Screen Capture Detection System

A comprehensive Windows security application that detects and monitors malicious screen capture activities based on MITRE ATT&CK Framework Technique T1113.

## 🎉 Version 2.0 - Major Update Available!

**NEW FEATURES:**
- 🖥️ **Enhanced GUI** with 6 tabs including real-time charts, performance monitoring, and settings
- 📊 **Real-Time Visualization** with live alert history and severity distribution graphs
- 🔍 **Advanced Filtering** and search capabilities across all alerts
- 📤 **CSV Export** for alerts and comprehensive JSON reports
- 💻 **Performance Dashboard** tracking CPU, memory, and disk usage
- 🔔 **System Tray Integration** for background monitoring
- 🎯 **Enhanced Detection** with 12 new detection flags and improved accuracy
- ⚙️ **Customizable Settings** panel for personalized monitoring

See [ENHANCEMENTS.md](ENHANCEMENTS.md) for complete details on all new features!

## Overview

This application provides real-time detection and monitoring of suspicious screen capture activities that may indicate the presence of spyware, keyloggers, or remote access trojans (RATs) attempting to steal sensitive information from your screen.

## MITRE ATT&CK Framework Reference

**Technique**: T1113 - Screen Capture
**Tactic**: Collection
**Platforms**: Windows, macOS, Linux

### Attack Description
Adversaries may attempt to take screen captures of the desktop to gather information over the course of an operation. Screen capturing functionality may be included as a feature of remote access tools used in post-compromise operations. Taking screenshots is also typically possible through native utilities or API calls.

## Features

### 1. Process Monitoring
- Detects suspicious processes accessing screen capture APIs
- Identifies known screenshot utilities and tools
- Monitors processes with hidden windows taking screenshots
- Tracks process behavior patterns

### 2. API Monitoring
- Monitors Windows GDI/GDI+ API calls:
  - `BitBlt` - Common screenshot API
  - `GetDC/GetWindowDC` - Device context retrieval
  - `CreateCompatibleBitmap` - Bitmap creation
  - `Windows.Graphics.Capture` - Modern capture API
- Detects suspicious API call patterns
- Identifies processes hooking into screen capture functions

### 3. File System Monitoring
- Tracks image file creation (.png, .jpg, .bmp, .gif)
- Monitors suspicious directories
- Detects rapid screenshot creation patterns
- Identifies hidden or temporary screenshot storage

### 4. Network Monitoring
- Detects potential screenshot exfiltration
- Monitors unusual network traffic patterns
- Identifies data transmission to suspicious IPs
- Tracks bandwidth usage spikes

### 5. Behavioral Analysis
- Machine learning-based anomaly detection
- Pattern recognition for malicious behavior
- Risk scoring for processes
- Historical behavior tracking

### 6. Alert System
- Real-time alerts with severity levels (Low, Medium, High, Critical)
- Comprehensive logging with timestamps
- MITRE ATT&CK technique mapping
- Alert history and reporting

### 7. GUI Dashboard
- Real-time monitoring display
- Process list with risk assessment
- Alert timeline and history
- System statistics and graphs
- Configuration management

## Architecture

```
MalCapture-Defender/
├── src/
│   ├── core/
│   │   ├── detection_engine.py    # Main detection engine
│   │   ├── alert_manager.py       # Alert handling and notification
│   │   └── config_manager.py      # Configuration management
│   ├── monitors/
│   │   ├── process_monitor.py     # Process monitoring
│   │   ├── api_monitor.py         # API hook monitoring
│   │   ├── file_monitor.py        # File system monitoring
│   │   └── network_monitor.py     # Network activity monitoring
│   ├── gui/
│   │   ├── main_window.py         # Main GUI application
│   │   └── dashboard.py           # Dashboard components
│   └── utils/
│       ├── logger.py              # Logging utilities
│       └── mitre_mapper.py        # MITRE ATT&CK mapping
├── tests/                         # Test suite
├── docs/                          # Documentation
├── logs/                          # Application logs
└── config.yaml                    # Configuration file
```

## Installation

### Prerequisites
- Windows 10/11 (64-bit)
- Python 3.8 or higher
- Administrator privileges (required for system monitoring)

### Setup

1. Clone the repository:
```bash
git clone https://github.com/crushrrr007/software_Engineering_Project.git
cd software_Engineering_Project
```

2. Install required dependencies:
```bash
pip install -r requirements.txt
```

3. Run the application with administrator privileges:
```bash
python src/main.py
```

## Usage

### Starting the Monitor

1. Launch the application as Administrator
2. The GUI dashboard will open showing real-time monitoring
3. All detection modules will start automatically
4. Alerts will appear in the dashboard and be logged

### Configuring Detection

Edit `config.yaml` to customize:
- Detection sensitivity levels
- Monitored directories
- Alert thresholds
- Whitelisted processes
- Network monitoring rules

### Viewing Alerts

- **Real-time**: Alerts appear in the dashboard immediately
- **History**: View all alerts in the Alert History tab
- **Logs**: Detailed logs are stored in `/logs` directory

### Understanding Risk Scores

- **Low (1-3)**: Normal system activity, minimal risk
- **Medium (4-6)**: Potentially suspicious, requires attention
- **High (7-8)**: Likely malicious, immediate review recommended
- **Critical (9-10)**: Confirmed malicious behavior, take action

## Detection Methods

### 1. API Hook Detection
Monitors Windows API calls commonly used for screen capture:

```python
# Monitored APIs
- user32.dll: GetDC, GetWindowDC, ReleaseDC
- gdi32.dll: BitBlt, CreateCompatibleDC, CreateCompatibleBitmap
- Windows.Graphics.Capture namespace (Windows 10+)
```

### 2. Known Utilities Detection
Identifies known screenshot tools:
- `psr.exe` (Windows Problem Steps Recorder)
- `SnippingTool.exe`
- Third-party tools (ShareX, Greenshot, etc.)
- PowerShell screenshot scripts

### 3. Behavioral Patterns
Detects malicious patterns:
- Hidden processes taking screenshots
- Rapid sequential screenshot capture
- Screenshots during credential entry
- Unusual screenshot frequency

### 4. Network Exfiltration
Monitors for data theft:
- Image file transmission
- Encrypted payload detection
- Suspicious destination IPs
- Unusual bandwidth usage

## MITRE ATT&CK Mapping

### T1113 - Screen Capture
**Detection Methods Implemented:**

| Detection Type | Description | Implementation |
|----------------|-------------|----------------|
| Process Monitoring | Monitor for processes with screen capture capabilities | `process_monitor.py` |
| API Monitoring | Track calls to screen capture APIs | `api_monitor.py` |
| File Monitoring | Detect creation of image files | `file_monitor.py` |
| Network Monitoring | Identify screenshot exfiltration | `network_monitor.py` |

## Testing

### Running Tests
```bash
# Run all tests
python -m pytest tests/

# Run specific test module
python -m pytest tests/test_process_monitor.py

# Generate coverage report
python -m pytest --cov=src tests/
```

### Test Screenshot Detection
The application includes a safe test mode that simulates screenshot activity for validation:

```bash
python tests/test_detection.py
```

## Troubleshooting

### Common Issues

**Issue**: Application won't start
**Solution**: Ensure you're running as Administrator and Python 3.8+ is installed

**Issue**: No alerts appearing
**Solution**: Check detection sensitivity in config.yaml, may be set too high

**Issue**: High CPU usage
**Solution**: Adjust monitoring intervals in configuration

**Issue**: False positives
**Solution**: Add legitimate processes to whitelist in config.yaml

## Security Considerations

- This tool requires administrative privileges to monitor system activities
- All logs and alerts are stored locally
- No data is transmitted outside your system
- Review whitelisted processes regularly
- Keep the application updated

## Contributing

Contributions are welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

## License

This project is created for educational purposes as part of a Software Engineering course project.

## Disclaimer

This software is designed for defensive security purposes only. Use it to protect your systems from malicious screen capture activities. Do not use this tool for unauthorized monitoring or malicious purposes.

## Authors

- Software Engineering Project Team
- Course: Software Engineering
- Topic: Detection of Malicious Screen Capture in Windows

## References

- [MITRE ATT&CK T1113 - Screen Capture](https://attack.mitre.org/techniques/T1113/)
- [Windows API Documentation](https://docs.microsoft.com/en-us/windows/win32/api/)
- [Kaspersky - Screenshot Protection](https://www.kaspersky.com/blog/preventing-dangerous-screenshots/22944/)

## Changelog

### Version 1.0.0 (Initial Release)
- Process monitoring implementation
- API hook detection
- File system monitoring
- Network monitoring
- GUI dashboard
- Alert system
- MITRE ATT&CK mapping
- Comprehensive logging

---

**Note**: This application is designed to detect malicious screen capture activities. For best results, run continuously in the background and review alerts regularly.
