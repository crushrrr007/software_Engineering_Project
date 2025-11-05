# MalCapture Defender - Malicious Screen Capture Detection System

![Version](https://img.shields.io/badge/version-2.1-blue.svg)
![Python](https://img.shields.io/badge/python-3.8+-green.svg)
![Platform](https://img.shields.io/badge/platform-Windows-lightgrey.svg)
![License](https://img.shields.io/badge/license-Educational-orange.svg)

A comprehensive Windows security application that detects and monitors malicious screen capture activities based on MITRE ATT&CK Framework Technique T1113.

## 🎯 Quick Start

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Run the application (requires Administrator)
cd src
python main.py

# 3. Open Snipping Tool to test detection
# Press: Win + Shift + S

# 4. Check the Alerts tab!
```

## ✨ Features

### 🎨 **Beautiful GUI Dashboard**
- Real-time monitoring with 6 tabs
- **Enhanced Alert Details** - User-friendly formatted view (not raw JSON!)
- Color-coded severity badges
- Live charts and performance metrics
- Export reports and CSV

### 🔍 **4-Layer Detection System**
1. **Process Monitor** - Detects screenshot utilities (SnippingTool, ShareX, etc.)
2. **API Monitor** - Monitors Windows GDI APIs (BitBlt, GetDC)
3. **File Monitor** - Tracks rapid image file creation
4. **Network Monitor** - Detects screenshot exfiltration

### 🎯 **MITRE ATT&CK T1113 Coverage**
- Aligned with Screen Capture technique
- Comprehensive detection across collection & exfiltration
- Risk scoring and severity classification

### 🔔 **Advanced Alerting**
- Real-time desktop notifications
- Persistent alert history (survives restarts)
- Filtering and search capabilities
- Copy to clipboard & JSON export

## 📁 Project Structure

```
MalCapture-Defender/
├── src/
│   ├── core/
│   │   ├── detection_engine.py    # Main orchestrator
│   │   └── alert_manager.py       # Alert handling
│   ├── monitors/
│   │   ├── process_monitor.py     # Process detection
│   │   ├── api_monitor.py         # API call monitoring
│   │   ├── file_monitor.py        # File system monitoring
│   │   └── network_monitor.py     # Network monitoring
│   ├── gui/
│   │   └── dashboard.py           # Enhanced GUI
│   ├── utils/
│   │   ├── logger.py              # Logging system
│   │   └── mitre_mapper.py        # MITRE mapping
│   └── main.py                    # Entry point
├── tools/
│   ├── test_alerts.py             # Create test alerts
│   ├── test_alert_loading.py      # Test alert persistence
│   ├── diagnose_processes.py      # Find screenshot processes
│   └── verify_installation.py     # Installation checker
├── docs/
│   ├── COMPLETE_TESTING_GUIDE.md  # Comprehensive testing
│   ├── ALERT_DETAILS_ENHANCEMENT.md
│   ├── ALERT_DISPLAY_FIX.md
│   ├── FIXES_SUMMARY.md
│   ├── INSTALLATION.md
│   └── MITRE_ATTACK_MAPPING.md
├── tests/
│   └── test_detection.py          # Unit tests
├── config.yaml                     # Configuration
├── requirements.txt                # Dependencies
├── QUICKSTART.md                   # Quick start guide
├── CHANGELOG.md                    # Version history
└── README.md                       # This file
```

## 🚀 Installation

### Prerequisites
- **OS**: Windows 10/11 (64-bit)
- **Python**: 3.8 or higher
- **Privileges**: Administrator access required
- **Disk Space**: ~500MB

### Step-by-Step Setup

1. **Clone the repository**
   ```bash
   git clone https://github.com/crushrrr007/software_Engineering_Project.git
   cd software_Engineering_Project
   ```

2. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Verify installation**
   ```bash
   python tools/verify_installation.py
   ```

4. **Run the application**
   ```bash
   cd src
   python main.py
   ```

For detailed installation instructions, see [docs/INSTALLATION.md](docs/INSTALLATION.md)

## 🧪 Testing

### Quick Test
```bash
# Create test alerts
python tools/test_alerts.py

# Start GUI
cd src && python main.py

# Check Alerts tab - should see 4 test alerts!
```

### Full Testing Guide
See [docs/COMPLETE_TESTING_GUIDE.md](docs/COMPLETE_TESTING_GUIDE.md) for:
- Testing all 4 detection layers
- Process detection testing
- API monitoring verification
- File and network monitoring
- Troubleshooting guide

### Diagnostic Tools
```bash
# Find screenshot processes
python tools/diagnose_processes.py

# Test alert loading
python tools/test_alert_loading.py
```

## ⚙️ Configuration

Edit `config.yaml` to customize:

```yaml
# Process monitoring
process_monitor:
  scan_interval: 5  # seconds
  suspicious_processes:
    - "SnippingTool.exe"
    - "ShareX.exe"
    # Add your own...

# Alert settings
alerts:
  methods:
    gui_notification: true
    desktop_notification: true
    log_file: true

# Detection sensitivity
detection:
  sensitivity: "medium"  # low, medium, high
```

## 📊 How Detection Works

### 1. Process Detection
```
Process Scanner (every 5 seconds)
  ↓
Checks: SnippingTool.exe, ShareX.exe, etc.
  ↓
Pattern matching: "snip", "capture", "screen"
  ↓
Behavioral analysis: hidden windows, memory usage
  ↓
Risk Score: 0-10 → Severity: Low/Medium/High/Critical
  ↓
Alert Generated
```

**Try it**: Open Snipping Tool (Win + Shift + S)

### 2. API Monitoring
Monitors Windows GDI API calls:
- `BitBlt` - Screen pixel copying
- `GetDC` - Device context retrieval
- `StretchBlt` - Screen region copying

**Triggers**: >30 calls per minute

### 3. File Monitoring
Watches for rapid image creation:
- Monitors: TEMP, AppData directories
- Detects: 5+ images in 30 seconds
- Formats: PNG, JPG, BMP, GIF

### 4. Network Monitoring
Detects screenshot exfiltration:
- Large image uploads (>1MB)
- High bandwidth usage (>50MB/min)
- Suspicious ports (4444, 5555, etc.)

## 🎨 GUI Features

### Enhanced Alert Details
Double-click any alert to see:

```
┌─────────────────────────────────────┐
│ CRITICAL  🕐 12:30:45    MITRE T1113│
│                                     │
│ 📋 Alert Message                   │
│ Suspicious process detected:       │
│ ScreenSnip.exe (PID: 12345)        │
│                                     │
│ ℹ️ Basic Information               │
│ • Type: Process                    │
│ • Alert ID: xxx                    │
│ • Acknowledged: ✗ No               │
│                                     │
│ 🔬 Additional Details              │
│ • Risk Score: 8/10                 │
│ • Flags: suspicious_name           │
│                                     │
│ [📋 Copy] [💾 Export] [✖ Close]   │
└─────────────────────────────────────┘
```

**Features**:
- Color-coded severity badges
- Copy to clipboard
- Export as JSON
- Organized sections
- No more raw JSON!

### Dashboard Tabs
1. **🚨 Alerts** - Real-time alerts with filtering
2. **⚙️ Processes** - Suspicious process list
3. **📊 Real-Time** - Live charts
4. **💻 Performance** - System metrics
5. **📈 Statistics** - Detection stats
6. **⚙️ Settings** - Configuration

## 🔧 Troubleshooting

### ❌ "Snipping Tool not detected"
```bash
# 1. Find the exact process name
python tools/diagnose_processes.py

# 2. Open Snipping Tool

# 3. Run diagnostic again
python tools/diagnose_processes.py

# 4. Add to config.yaml if needed
```

**Note**: Detection is now **case-insensitive**!

### ❌ "No alerts appearing"
- Check filter is set to "All"
- Clear search box
- Look for `[DEBUG]` messages in console
- Verify detection engine is running

### ❌ "Export report fails"
✅ **FIXED** - Datetime serialization now handled automatically

See [docs/FIXES_SUMMARY.md](docs/FIXES_SUMMARY.md) for all resolved issues.

## 📚 Documentation

| Document | Description |
|----------|-------------|
| [QUICKSTART.md](QUICKSTART.md) | Quick start guide |
| [CHANGELOG.md](CHANGELOG.md) | Version history |
| [docs/COMPLETE_TESTING_GUIDE.md](docs/COMPLETE_TESTING_GUIDE.md) | Comprehensive testing |
| [docs/ALERT_DETAILS_ENHANCEMENT.md](docs/ALERT_DETAILS_ENHANCEMENT.md) | Alert UI improvements |
| [docs/FIXES_SUMMARY.md](docs/FIXES_SUMMARY.md) | All bug fixes |
| [docs/INSTALLATION.md](docs/INSTALLATION.md) | Detailed installation |
| [docs/MITRE_ATTACK_MAPPING.md](docs/MITRE_ATTACK_MAPPING.md) | MITRE ATT&CK coverage |

## 🛡️ MITRE ATT&CK T1113 Coverage

### Screen Capture Detection
| Detection Layer | Implementation | Status |
|----------------|----------------|--------|
| Process Monitoring | `process_monitor.py` | ✅ Active |
| API Monitoring | `api_monitor.py` | ✅ Active |
| File Monitoring | `file_monitor.py` | ✅ Active |
| Network Monitoring | `network_monitor.py` | ✅ Active |

**Coverage**: Collection → Exfiltration (full chain)

## 🎯 Risk Scoring

| Risk Score | Severity | Action |
|------------|----------|--------|
| 9-10 | 🔴 Critical | Immediate action required |
| 7-8 | 🟠 High | Review immediately |
| 4-6 | 🟡 Medium | Investigate when possible |
| 1-3 | 🟢 Low | Monitor for patterns |

## 🔒 Security & Privacy

- ✅ All processing happens locally
- ✅ No data sent to external servers
- ✅ Logs stored securely on your system
- ✅ Administrator privileges for monitoring only
- ✅ Open source - audit the code yourself

## 🤝 Contributing

Contributions welcome! Please:
1. Fork the repository
2. Create a feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 📝 License

Educational use only. Created for Software Engineering course project.

## 👥 Authors

- **Software Engineering Project Team**
- **Course**: Software Engineering
- **Institution**: [Your Institution]
- **Year**: 2025

## 🙏 Acknowledgments

- MITRE ATT&CK Framework for threat intelligence
- Windows API documentation
- PyQt5 community for GUI development
- Python security community

## 📖 References

- [MITRE ATT&CK T1113](https://attack.mitre.org/techniques/T1113/)
- [Windows API Documentation](https://docs.microsoft.com/en-us/windows/win32/api/)
- [Screen Capture Security Best Practices](https://www.kaspersky.com/blog/preventing-dangerous-screenshots/22944/)

## 🆘 Support

Having issues? Check:
1. [docs/FIXES_SUMMARY.md](docs/FIXES_SUMMARY.md) - Common issues resolved
2. [docs/COMPLETE_TESTING_GUIDE.md](docs/COMPLETE_TESTING_GUIDE.md) - Testing & troubleshooting
3. [GitHub Issues](https://github.com/crushrrr007/software_Engineering_Project/issues)

## ⭐ Star History

If this project helped you, please consider giving it a star! ⭐

---

**Status**: ✅ Production Ready
**Version**: 2.1
**Last Updated**: November 2025

**Quick Links**:
- 📖 [Quick Start](QUICKSTART.md)
- 🧪 [Testing Guide](docs/COMPLETE_TESTING_GUIDE.md)
- 🐛 [Bug Fixes](docs/FIXES_SUMMARY.md)
- 📊 [MITRE Coverage](docs/MITRE_ATTACK_MAPPING.md)

---

Made with ❤️ for Windows Security
