# Changelog

All notable changes to MalCapture Defender will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.1.0] - 2025-11-05

### 🎉 Major Enhancements

#### Enhanced Alert Details Dialog
- **Complete redesign** of alert details from raw JSON to beautiful formatted view
- Color-coded severity badges (Critical=Red, High=Orange, Medium=Yellow, Low=Green)
- Organized sections: Header, Message, Basic Info, Additional Details
- Professional dark theme matching main application
- Added action buttons:
  - 📋 Copy to Clipboard - Copies formatted text
  - 💾 Export JSON - Exports alert with datetime handling
  - ✖ Close - Standard close button
- Smart data formatting for nested objects and lists
- Emoji icons for quick visual recognition
- Dialog sized at 700x600 (increased from 600x400)

### 🐛 Critical Bug Fixes

#### 1. JSON Serialization Error (Export Report)
- **Issue**: Export report failed with "datetime is not JSON serializable"
- **Fix**: Added custom json_serializer function in `detection_engine.py`
- **Impact**: Export reports now work flawlessly
- **File**: `src/core/detection_engine.py`

#### 2. Snipping Tool Detection Failure
- **Issue**: SnippingTool.exe not detected even when listed in config
- **Root Cause**: Case-sensitive process name matching
- **Fix**: Converted all process names to lowercase for comparison
- **Impact**: Now detects all name variations (SnippingTool.exe, snippingtool.exe, SNIPPINGTOOL.EXE)
- **Files**: `src/monitors/process_monitor.py`, `config.yaml`

#### 3. Alert Display Not Showing Captured Alerts
- **Issue**: Alerts were created and logged but not appearing in GUI
- **Root Cause**: AlertManager never loaded alerts from disk on startup
- **Fix**: Added `_load_alerts_from_disk()` method
- **Impact**: Alerts now persist across application restarts
- **File**: `src/core/alert_manager.py`

#### 4. QSpinBox getValue() Error
- **Issue**: 'QSpinBox' object has no attribute 'getValue'
- **Fix**: Changed `getValue()` to `value()` (correct PyQt5 method)
- **File**: `src/gui/dashboard.py`

### ✨ New Features

#### Alert Persistence
- Alerts automatically load from JSON log files on startup
- Historical alerts preserved across sessions
- Statistics recalculated after loading
- Supports multiple alert log files

#### Debug Logging
- Comprehensive debug output in `update_alerts()`
- Shows alert retrieval count and filter status
- Logs filtering decisions for troubleshooting
- Full traceback on errors

#### Case-Insensitive Detection
- All process name matching now case-insensitive
- Whitelist matching case-insensitive
- Pattern matching unchanged (already lowercase)
- Works with any name variation

### 🛠️ Improvements

#### Configuration
- Added more screenshot tool name variations to `config.yaml`
- Added: SnippingTool.exe, Snip.exe, ScreenClippingHost.exe
- Added capitalized versions: ShareX.exe, Greenshot.exe, Lightshot.exe, Gyazo.exe
- Added note about case-insensitive matching
- Better organized with comments

#### Documentation
- Created comprehensive testing guide (600+ lines)
- Added diagnostic tool documentation
- Created fixes summary document
- Added alert enhancement documentation
- Improved README with new structure

### 🔧 Tools

#### New Diagnostic Scripts
- **test_alerts.py**: Creates 4 test alerts (Critical, High, Medium, Low)
- **test_alert_loading.py**: Verifies alerts load from disk correctly
- **diagnose_processes.py**: Finds screenshot processes and shows exact names

### 📁 Project Organization

#### File Structure Changes
- Created `tools/` directory for utility scripts
- Moved test scripts to `tools/`
- Moved documentation to `docs/`
- Removed duplicate files (QUICK_START.md, HOW_TO_RUN.txt)
- Cleaned up logs directory

#### Files Reorganized
```
tools/
├── test_alerts.py (moved from root)
├── test_alert_loading.py (moved from root)
├── diagnose_processes.py (moved from root)
└── verify_installation.py (moved from root)

docs/
├── COMPLETE_TESTING_GUIDE.md (moved from root)
├── ALERT_DETAILS_ENHANCEMENT.md (moved from root)
├── ALERT_DISPLAY_FIX.md (moved from root)
├── ALERT_FIX_SUMMARY.md (moved from root)
├── FIXES_SUMMARY.md (moved from root)
└── ENHANCEMENTS.md (moved from root)
```

#### Files Removed
- `QUICK_START.md` (duplicate of QUICKSTART.md)
- `HOW_TO_RUN.txt` (superseded by QUICKSTART.md)
- `logs/` directory (test data, not tracked)

### 📊 Testing

#### Enhanced Testing Guide
- Comprehensive 600+ line testing guide created
- Covers all 4 detection layers
- Step-by-step testing procedures
- Troubleshooting section
- MITRE ATT&CK T1113 coverage explanation
- Quick test checklist

#### Verification Tools
- Process diagnostic tool for identifying exact process names
- Alert loading verification script
- Test alert generation script
- Installation verification script

### 🎨 UI/UX Improvements

#### Alert Details Dialog
- Modern, professional design
- Color-coded severity for quick triage
- Organized information hierarchy
- No more raw JSON dumps
- User-friendly formatting
- Export and copy capabilities

#### Console Output
- Added debug logging for transparency
- Better error messages with tracebacks
- Filter status visibility
- Alert count tracking

### 📝 Documentation Updates

#### New Documentation
- `CHANGELOG.md` - This file
- `docs/COMPLETE_TESTING_GUIDE.md` - Comprehensive testing
- `docs/ALERT_DETAILS_ENHANCEMENT.md` - Alert UI documentation
- `docs/FIXES_SUMMARY.md` - All bugs fixed
- Updated README.md with new structure

#### Documentation Improvements
- Better project structure documentation
- Updated file paths for reorganization
- Added troubleshooting sections
- Improved installation instructions

---

## [2.0.0] - 2025-11-04

### 🎉 Major Release - Enhanced GUI

#### Enhanced GUI Dashboard
- 6 tabs: Alerts, Processes, Real-Time Charts, Performance, Statistics, Settings
- Real-time visualization with live charts
- Performance monitoring dashboard
- Advanced filtering and search
- CSV and JSON export capabilities
- System tray integration

#### Detection Improvements
- 12 new detection flags
- Enhanced behavioral analysis
- Improved risk scoring
- Better process categorization

#### Features Added
- Real-time charts (alert history, severity distribution)
- Performance metrics (CPU, memory, disk)
- System resource monitoring
- Customizable settings panel
- Desktop notifications
- Alert aggregation

See [docs/ENHANCEMENTS.md](docs/ENHANCEMENTS.md) for complete version 2.0 details.

---

## [1.0.0] - 2025-11-01

### 🚀 Initial Release

#### Core Features
- **Process Monitoring**: Detects suspicious screenshot processes
- **API Monitoring**: Tracks Windows GDI API calls
- **File Monitoring**: Watches for rapid image creation
- **Network Monitoring**: Detects screenshot exfiltration

#### Detection Engine
- Multi-layer detection system
- Risk scoring (0-10 scale)
- Severity classification (Low/Medium/High/Critical)
- MITRE ATT&CK T1113 mapping

#### Alert System
- Real-time alert generation
- Comprehensive logging
- Desktop notifications
- Alert history

#### GUI Dashboard
- Real-time monitoring display
- Process list with risk assessment
- Alert timeline
- Basic statistics

#### Configuration
- YAML-based configuration
- Customizable detection rules
- Whitelist support
- Adjustable sensitivity

---

## Version Comparison

| Feature | v1.0 | v2.0 | v2.1 |
|---------|------|------|------|
| Process Monitor | ✅ | ✅ | ✅ Enhanced |
| API Monitor | ✅ | ✅ | ✅ |
| File Monitor | ✅ | ✅ | ✅ |
| Network Monitor | ✅ | ✅ | ✅ |
| Basic GUI | ✅ | ❌ | ❌ |
| Enhanced GUI | ❌ | ✅ | ✅ |
| Real-Time Charts | ❌ | ✅ | ✅ |
| Performance Monitor | ❌ | ✅ | ✅ |
| Alert Persistence | ❌ | ❌ | ✅ |
| Beautiful Alert Details | ❌ | ❌ | ✅ |
| Case-Insensitive Detection | ❌ | ❌ | ✅ |
| Debug Logging | ❌ | ❌ | ✅ |
| Diagnostic Tools | ❌ | ❌ | ✅ |
| Comprehensive Testing Guide | ❌ | ❌ | ✅ |

---

## Roadmap

### Future Enhancements (v2.2)
- [ ] Machine learning-based anomaly detection
- [ ] Cloud alert integration (SIEM)
- [ ] Multi-language support
- [ ] Email alert notifications
- [ ] Scheduled scanning
- [ ] Report generation automation

### Under Consideration
- [ ] Linux/macOS support
- [ ] Web-based dashboard
- [ ] Mobile notifications
- [ ] API for integration
- [ ] Database backend option

---

## Known Issues

### None Currently!

All reported issues have been fixed in version 2.1.

Previously fixed issues:
- ✅ JSON serialization error (v2.1)
- ✅ Snipping Tool detection failure (v2.1)
- ✅ Alert display persistence (v2.1)
- ✅ QSpinBox getValue() error (v2.1)

---

## Migration Guide

### Upgrading from v2.0 to v2.1

1. **No Breaking Changes**
   - All v2.0 features preserved
   - Configuration compatible
   - No data migration needed

2. **New Features Available**
   - Alert details now show formatted view automatically
   - Alerts persist across restarts automatically
   - Case-insensitive detection works automatically
   - New diagnostic tools in `tools/` directory

3. **File Structure Changes**
   - Test scripts moved to `tools/`
   - Documentation moved to `docs/`
   - Update any scripts referencing old locations

### Upgrading from v1.0 to v2.0+

See [docs/ENHANCEMENTS.md](docs/ENHANCEMENTS.md) for v1.0 to v2.0 migration.

---

## Credits

### Contributors
- Software Engineering Project Team

### Special Thanks
- MITRE ATT&CK Framework
- PyQt5 Community
- Windows API Documentation
- Python Security Community

---

## Links

- **Repository**: https://github.com/crushrrr007/software_Engineering_Project
- **Issues**: https://github.com/crushrrr007/software_Engineering_Project/issues
- **MITRE ATT&CK**: https://attack.mitre.org/techniques/T1113/

---

**Note**: This changelog documents changes from version 2.0 onwards. For earlier history, see git commit logs.
