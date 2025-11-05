# 🧪 Complete Testing Guide for MalCapture Defender

## 🎯 Overview: How Everything Connects to Screen Capture Detection

MalCapture Defender uses **4 detection layers** to identify malicious screen capture activity based on **MITRE ATT&CK T1113** (Screen Capture technique):

```
┌─────────────────────────────────────────────────────────────┐
│               Screen Capture Detection System               │
├─────────────────────────────────────────────────────────────┤
│  1. Process Monitor    → Detects screenshot utilities       │
│  2. API Monitor        → Detects BitBlt/GetDC API calls     │
│  3. File Monitor       → Detects rapid image file creation  │
│  4. Network Monitor    → Detects image data exfiltration    │
└─────────────────────────────────────────────────────────────┘
```

---

## 📋 Table of Contents

1. [Process Monitor Testing](#1-process-monitor-testing)
2. [API Monitor Testing](#2-api-monitor-testing)
3. [File Monitor Testing](#3-file-monitor-testing)
4. [Network Monitor Testing](#4-network-monitor-testing)
5. [Integration Testing](#5-integration-testing)
6. [Troubleshooting](#6-troubleshooting)

---

## 1️⃣ Process Monitor Testing

### What It Detects
- Known screenshot utilities (SnippingTool, ShareX, Greenshot, etc.)
- Processes with suspicious names containing: "screen", "capture", "snip", "shot", "record"
- Processes running from TEMP directories
- Hidden window processes
- Unsigned executables
- Processes spawned by PowerShell/CMD
- High memory usage (image buffering)
- Network activity (data exfiltration)

### How It Works
```
Process Scanner (every 5 seconds)
    ↓
Checks process name against:
    - suspicious_processes list (config.yaml)
    - screenshot_patterns (keywords)
    - whitelist (excluded processes)
    ↓
Analyzes behavior:
    - Command line arguments
    - File location (TEMP?)
    - Memory usage
    - Network connections
    - Parent process
    ↓
Calculates Risk Score (0-10)
    ↓
Generates Alert (Low/Medium/High/Critical)
```

### Testing Steps

#### Test 1: Detect Snipping Tool
```bash
# Step 1: Open Snipping Tool
# Windows 10/11: Press Win + Shift + S
# Windows 7/8: Search for "Snipping Tool"

# Step 2: Wait 5-10 seconds for scan

# Step 3: Check GUI Alert tab
# Expected: Alert with "SnippingTool.exe" or "ScreenSnip.exe"
```

**Expected Alert**:
- **Severity**: HIGH or CRITICAL
- **Message**: "Suspicious process detected: ScreenSnip.exe (PID: XXX) - Process name contains 'snip'"
- **Risk Score**: 7-10
- **MITRE**: T1113

#### Test 2: Detect ShareX/Greenshot/Lightshot
```bash
# Install one of these tools:
# - ShareX: https://getsharex.com/
# - Greenshot: https://getgreenshot.org/
# - Lightshot: https://app.prntscr.com/

# Run the tool
# Wait 5-10 seconds
# Check Alert tab
```

**Expected**: Similar alert for the installed tool

#### Test 3: Check Process Diagnostics
```bash
# Run diagnostic tool
python diagnose_processes.py

# This shows you the EXACT process name
# Add it to config.yaml suspicious_processes if needed
```

#### Test 4: Verify Case-Insensitive Detection
The system now detects processes regardless of case:
- ✅ `SnippingTool.exe`
- ✅ `snippingtool.exe`
- ✅ `SNIPPINGTOOL.EXE`

All variations should trigger alerts!

---

## 2️⃣ API Monitor Testing

### What It Detects
Windows Graphics Device Interface (GDI) API calls used for screen capture:
- **BitBlt** - Copies screen pixels
- **StretchBlt** - Copies and resizes screen regions
- **GetDC** - Gets device context for screen
- **GetWindowDC** - Gets window device context
- **PrintWindow** - Captures window content
- **GetDIBits** - Retrieves bitmap pixel data

### How It Works
```
API Hooking (if available)
    ↓
Monitors function calls to:
    - gdi32.dll (BitBlt, StretchBlt, GetDIBits)
    - user32.dll (GetDC, GetWindowDC, PrintWindow)
    ↓
Tracks call frequency
    ↓
If calls > threshold (30/minute):
    → Generate Alert
```

### Testing Steps

#### Test 1: Generate Screen Capture Activity
```python
# Run this Python script to simulate screen capture
import win32gui
import win32ui
import win32con

# Get screen DC
hdesktop = win32gui.GetDesktopWindow()
desktop_dc = win32gui.GetWindowDC(hdesktop)

# Create memory DC
mem_dc = win32ui.CreateDCFromHandle(desktop_dc)

# This triggers BitBlt/GetDC API calls
# Should generate an alert if frequency exceeds threshold
```

#### Test 2: Use Screenshot Tool Repeatedly
```bash
# Open Snipping Tool
# Take 5-10 screenshots rapidly (within 1 minute)
# This should trigger API call threshold

# Expected: API Monitor alert
```

**Note**: API Monitor requires Windows and may need admin privileges.

---

## 3️⃣ File Monitor Testing

### What It Detects
- Rapid creation of image files (PNG, JPG, BMP, etc.)
- Image files created in TEMP/AppData directories
- Threshold: 5+ images in 30 seconds

### How It Works
```
File System Monitor (Watchdog)
    ↓
Monitors directories:
    - %TEMP%
    - %APPDATA%
    - %LOCALAPPDATA%
    - C:\Windows\Temp
    ↓
Detects file creation:
    - .png, .jpg, .jpeg, .bmp, .gif, .tiff
    ↓
Tracks creation rate
    ↓
If 5+ images in 30 seconds:
    → Generate Alert
```

### Testing Steps

#### Test 1: Rapid File Creation
```bash
# Create test script
cat > create_test_images.py << 'EOF'
from PIL import Image
import os
import time

temp_dir = os.environ['TEMP']
for i in range(6):
    img = Image.new('RGB', (100, 100), color='red')
    img.save(os.path.join(temp_dir, f'test_screenshot_{i}.png'))
    time.sleep(1)
    print(f'Created image {i+1}')
EOF

# Run script
python create_test_images.py

# Expected: File Monitor alert
```

**Expected Alert**:
- **Severity**: MEDIUM or HIGH
- **Message**: "Rapid image file creation detected in TEMP directory"
- **Files**: 5-6 PNG files

#### Test 2: Use Screenshot Tool
```bash
# Open Snipping Tool
# Take 5+ screenshots quickly
# Save all to TEMP directory
# Should trigger alert
```

---

## 4️⃣ Network Monitor Testing

### What It Detects
- Large image data transfers (> 1MB)
- High upload bandwidth (> 50MB/minute)
- Connections to suspicious ports (4444, 5555, etc.)
- Image exfiltration attempts

### How It Works
```
Network Connection Monitor
    ↓
Tracks process network activity
    ↓
Monitors:
    - Upload bandwidth per process
    - Connection destinations
    - Data transfer sizes
    ↓
If suspicious activity detected:
    → Generate Alert
```

### Testing Steps

#### Test 1: Upload Large Image
```bash
# Take a large screenshot
# Upload it to any service
# Expected: Network alert if > 1MB
```

#### Test 2: Suspicious Port Detection
```python
# Run a simple server on suspicious port
python -m http.server 4444

# If any process connects to port 4444:
# Expected: Alert
```

**Note**: Network Monitor may require admin privileges.

---

## 5️⃣ Integration Testing

### Full Detection Chain Test

```bash
# This tests ALL detection layers at once

# Step 1: Start MalCapture Defender
cd src && python main.py

# Step 2: Open Snipping Tool (Process detection)
# Win + Shift + S

# Step 3: Take 5 screenshots (File + API detection)
# Save to different locations

# Step 4: Upload one screenshot (Network detection)
# Use any cloud service

# Step 5: Check GUI
# Expected: Multiple alerts from different monitors
```

### Expected Results:
- 🔵 Process Alert: "ScreenSnip.exe detected"
- 🔵 API Alert: "High frequency of BitBlt calls"
- 🔵 File Alert: "Rapid image creation"
- 🔵 Network Alert: "Large data transfer"

---

## 6️⃣ Troubleshooting

### ❌ "Snipping Tool not detected"

**Diagnosis**:
```bash
# Step 1: Find the exact process name
python diagnose_processes.py

# Step 2: Open Snipping Tool
# Step 3: Run diagnostic again
# It will show you the exact name
```

**Common Issues**:
1. **Case sensitivity** → ✅ FIXED (now case-insensitive)
2. **Wrong process name** → Use `diagnose_processes.py` to find correct name
3. **Whitelisted** → Check `config.yaml` whitelist section
4. **Pattern matching** → Should catch "snip" in name automatically

**Fix**:
```yaml
# Add to config.yaml suspicious_processes:
- "YourExactProcessName.exe"
```

### ❌ "No alerts appearing"

**Check**:
1. **Is the engine running?** → Look for "Detection engine started" in console
2. **Are monitors enabled?** → Check config.yaml
3. **Check logs** → `logs/malcapture_*.log`
4. **Check console** → Look for `[DEBUG]` messages

```bash
# Enable debug mode
python test_alert_loading.py  # Verify alerts load

# Check statistics
# In GUI: Go to Statistics tab
# Should show monitoring activity
```

### ❌ "Export report fails"

**Error**: `datetime is not JSON serializable`

**Status**: ✅ FIXED

The export now handles datetime objects properly with custom JSON serializer.

### ❌ "Process detected but no alert in GUI"

**Check**:
1. **Filter settings** → Set to "All" in Alert tab
2. **Search box** → Clear any search text
3. **Check console** → Look for filtering debug messages

```bash
# Console should show:
[DEBUG] Retrieved N alerts from alert manager
[DEBUG] Current filter: severity='all', search=''
[DEBUG] After filtering: N alerts
```

---

## 📊 Understanding Detection Connections

### How Each Monitor Connects to Screen Capture:

#### 1. **Process Monitor** → Primary Detection
- **Why**: Screenshot tools must run as processes
- **Connection**: Identifies tools by name/behavior
- **Examples**: SnippingTool.exe, ShareX.exe

#### 2. **API Monitor** → Technical Detection
- **Why**: Screen capture requires Windows GDI APIs
- **Connection**: Monitors BitBlt/GetDC calls
- **Examples**: Any tool calling `BitBlt()` frequently

#### 3. **File Monitor** → Artifact Detection
- **Why**: Screenshots are saved as image files
- **Connection**: Detects rapid image creation
- **Examples**: 5+ PNG files in TEMP within 30s

#### 4. **Network Monitor** → Exfiltration Detection
- **Why**: Malware sends captured screens to C2 servers
- **Connection**: Detects large image uploads
- **Examples**: Uploading screenshots to external IPs

### MITRE ATT&CK T1113 Coverage

```
T1113: Screen Capture
├── Collection
│   ├── [COVERED] Screenshot utilities
│   ├── [COVERED] API-based capture
│   └── [COVERED] Clipboard capture
├── Exfiltration
│   └── [COVERED] Network upload
└── Persistence
    └── [PARTIAL] Startup processes
```

---

## 🎯 Quick Test Checklist

- [ ] Run `python diagnose_processes.py` to find screenshot tools
- [ ] Run `python test_alerts.py` to create test alerts
- [ ] Run `python test_alert_loading.py` to verify loading
- [ ] Start GUI: `cd src && python main.py`
- [ ] Open Snipping Tool (Win + Shift + S)
- [ ] Take 5+ screenshots
- [ ] Check Alert tab for detections
- [ ] Check Processes tab for suspicious processes
- [ ] Check Statistics tab for monitoring data
- [ ] Export report: Click "Export Report" button
- [ ] Verify no errors in console

---

## 🔧 Advanced Testing

### Custom Screenshot Tool Detection

```yaml
# Add your own tools to config.yaml
suspicious_processes:
  - "YourCustomTool.exe"
  - "custom-screenshot.exe"
```

### Adjusting Sensitivity

```yaml
# Make detection more sensitive
process_monitor:
  scan_interval: 2  # Scan every 2 seconds (default: 5)

alerts:
  aggregation:
    max_alerts: 5  # Lower threshold (default: 10)

file_monitor:
  rapid_creation_threshold: 3  # 3 files instead of 5
  rapid_creation_window: 20    # In 20 seconds instead of 30
```

### Testing on Different Windows Versions

- **Windows 7/8**: SnippingTool.exe
- **Windows 10 (old)**: SnippingTool.exe
- **Windows 10 (new)**: ScreenSnip.exe
- **Windows 11**: Snip.exe or ScreenSnip.exe

All should now be detected due to case-insensitive matching and pattern recognition!

---

## 📚 Additional Resources

- **MITRE ATT&CK T1113**: https://attack.mitre.org/techniques/T1113/
- **Windows GDI APIs**: https://docs.microsoft.com/en-us/windows/win32/gdi/
- **Process Monitor**: Check `src/monitors/process_monitor.py`
- **Configuration**: Edit `config.yaml` for customization

---

## 🎉 Summary

MalCapture Defender provides **comprehensive screen capture detection** through:

✅ **4 Detection Layers** (Process, API, File, Network)
✅ **MITRE ATT&CK Aligned** (T1113 coverage)
✅ **Case-Insensitive Matching** (detects all name variations)
✅ **Pattern Recognition** (catches unknown tools)
✅ **Behavioral Analysis** (hidden windows, memory usage, etc.)
✅ **Alert Persistence** (survives restarts)
✅ **Real-Time GUI** (live monitoring)
✅ **Export Reports** (JSON with full data)

**Start Testing**: Run `python diagnose_processes.py` then `cd src && python main.py`!
