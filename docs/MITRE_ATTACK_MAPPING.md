# MITRE ATT&CK Mapping for MalCapture Defender

This document provides detailed mapping of detection capabilities to the MITRE ATT&CK framework.

## Overview

MalCapture Defender implements detection and monitoring capabilities aligned with the MITRE ATT&CK framework, specifically targeting screen capture and data exfiltration techniques commonly used by adversaries.

---

## Primary Technique

### T1113 - Screen Capture

**Tactic**: Collection
**Platforms**: Windows, macOS, Linux
**Data Sources**: API monitoring, Process monitoring, File monitoring
**Severity**: HIGH

#### Description

Adversaries may attempt to take screen captures of the desktop to gather information over the course of an operation. Screen capturing functionality may be included as a feature of a remote access tool used in post-compromise operations. Taking a screenshot is also typically possible through native utilities or API calls, such as CopyFromScreen, xwd, or screencapture.

#### Detection Methods Implemented

| Detection Method | Implementation | Module | Description |
|-----------------|----------------|---------|-------------|
| **API Monitoring** | ✅ Implemented | `api_monitor.py` | Monitors Windows GDI/GDI+ API calls (BitBlt, GetDC, CreateCompatibleBitmap, etc.) |
| **Process Monitoring** | ✅ Implemented | `process_monitor.py` | Detects known screenshot utilities and suspicious process behavior |
| **File Monitoring** | ✅ Implemented | `file_monitor.py` | Tracks creation of image files in suspicious locations |
| **Behavioral Analysis** | ✅ Implemented | `detection_engine.py` | Pattern recognition for malicious screenshot sequences |

#### Windows APIs Monitored

**GDI32.dll**:
- `BitBlt` - Transfers pixel blocks between device contexts
- `StretchBlt` - Transfers pixel blocks with stretching
- `CreateCompatibleDC` - Creates memory device context
- `CreateCompatibleBitmap` - Creates bitmap compatible with device
- `GetDIBits` - Retrieves bitmap bits

**USER32.dll**:
- `GetDC` - Retrieves device context for screen
- `GetWindowDC` - Retrieves device context for window
- `GetDCEx` - Retrieves device context with extended options
- `ReleaseDC` - Releases device context
- `PrintWindow` - Prints window to device context

#### Common Screenshot Tools Detected

- `psr.exe` - Problem Steps Recorder (Windows built-in)
- `SnippingTool.exe` / `ScreenSnip.exe` - Windows Snipping Tool
- `ShareX.exe` - Third-party screenshot tool
- `Greenshot.exe` - Third-party screenshot tool
- `Lightshot.exe` - Third-party screenshot tool
- `Gyazo.exe` - Screenshot and screen recording
- PowerShell-based screenshot scripts

#### Detection Patterns

1. **Rapid API Calls**: Multiple BitBlt/GetDC calls within short timeframe
2. **API Call Sequence**: GetDC → CreateCompatibleDC → CreateCompatibleBitmap → BitBlt
3. **Hidden Process Screenshots**: Processes with hidden windows taking screenshots
4. **Rapid File Creation**: Multiple image files created in quick succession
5. **Suspicious Locations**: Screenshots saved to TEMP, AppData, or hidden directories

#### Example Detection Scenarios

**Scenario 1: Malware Taking Screenshots**
```
Alert: Suspicious process detected: malware.exe
Process: malware.exe (PID: 1234)
Flags: hidden_window, temp_location, rapid_screenshots
Risk Score: 9/10
MITRE: T1113 - Screen Capture
Action: Alert generated, process flagged for investigation
```

**Scenario 2: PowerShell Screenshot Script**
```
Alert: Suspicious API call pattern detected
Process: powershell.exe (PID: 5678)
Pattern: Rapid BitBlt calls (15 calls in 5 seconds)
Parent: cmd.exe
MITRE: T1113 - Screen Capture
Action: Alert generated, script execution logged
```

---

## Related Techniques

### T1056.001 - Input Capture: Keylogging

**Tactic**: Collection, Credential Access
**Severity**: HIGH

**Detection**: Often combined with screen capture to steal credentials. MalCapture Defender correlates screenshot activity with keylogging patterns.

**Indicators**:
- Processes monitoring both keyboard input and screen
- Screenshots taken during password field focus
- Combined with clipboard monitoring

---

### T1041 - Exfiltration Over C2 Channel

**Tactic**: Exfiltration
**Severity**: HIGH

#### Description

Adversaries may steal data by exfiltrating it over an existing command and control channel. Stolen data is encoded or encrypted before transmission.

#### Detection Methods Implemented

| Detection Method | Implementation | Module | Description |
|-----------------|----------------|---------|-------------|
| **Network Monitoring** | ✅ Implemented | `network_monitor.py` | Monitors network connections and data transfers |
| **Bandwidth Analysis** | ✅ Implemented | `network_monitor.py` | Detects unusual outbound data volumes |
| **Port Monitoring** | ✅ Implemented | `network_monitor.py` | Identifies suspicious port usage |

#### Suspicious Network Indicators

**Suspicious Ports Monitored**:
- 4444 (Metasploit default)
- 5555 (Common backdoor port)
- 6666 (IRC/backdoor)
- 8080, 8888 (HTTP alternatives)
- 9999 (Common backdoor)

**Detection Patterns**:
1. Large image file transfers to unknown destinations
2. Encrypted payload detection
3. Bandwidth spikes correlating with screenshot activity
4. Connections to suspicious IPs/domains

---

### T1057 - Process Discovery

**Tactic**: Discovery
**Severity**: LOW

**Detection**: Monitored as reconnaissance activity that often precedes screen capture operations.

---

### T1082 - System Information Discovery

**Tactic**: Discovery
**Severity**: LOW

**Detection**: Tracked as preparatory activity for targeted screenshot operations.

---

### T1055 - Process Injection

**Tactic**: Privilege Escalation, Defense Evasion
**Severity**: CRITICAL

**Detection**: Identifies attempts to inject screenshot functionality into legitimate processes.

**Indicators**:
- Legitimate processes making unexpected screenshot API calls
- DLL injection into processes with screen access
- Memory manipulation of processes with GUI windows

---

### T1027 - Obfuscated Files or Information

**Tactic**: Defense Evasion
**Severity**: MEDIUM

**Detection**: Encrypted or obfuscated screenshot files being created or transmitted.

---

## Detection Coverage Matrix

| MITRE Technique | Tactic | Severity | Detection Coverage | Implementation Status |
|----------------|--------|----------|-------------------|---------------------|
| T1113 | Collection | HIGH | 95% | ✅ Fully Implemented |
| T1056.001 | Collection | HIGH | 40% | ⚠️ Partial (correlation) |
| T1041 | Exfiltration | HIGH | 85% | ✅ Fully Implemented |
| T1057 | Discovery | LOW | 90% | ✅ Fully Implemented |
| T1082 | Discovery | LOW | 60% | ✅ Fully Implemented |
| T1055 | Privilege Escalation | CRITICAL | 70% | ⚠️ Partial |
| T1027 | Defense Evasion | MEDIUM | 50% | ⚠️ Partial |

---

## Alert Severity Mapping

| Severity | Risk Score | MITRE Techniques | Response Action |
|----------|-----------|------------------|-----------------|
| **CRITICAL** | 9-10 | T1055, Active exfiltration | Immediate investigation required |
| **HIGH** | 7-8 | T1113, T1041, T1056.001 | Urgent review recommended |
| **MEDIUM** | 4-6 | T1027, suspicious patterns | Monitor and investigate |
| **LOW** | 1-3 | T1057, T1082 | Log for analysis |

---

## Detection Rules

### Rule 1: Classic Screenshot Sequence
```yaml
Name: Classic Screenshot API Sequence
MITRE: T1113
Pattern: GetDC → CreateCompatibleDC → CreateCompatibleBitmap → BitBlt
Timeframe: < 2 seconds
Severity: HIGH
Action: Generate alert, log process details
```

### Rule 2: Rapid Screenshot Activity
```yaml
Name: Rapid Screenshot File Creation
MITRE: T1113
Pattern: ≥5 image files created in same directory
Timeframe: < 30 seconds
Severity: HIGH
Action: Generate alert, monitor process
```

### Rule 3: Hidden Process Screenshot
```yaml
Name: Hidden Window Screenshot Activity
MITRE: T1113
Pattern: Process with hidden window calling BitBlt
Frequency: Any
Severity: HIGH
Action: Generate alert, flag process
```

### Rule 4: Suspicious Exfiltration
```yaml
Name: Screenshot Exfiltration
MITRE: T1041
Pattern: Image file transmission to external IP
Size: > 1MB
Severity: CRITICAL
Action: Alert, block connection (optional)
```

---

## References

- [MITRE ATT&CK T1113](https://attack.mitre.org/techniques/T1113/)
- [MITRE ATT&CK T1041](https://attack.mitre.org/techniques/T1041/)
- [MITRE ATT&CK T1056.001](https://attack.mitre.org/techniques/T1056/001/)
- [Windows API Documentation](https://docs.microsoft.com/en-us/windows/win32/api/)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)

---

## Compliance & Standards

### NIST Cybersecurity Framework Mapping

- **Detect (DE.CM-7)**: Monitoring for unauthorized mobile code
- **Detect (DE.AE-2)**: Detected events are analyzed
- **Respond (RS.AN-1)**: Notifications from detection systems are investigated

### CIS Controls Mapping

- **Control 8**: Audit Log Management
- **Control 13**: Data Protection
- **Control 16**: Account Monitoring and Control

---

*Last Updated: 2024*
*Version: 1.0*
*MalCapture Defender - Detection of Malicious Screen Capture*
