# Installation Guide - MalCapture Defender

## System Requirements

### Minimum Requirements
- **Operating System**: Windows 10/11 (64-bit)
- **Python Version**: 3.8 or higher
- **RAM**: 2GB minimum, 4GB recommended
- **Disk Space**: 500MB for application and logs
- **Privileges**: Administrator/elevated privileges required

### Recommended Requirements
- **Operating System**: Windows 11 (64-bit)
- **Python Version**: 3.10 or higher
- **RAM**: 8GB
- **Disk Space**: 2GB
- **Network**: Internet connection for updates

---

## Installation Steps

### 1. Install Python

Download and install Python 3.8+ from [python.org](https://www.python.org/downloads/)

**Important**: During installation, check "Add Python to PATH"

Verify installation:
```bash
python --version
```

### 2. Clone the Repository

```bash
git clone https://github.com/crushrrr007/software_Engineering_Project.git
cd software_Engineering_Project
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

If you encounter permission errors, use:
```bash
pip install --user -r requirements.txt
```

### 4. Verify Installation

Run the test suite:
```bash
python tests/test_detection.py
```

### 5. Configure the Application

Edit `config.yaml` to customize detection settings:
- Adjust sensitivity levels
- Configure monitored directories
- Set alert thresholds
- Add whitelisted processes

### 6. Run the Application

**With GUI (recommended)**:
```bash
python src/main.py
```

**CLI mode only**:
```bash
python src/main.py --no-gui
```

**Note**: Run as Administrator for full functionality:
- Right-click on Command Prompt
- Select "Run as administrator"
- Navigate to the project directory
- Run the command

---

## Installing as Windows Service (Optional)

To run MalCapture Defender as a Windows service:

### 1. Install NSSM (Non-Sucking Service Manager)

Download from: https://nssm.cc/download

### 2. Install the Service

```bash
nssm install MalCaptureDefender "C:\Python310\python.exe" "C:\path\to\src\main.py --no-gui"
```

### 3. Start the Service

```bash
nssm start MalCaptureDefender
```

---

## Troubleshooting

### Issue: "ImportError: No module named 'PyQt5'"

**Solution**:
```bash
pip install PyQt5
```

### Issue: "Permission denied" errors

**Solution**: Run as Administrator or use elevated command prompt

### Issue: API monitoring not working

**Solution**:
- Ensure running with Administrator privileges
- Check Windows Defender/Antivirus isn't blocking
- Verify pywin32 is installed: `pip install pywin32`

### Issue: High CPU usage

**Solution**:
- Adjust scan intervals in `config.yaml`
- Enable lite_mode in configuration
- Reduce number of monitored directories

### Issue: GUI won't start

**Solution**:
- Verify PyQt5 is installed
- Use `--no-gui` flag to run in CLI mode
- Check system supports GUI applications

---

## Updating

To update to the latest version:

```bash
git pull origin main
pip install -r requirements.txt --upgrade
```

---

## Uninstallation

1. Stop the application/service
2. Remove Windows service (if installed):
   ```bash
   nssm remove MalCaptureDefender confirm
   ```
3. Delete the project directory
4. Optionally uninstall Python packages:
   ```bash
   pip uninstall -r requirements.txt -y
   ```

---

## Next Steps

- Review the [User Guide](USER_GUIDE.md)
- Configure detection rules in `config.yaml`
- Read [MITRE ATT&CK Mapping](MITRE_ATTACK_MAPPING.md)
- Run tests to verify functionality

---

## Support

For issues and questions:
- GitHub Issues: https://github.com/crushrrr007/software_Engineering_Project/issues
- Documentation: See `docs/` directory
