#!/usr/bin/env python3
"""
Verification Script for MalCapture Defender
Checks if all components are correctly installed and configured
"""

import sys
import os
from pathlib import Path

def print_header(text):
    """Print a formatted header"""
    print("\n" + "=" * 70)
    print(f"  {text}")
    print("=" * 70)

def print_check(text, status):
    """Print a check result"""
    symbol = "✓" if status else "✗"
    color = "\033[92m" if status else "\033[91m"
    reset = "\033[0m"
    print(f"{color}{symbol}{reset} {text}")

def check_python_version():
    """Check Python version"""
    version = sys.version_info
    is_valid = version.major == 3 and version.minor >= 8
    print_check(f"Python version {version.major}.{version.minor}.{version.micro}", is_valid)
    return is_valid

def check_file_structure():
    """Check if all required files exist"""
    required_files = [
        "config.yaml",
        "requirements.txt",
        "README.md",
        "src/main.py",
        "src/core/detection_engine.py",
        "src/core/alert_manager.py",
        "src/monitors/process_monitor.py",
        "src/monitors/api_monitor.py",
        "src/monitors/file_monitor.py",
        "src/monitors/network_monitor.py",
        "src/gui/dashboard.py",
        "src/utils/logger.py",
        "src/utils/mitre_mapper.py",
        "tests/test_detection.py",
        "docs/MITRE_ATTACK_MAPPING.md",
        "docs/INSTALLATION.md",
    ]

    all_exist = True
    for file_path in required_files:
        exists = os.path.exists(file_path)
        if not exists:
            print_check(f"File missing: {file_path}", False)
            all_exist = False

    print_check(f"All {len(required_files)} required files present", all_exist)
    return all_exist

def check_config_file():
    """Check if config.yaml is valid"""
    try:
        import yaml
        with open("config.yaml", 'r') as f:
            config = yaml.safe_load(f)

        # Check for essential sections
        required_sections = ["application", "detection", "process_monitor",
                           "api_monitor", "file_monitor", "network_monitor"]
        has_all = all(section in config for section in required_sections)

        print_check("config.yaml is valid and complete", has_all)
        return has_all
    except Exception as e:
        print_check(f"config.yaml error: {e}", False)
        return False

def check_imports():
    """Check if core modules can be imported"""
    sys.path.insert(0, 'src')

    imports_ok = True

    modules = [
        ("utils.logger", "Logger module"),
        ("utils.mitre_mapper", "MITRE Mapper module"),
        ("core.alert_manager", "Alert Manager module"),
    ]

    for module_name, description in modules:
        try:
            __import__(module_name)
            print_check(f"{description} imports OK", True)
        except ImportError as e:
            print_check(f"{description} import failed: {e}", False)
            imports_ok = False

    return imports_ok

def check_dependencies():
    """Check if required dependencies are installed"""
    required_packages = [
        "psutil",
        "yaml",
        "watchdog",
    ]

    optional_packages = [
        "PyQt5",
        "pandas",
        "numpy",
        "colorlog",
    ]

    essential_ok = True
    print("\n  Essential Dependencies:")
    for package in required_packages:
        try:
            __import__(package)
            print_check(f"  {package} installed", True)
        except ImportError:
            print_check(f"  {package} NOT installed (REQUIRED)", False)
            essential_ok = False

    print("\n  Optional Dependencies:")
    for package in optional_packages:
        try:
            __import__(package)
            print_check(f"  {package} installed", True)
        except ImportError:
            print_check(f"  {package} not installed (optional)", True)

    return essential_ok

def check_syntax():
    """Check Python syntax of main files"""
    import py_compile

    files_to_check = [
        "src/main.py",
        "src/core/detection_engine.py",
        "src/monitors/process_monitor.py",
        "src/gui/dashboard.py",
    ]

    syntax_ok = True
    for file_path in files_to_check:
        try:
            py_compile.compile(file_path, doraise=True)
            # Don't print individual files, just overall result
        except py_compile.PyCompileError as e:
            print_check(f"Syntax error in {file_path}: {e}", False)
            syntax_ok = False

    print_check(f"Python syntax check for {len(files_to_check)} files", syntax_ok)
    return syntax_ok

def check_permissions():
    """Check if we have necessary permissions"""
    try:
        # Check if we can create log directory
        log_dir = Path("logs")
        log_dir.mkdir(exist_ok=True)

        # Check if we can write to it
        test_file = log_dir / "test.tmp"
        test_file.write_text("test")
        test_file.unlink()

        print_check("Write permissions OK", True)
        return True
    except Exception as e:
        print_check(f"Permission check failed: {e}", False)
        return False

def run_quick_test():
    """Run a quick functional test"""
    sys.path.insert(0, 'src')

    try:
        from utils.mitre_mapper import MITREMapper

        mapper = MITREMapper()
        technique = mapper.get_technique("T1113")

        if technique and technique.name == "Screen Capture":
            print_check("MITRE T1113 technique loaded correctly", True)
            return True
        else:
            print_check("MITRE T1113 technique loading failed", False)
            return False
    except Exception as e:
        print_check(f"Functional test failed: {e}", False)
        return False

def main():
    """Main verification function"""
    print_header("MalCapture Defender - Installation Verification")

    print("\nProject Information:")
    print(f"  Location: {os.getcwd()}")
    print(f"  Python: {sys.executable}")
    print(f"  OS: {os.name}")

    print_header("Running Checks")

    checks = []

    print("\n[1/8] Checking Python version...")
    checks.append(("Python Version", check_python_version()))

    print("\n[2/8] Checking file structure...")
    checks.append(("File Structure", check_file_structure()))

    print("\n[3/8] Checking configuration file...")
    checks.append(("Configuration", check_config_file()))

    print("\n[4/8] Checking dependencies...")
    checks.append(("Dependencies", check_dependencies()))

    print("\n[5/8] Checking Python syntax...")
    checks.append(("Syntax", check_syntax()))

    print("\n[6/8] Checking module imports...")
    checks.append(("Imports", check_imports()))

    print("\n[7/8] Checking permissions...")
    checks.append(("Permissions", check_permissions()))

    print("\n[8/8] Running functional test...")
    checks.append(("Functional Test", run_quick_test()))

    # Summary
    print_header("Verification Summary")

    passed = sum(1 for _, status in checks if status)
    total = len(checks)

    print(f"\nChecks passed: {passed}/{total}")
    print()

    for name, status in checks:
        print_check(name, status)

    if passed == total:
        print("\n" + "=" * 70)
        print("  🎉 ALL CHECKS PASSED!")
        print("  Your MalCapture Defender installation is ready to use.")
        print("=" * 70)
        print("\nTo run the application:")
        print("  python src/main.py --no-gui")
        print("\nTo run tests:")
        print("  python tests/test_detection.py")
        print()
        return 0
    else:
        print("\n" + "=" * 70)
        print("  ⚠ SOME CHECKS FAILED")
        print("  Please fix the issues above before running the application.")
        print("=" * 70)
        print("\nCommon fixes:")
        print("  - Install dependencies: pip install -r requirements.txt")
        print("  - Check file permissions: chmod +x src/main.py")
        print("  - Verify you're in the correct directory")
        print()
        return 1

if __name__ == "__main__":
    sys.exit(main())
