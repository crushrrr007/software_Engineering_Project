"""
Diagnostic script to check running screenshot processes
This helps identify the exact process name for Snipping Tool
"""

import psutil
import sys

def find_screenshot_processes():
    """Find all processes that might be screenshot-related"""
    print("=" * 80)
    print("Screenshot Process Diagnostic Tool")
    print("=" * 80)
    print()

    # Keywords to look for
    keywords = ["snip", "screen", "capture", "shot", "record", "grab"]

    found_processes = []

    print("Scanning all running processes for screenshot-related names...")
    print()

    try:
        for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline']):
            try:
                name = proc.info['name']
                name_lower = name.lower()

                # Check if any keyword is in the process name
                for keyword in keywords:
                    if keyword in name_lower:
                        found_processes.append({
                            'pid': proc.info['pid'],
                            'name': name,
                            'exe': proc.info.get('exe', 'N/A'),
                            'cmdline': ' '.join(proc.info.get('cmdline', [])) if proc.info.get('cmdline') else 'N/A'
                        })
                        break

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

    except Exception as e:
        print(f"Error scanning processes: {e}")
        return

    if found_processes:
        print(f"✓ Found {len(found_processes)} screenshot-related processes:")
        print("-" * 80)

        for p in found_processes:
            print(f"Process Name: {p['name']}")
            print(f"  PID: {p['pid']}")
            print(f"  Executable: {p['exe']}")
            print(f"  Command: {p['cmdline'][:100]}...")
            print()

        print("=" * 80)
        print("IMPORTANT: Add the EXACT process name to config.yaml")
        print()
        print("Example:")
        print("  suspicious_processes:")
        for p in found_processes:
            print(f'    - "{p["name"]}"')

    else:
        print("⚠ No screenshot-related processes found")
        print()
        print("Try opening:")
        print("  - Windows Snipping Tool (Win + Shift + S)")
        print("  - ShareX, Greenshot, or Lightshot")
        print("  - Any screenshot utility")
        print()
        print("Then run this script again!")

    print()
    print("=" * 80)
    print()
    print("Current Windows Snipping Tool names (varies by Windows version):")
    print("  - SnippingTool.exe  (Windows 7, 8, 10 old)")
    print("  - ScreenSnip.exe    (Windows 10 new)")
    print("  - Snip.exe          (Windows 11)")
    print("  - ScreenClippingHost.exe  (Windows 10/11 background)")
    print("=" * 80)

if __name__ == "__main__":
    find_screenshot_processes()
