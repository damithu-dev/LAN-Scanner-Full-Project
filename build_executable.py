"""PyInstaller packaging script for LAN Scanner.

Compiles the command-line interface into a single standalone executable binary
with bundled data files (offline CVE database), allowing distribution to endpoints
without requiring an installed Python interpreter.
"""

import os
import platform
import subprocess
import sys


def build_binary():
    """Execute PyInstaller build pipeline."""
    print("=" * 70)
    print(" LAN Scanner & Active Port Scanner - Executable Builder")
    print("=" * 70)

    # Check for PyInstaller
    try:
        import PyInstaller
        print("[+] PyInstaller detected.")
    except ImportError:
        print("[!] PyInstaller is not installed. Installing via pip...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "pyinstaller"])

    project_root = os.path.dirname(os.path.abspath(__file__))
    main_script = os.path.join(project_root, "main.py")
    cve_data = os.path.join(project_root, "scanner", "data", "cve_database.json")

    sep = ";" if platform.system() == "Windows" else ":"
    data_arg = f"{cve_data}{sep}scanner/data"

    cmd = [
        sys.executable,
        "-m",
        "PyInstaller",
        "--noconfirm",
        "--onefile",
        "--name",
        "lan_scanner",
        "--add-data",
        data_arg,
        "--hidden-import",
        "scapy",
        "--hidden-import",
        "rich",
        "--hidden-import",
        "exporters",
        "--hidden-import",
        "ui",
        main_script,
    ]

    print(f"[*] Executing command:\n{' '.join(cmd)}\n")
    result = subprocess.run(cmd)

    if result.returncode == 0:
        bin_dir = os.path.join(project_root, "dist")
        bin_name = "lan_scanner.exe" if platform.system() == "Windows" else "lan_scanner"
        bin_path = os.path.join(bin_dir, bin_name)
        print("=" * 70)
        print(f"[+] Build Successful! Standalone binary located at:\n    {bin_path}")
        print("=" * 70)
    else:
        print(f"[!] Build failed with exit code {result.returncode}")
        sys.exit(result.returncode)


if __name__ == "__main__":
    build_binary()
