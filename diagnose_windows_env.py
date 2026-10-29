"""Diagnose (and optionally repair) the "Application Control policy blocked ..." error.

Why this script exists
----------------------
On Windows, importing pandas can fail with::

    ImportError: DLL load failed while importing vectorized:
    An Application Control policy has blocked this file.

That message does not come from Python or pandas. It comes from the Windows
code-integrity subsystem (WDAC / AppLocker / Smart App Control / Defender
Application Control) which refused to load a compiled pandas extension such as::

    .venv\\Lib\\site-packages\\pandas\\_libs\\tslibs\\vectorized.cp312-win_amd64.pyd

Any Python package containing compiled binaries can be affected, but pandas,
numpy and pyarrow are the usual victims because they ship many ``.pyd`` files.

What this script does
---------------------
1. Reports the interpreter, virtualenv and platform in use.
2. Tries to import every dependency the project needs and prints the *first*
   failure with its exact message (so you know if it is really code integrity).
3. On Windows, inspects the code-integrity configuration and event log:
   Smart App Control state, deployed WDAC/AppLocker policies, and the most recent
   CodeIntegrity block events that mention the failing DLL.
4. Prints a prioritised action list (see FIX_PANDAS_WINDOWS.md for the long form).
5. With ``--repair``, reinstalls the binary dependencies from official wheels.

Usage:
    python diagnose_windows_env.py
    python diagnose_windows_env.py --repair
    python diagnose_windows_env.py --repair --venv C:\\Tools\\lan-scanner-venv
    python diagnose_windows_env.py --requirements requirements.txt
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import shutil
import subprocess
import sys
import textwrap
from typing import Any, Dict, List, Optional, Sequence

BLOCK_MARKERS = (
    "application control policy",
    "blocked this file",
    "was blocked",
    "code integrity",
    "0xc0e90002",
)

DEPENDENCY_CHECKS = [
    # (import name, pip name, required?)
    ("numpy", "numpy", True),
    ("pandas", "pandas", True),
    ("pyarrow", "pyarrow", False),
    ("streamlit", "streamlit", False),
    ("scapy", "scapy", False),
    ("rich", "rich", False),
    ("docx", "python-docx", False),
]

REPAIR_PACKAGES = [
    "numpy>=2.0",
    "pandas>=2.2.2",
    "pyarrow>=16.0.0",
    "streamlit>=1.30.0",
    "scapy>=2.5.0",
    "rich>=13.0.0",
    "python-docx>=1.0.0",
]


class Reporter:
    """Tiny console reporter with section headers."""

    def __init__(self, color: bool = True) -> None:
        self.color = color

    def _c(self, text: str, code: str) -> str:
        if not self.color or os.environ.get("NO_COLOR"):
            return text
        return f"\033[{code}m{text}\033[0m"

    def header(self, text: str) -> None:
        print()
        print(self._c("=" * 74, "36"))
        print(self._c(f" {text}", "1;36"))
        print(self._c("=" * 74, "36"))

    def ok(self, text: str) -> None:
        print(f"  {self._c('[ OK ]', '32')} {text}")

    def warn(self, text: str) -> None:
        print(f"  {self._c('[WARN]', '33')} {text}")

    def fail(self, text: str) -> None:
        print(f"  {self._c('[FAIL]', '31')} {text}")

    def info(self, text: str) -> None:
        print(f"  {self._c('[ -- ]', '90')} {text}")

    def bullet(self, text: str) -> None:
        print(textwrap.fill(text, width=76, initial_indent="    - ", subsequent_indent="      "))


# --------------------------------------------------------------------------- #
# Process helpers
# --------------------------------------------------------------------------- #


def run_command(command: Sequence[str], timeout: int = 30) -> Optional[str]:
    """Run a command and return combined output, or None on failure."""
    try:
        proc = subprocess.run(
            list(command),
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    output = (proc.stdout or "") + (proc.stderr or "")
    return output.strip() or None


def run_powershell(script: str, timeout: int = 40) -> Optional[str]:
    """Execute a PowerShell snippet, returning its output or None."""
    shell = shutil.which("powershell") or shutil.which("pwsh")
    if not shell:
        return None
    return run_command(
        [shell, "-NoProfile", "-NonInteractive", "-Command", script],
        timeout=timeout,
    )


# --------------------------------------------------------------------------- #
# Checks
# --------------------------------------------------------------------------- #


def describe_environment(rep: Reporter) -> Dict[str, Any]:
    """Print interpreter/venv/platform details."""
    rep.header("1. Python environment")
    in_venv = sys.prefix != getattr(sys, "base_prefix", sys.prefix)
    details = {
        "python": sys.version.split()[0],
        "executable": sys.executable,
        "platform": platform.platform(),
        "machine": platform.machine(),
        "in_venv": in_venv,
        "prefix": sys.prefix,
        "cwd": os.getcwd(),
    }
    rep.info(f"Python {details['python']} ({details['machine']}) on {details['platform']}")
    rep.info(f"Interpreter: {details['executable']}")
    if in_venv:
        rep.ok(f"Running inside a virtual environment: {sys.prefix}")
    else:
        rep.warn(
            "Not running inside a virtual environment. Activate yours first, e.g. "
            r".venv\Scripts\activate  (or pass --venv to --repair)."
        )
    lowered = str(sys.executable).lower()
    if "onedrive" in lowered:
        rep.warn(
            "Python/venv lives inside OneDrive. OneDrive-synced folders sometimes lose "
            r"metadata and are frequently blocked by Application Control policies. "
            r"Prefer C:\Tools\lan-scanner-venv."
        )
    return details


def check_imports(rep: Reporter) -> Dict[str, Dict[str, Any]]:
    """Import each dependency in an isolated subprocess and record failures."""
    rep.header("2. Dependency import check (each in its own process)")
    results: Dict[str, Dict[str, Any]] = {}

    for import_name, pip_name, required in DEPENDENCY_CHECKS:
        code = (
            "import importlib, json, sys\n"
            f"mod = importlib.import_module({import_name!r})\n"
            "print(json.dumps({'version': getattr(mod, '__version__', 'unknown'),"
            " 'file': getattr(mod, '__file__', '')}))\n"
        )
        try:
            proc = subprocess.run(
                [sys.executable, "-c", code],
                capture_output=True,
                text=True,
                timeout=180,
            )
        except subprocess.SubprocessError as exc:  # pragma: no cover
            results[import_name] = {"ok": False, "error": str(exc), "required": required}
            rep.fail(f"{pip_name}: timed out or could not start ({exc})")
            continue

        if proc.returncode == 0:
            try:
                payload = json.loads(proc.stdout.strip().splitlines()[-1])
            except (ValueError, IndexError):
                payload = {"version": "unknown", "file": ""}
            results[import_name] = {
                "ok": True,
                "version": payload.get("version"),
                "file": payload.get("file"),
                "required": required,
            }
            rep.ok(f"{pip_name}: imported successfully (version {payload.get('version')})")
            continue

        stderr = (proc.stderr or "").strip()
        last_line = stderr.splitlines()[-1] if stderr else "unknown import error"
        blocked = any(marker in stderr.lower() for marker in BLOCK_MARKERS)
        results[import_name] = {
            "ok": False,
            "error": last_line,
            "stderr": stderr,
            "blocked_by_policy": blocked,
            "required": required,
        }
        if blocked:
            rep.fail(f"{pip_name}: BLOCKED BY APPLICATION CONTROL -> {last_line}")
        elif required:
            rep.fail(f"{pip_name}: import failed -> {last_line}")
        else:
            rep.warn(f"{pip_name}: optional import failed -> {last_line}")

    return results


def find_blocked_modules(results: Dict[str, Dict[str, Any]]) -> List[str]:
    """Return pip names of dependencies that code integrity blocked."""
    return [
        pip_name
        for import_name, pip_name, _required in DEPENDENCY_CHECKS
        if import_name in results and results[import_name].get("blocked_by_policy")
    ]


def failing_dll_from_stderr(results: Dict[str, Dict[str, Any]]) -> Optional[str]:
    """Extract the '.pyd'/'.dll' filename mentioned in a failing traceback."""
    for data in results.values():
        text = data.get("stderr") or ""
        for line in text.splitlines():
            lowered = line.lower()
            if "vectorized" in lowered and ".pyd" in lowered:
                return line.strip()
        for line in text.splitlines():
            if ".pyd" in line.lower() or ".dll" in line.lower():
                return line.strip()
    return None


def check_code_integrity(rep: Reporter) -> Dict[str, Any]:
    """Inspect Windows code-integrity configuration and event log."""
    rep.header("3. Windows code-integrity configuration")
    data: Dict[str, Any] = {"platform": sys.platform}
    if sys.platform != "win32":
        rep.warn("Not running on Windows - skipping code-integrity checks.")
        return data

    # Smart App Control state (0 = off, 1 = enforced, 2 = evaluation)
    sac = run_powershell(
        "try { (Get-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\CI\\Policy' "
        "-Name VerifiedAndReputablePolicyState -ErrorAction Stop).VerifiedAndReputablePolicyState } "
        "catch { 'unknown' }"
    )
    data["smart_app_control"] = sac
    labels = {"0": "Off", "1": "On (enforcing)", "2": "Evaluation mode", "unknown": "unknown"}
    state = (sac or "unknown").strip()
    label = labels.get(state, state)
    if state in ("1", "2"):
        rep.warn(
            f"Smart App Control is {label}. It blocks unsigned/unpopular binaries - including "
            "compiled Python extension modules such as pandas .pyd files."
        )
    else:
        rep.info(f"Smart App Control: {label}")

    # WDAC policies
    policies = run_powershell(
        "$p = Join-Path $env:SystemRoot 'System32\\CiTool.exe'; "
        "if (Test-Path $p) { & $p -lp } else { 'CiTool.exe not found' }"
    )
    data["wdac_policies"] = policies
    if policies and "not found" not in policies.lower():
        active = [ln.strip() for ln in policies.splitlines() if "is enrolled" in ln.lower() or "policy" in ln.lower()]
        if active:
            rep.warn("Deployed Windows Defender Application Control (WDAC) policies were found:")
            for line in active[:10]:
                print(f"          {line}")
        else:
            rep.info("No active WDAC policies reported by CiTool.")
    elif policies:
        rep.info("CiTool.exe unavailable - cannot list WDAC policies on this edition.")

    # AppLocker rules (only meaningful if the service is running)
    applocker = run_powershell(
        "try { (Get-AppLockerPolicy -Effective -ErrorAction Stop).RuleCollections | "
        "ForEach-Object { $_.PolicyDecision.ToString() + ': ' + ($_.Rules | "
        "ForEach-Object { $_.Name }) -join ', ' } } catch { 'AppLocker not configured' }"
    )
    data["applocker"] = applocker
    if applocker and "not configured" not in applocker.lower():
        rep.warn("AppLocker policies are configured; they may block .pyd files:")
        print(textwrap.indent(applocker[:600], "          "))
    else:
        rep.info("AppLocker: not configured (or not available).")

    # Recent CodeIntegrity block events mentioning python/pandas/.pyd
    events = run_powershell(
        "try { Get-WinEvent -LogName 'Microsoft-Windows-CodeIntegrity/Operational' "
        "-MaxEvents 60 -ErrorAction Stop | Where-Object { $_.Message -match "
        "'python|pandas|num?py|pyarrow|\\.pyd|\\.dll' } | Select-Object -First 8 | "
        "ForEach-Object { $_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss') + ' | ' + "
        "($_.Message -replace '\\s+', ' ').Substring(0, [Math]::Min(240, "
        "($_.Message -replace '\\s+', ' ').Length)) } } catch { 'no matching events' }"
    )
    data["codeintegrity_events"] = events
    if events and "no matching events" not in events.lower():
        rep.warn("Recent CodeIntegrity events that mention Python/pandas/.pyd/.dll:")
        print(textwrap.indent(events[:1800], "          "))
    else:
        rep.info(
            "No matching CodeIntegrity events (the log may be disabled; open Event Viewer -> "
            "Applications and Services Logs -> Microsoft -> Windows -> CodeIntegrity -> Operational)."
        )

    return data


def check_pandas_files(rep: Reporter, results: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    """Inspect the on-disk pandas extension modules for download markers/signatures."""
    rep.header("4. pandas / numpy compiled files on disk")
    info: Dict[str, Any] = {}
    if sys.platform != "win32":
        rep.info("Skipped (not Windows).")
        return info

    try:
        import importlib.util

        spec = importlib.util.find_spec("pandas")
    except (ImportError, ValueError):
        spec = None

    if spec is None or not spec.origin:
        rep.warn("pandas is not installed in this interpreter at all.")
        return info

    site_dir = os.path.dirname(os.path.dirname(spec.origin))
    libs = os.path.join(site_dir, "pandas", "_libs")
    target = os.path.join(libs, "tslibs", "vectorized.cp*-win_amd64.pyd")
    rep.info(f"pandas location: {spec.origin}")

    import glob

    matches = glob.glob(target)
    if not matches:
        rep.warn(f"Could not find {target} - the blocked file may have a different name/ABI.")
        return info

    for path in matches:
        info["blocked_dll_path"] = path
        zonepath = path + ":Zone.Identifier"
        zone = run_powershell(
            f"if (Test-Path -LiteralPath '{zonepath}') {{ Get-Content -LiteralPath '{zonepath}' }} else {{ 'none' }}"
        )
        if zone and zone.strip().lower() != "none":
            rep.warn(f"{os.path.basename(path)} carries a 'downloaded from the internet' marker (Zone.Identifier).")
            rep.bullet(
                "Unblock it: right-click the file -> Properties -> tick 'Unblock' -> OK, or run: "
                f"Unblock-File -LiteralPath '{path}'"
            )
        else:
            rep.info(f"{os.path.basename(path)}: no Zone.Identifier marker.")

        signature = run_powershell(
            f"(Get-AuthenticodeSignature -LiteralPath '{path}').Status"
        )
        info["signature"] = signature
        rep.info(f"Authenticode status: {signature or 'unknown'}")
        if signature and signature.strip().lower() in ("notsigned", "hashmismatch", "unknownerror"):
            rep.warn(
                "The DLL is unsigned/hash-mismatched. Application Control policies that require "
                "signed binaries will block it every time - this cannot be fixed with pip."
            )
    return info


def print_verdict(
    rep: Reporter,
    results: Dict[str, Dict[str, Any]],
    ci_data: Dict[str, Any],
    file_info: Dict[str, Any],
) -> None:
    """Summarise findings and print prioritised next steps."""
    rep.header("VERDICT & NEXT STEPS")
    blocked = find_blocked_modules(results)
    streamlit_failed = results.get("streamlit", {}).get("ok") is False
    pandas_failed = results.get("pandas", {}).get("ok") is False
    dll_hint = failing_dll_from_stderr(results)

    if dll_hint:
        rep.info(f"Failing component: {dll_hint}")

    if blocked:
        rep.fail(
            "Windows code integrity is blocking the compiled Python extension(s): "
            + ", ".join(blocked)
        )
        rep.info("")
        rep.info("Choose ONE of these paths, in order of preference:")
        rep.bullet(
            "1. Run the dashboard that does not need pandas at all: "
            "python run_dashboard.py --backend standalone   (fully working web UI, stdlib only)"
        )
        rep.bullet(
            "2. Ask your administrator/IT to allow the package directory in the Application Control "
            "policy (they can allow-list the venv folder, e.g. C:\\Tools\\lan-scanner-venv\\*, or add "
            "a WDAC supplemental policy). Add --repair to this script afterwards to reinstall cleanly."
        )
        rep.bullet(
            "3. Create the virtual environment OUTSIDE OneDrive/Desktop in a folder that policy "
            "already trusts: python -m venv C:\\Tools\\lan-scanner-venv, then "
            "C:\\Tools\\lan-scanner-venv\\Scripts\\pip install -r requirements.txt"
        )
        rep.bullet(
            "4. If Smart App Control is the cause (state = 1/2 above) and you control the PC, turning "
            "it off (Windows Security -> App & browser control -> Smart App Control) unblocks unsigned "
            "Python extensions. Note: turning it off is effectively permanent until Windows is reset."
        )
        rep.bullet(
            "5. Use the terminal scanner instead, which needs no pandas/Streamlit: "
            "python main.py --help"
        )
        if streamlit_failed:
            rep.info("")
            rep.warn(
                "Because Streamlit imports pandas at start-up, 'streamlit run dashboard/app.py' "
                "cannot work while pandas is blocked. Use option 1."
            )
    elif pandas_failed:
        rep.fail("pandas failed to import for a reason other than code integrity (see section 2).")
        rep.bullet("Try a clean reinstall: python diagnose_windows_env.py --repair")
    elif streamlit_failed:
        rep.warn("pandas works but Streamlit does not import - reinstall Streamlit:")
        rep.bullet("python -m pip install --force-reinstall --no-cache-dir streamlit")
    else:
        rep.ok("All Python dependencies import successfully on this interpreter.")
        rep.bullet("Start the dashboard with: streamlit run dashboard/app.py")
        rep.bullet("or: python run_dashboard.py")

    if not file_info.get("blocked_dll_path"):
        rep.info("")
        rep.info(
            "Reminder: App Control events are logged in Event Viewer under "
            "Applications and Services Logs > Microsoft > Windows > CodeIntegrity > Operational."
        )
    print()


# --------------------------------------------------------------------------- #
# Repair
# --------------------------------------------------------------------------- #


def repair(rep: Reporter, venv_dir: Optional[str], requirements: Optional[str]) -> int:
    """Reinstall binary dependencies from official wheels."""
    rep.header("REPAIR")
    python = sys.executable

    if venv_dir:
        rep.info(f"Creating a fresh virtual environment at {venv_dir} ...")
        try:
            subprocess.run([python, "-m", "venv", venv_dir], check=True)
        except subprocess.SubprocessError as exc:
            rep.fail(f"Could not create the virtual environment: {exc}")
            return 1
        candidate = os.path.join(venv_dir, "Scripts", "python.exe") if sys.platform == "win32" else os.path.join(venv_dir, "bin", "python")
        if os.path.exists(candidate):
            python = candidate
            rep.ok(f"Using interpreter {python}")
        else:
            rep.fail("Virtual environment created but its interpreter was not found.")
            return 1
    elif sys.prefix == getattr(sys, "base_prefix", sys.prefix):
        rep.warn(
            "You are not in a virtual environment; packages will be installed into the global "
            "interpreter. Pass --venv DIR for an isolated install."
        )

    rep.info("Upgrading pip ...")
    subprocess.run([python, "-m", "pip", "install", "--upgrade", "pip"], check=False)

    if requirements and os.path.exists(requirements):
        rep.info(f"Installing from {requirements} (binary wheels only) ...")
        cmd = [python, "-m", "pip", "install", "--only-binary=:all:", "--no-cache-dir",
               "--force-reinstall", "-r", requirements]
    else:
        rep.info("Installing project dependencies from official wheels ...")
        cmd = [python, "-m", "pip", "install", "--only-binary=:all:", "--no-cache-dir",
               "--force-reinstall", *REPAIR_PACKAGES]

    rep.info("Command: " + " ".join(cmd))
    proc = subprocess.run(cmd)
    if proc.returncode != 0:
        rep.fail(
            "pip could not complete. If it reports a blocked .pyd/.dll again, the Application "
            "Control policy is still active - use the standalone dashboard instead: "
            "python run_dashboard.py --backend standalone"
        )
        return proc.returncode

    rep.ok("Dependencies reinstalled. Re-running the import check ...")
    results = check_imports(rep)
    if find_blocked_modules(results):
        rep.fail("The policy is still blocking the files. Use: python run_dashboard.py --backend standalone")
        return 1
    rep.ok("Imports look healthy. Try: streamlit run dashboard/app.py")
    return 0


# --------------------------------------------------------------------------- #
# Entry point
# --------------------------------------------------------------------------- #


def main(argv: Optional[List[str]] = None) -> int:
    """Run diagnostics (and optionally repair)."""
    parser = argparse.ArgumentParser(
        description=(
            "Diagnose the Windows 'Application Control policy has blocked this file' import "
            "error for pandas/pyarrow and suggest fixes."
        )
    )
    parser.add_argument("--repair", action="store_true", help="Reinstall binary dependencies from wheels.")
    parser.add_argument("--venv", metavar="DIR", help="Create/use a virtual environment at DIR (with --repair).")
    parser.add_argument(
        "--requirements",
        metavar="FILE",
        help="requirements.txt to install during --repair (default: built-in package list).",
    )
    parser.add_argument("--no-color", action="store_true", help="Disable ANSI colours.")
    args = parser.parse_args(argv)

    rep = Reporter(color=not args.no_color)
    rep.header("LAN Scanner - environment diagnostics")
    rep.info("Checks why pandas/Streamlit cannot be imported and what to do about it.")

    describe_environment(rep)
    results = check_imports(rep)
    ci_data = check_code_integrity(rep)
    file_info = check_pandas_files(rep, results)
    print_verdict(rep, results, ci_data, file_info)

    if not args.repair:
        rep.info("Run with --repair to reinstall the binary dependencies from official wheels.")
        print()
        return 0

    return repair(rep, args.venv, args.requirements)


if __name__ == "__main__":
    raise SystemExit(main())
