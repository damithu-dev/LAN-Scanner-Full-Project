"""One-command launcher for the LAN Scanner web dashboard.

It picks a working web front end automatically:

* **streamlit** - used when ``streamlit`` and ``pandas`` import cleanly. This is
  the richer dashboard (``dashboard/app.py``).
* **standalone** - a dependency-free dashboard built on the Python standard
  library (``dashboard/standalone_server.py``). Used automatically when Streamlit
  cannot import pandas, for example when a Windows Application Control policy
  blocks ``pandas\\_libs\\tslibs\\vectorized.cp3xx-win_amd64.pyd``.

Examples:
    python run_dashboard.py                        # auto-detect, open browser
    python run_dashboard.py --backend standalone   # force the stdlib dashboard
    python run_dashboard.py --backend streamlit     # force Streamlit
    python run_dashboard.py --port 8600 --no-browser
    python run_dashboard.py --diagnose              # explain import problems
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import webbrowser
from typing import List, Optional, Tuple

ROOT = os.path.dirname(os.path.abspath(__file__))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

APP_PATH = os.path.join(ROOT, "dashboard", "app.py")

BLOCK_MARKERS = (
    "application control policy",
    "blocked this file",
    "code integrity",
    "0xc0e90002",
)


def probe_streamlit() -> Tuple[bool, str]:
    """Check Streamlit/pandas importability in a separate process.

    Running the check in a subprocess means a hard crash inside a pandas DLL can
    never take this launcher down with it.

    Returns:
        tuple[bool, str]: (available, human-readable detail/error).
    """
    code = (
        "import pandas, streamlit\n"
        "print('pandas', pandas.__version__, '/ streamlit', streamlit.__version__)\n"
    )
    try:
        proc = subprocess.run(
            [sys.executable, "-c", code],
            capture_output=True,
            text=True,
            timeout=180,
        )
    except subprocess.SubprocessError as exc:
        return False, f"Could not verify Streamlit ({exc})."

    if proc.returncode == 0:
        return True, (proc.stdout or "").strip()

    detail = ((proc.stderr or "") + (proc.stdout or "")).strip()
    lines = [line for line in detail.splitlines() if line.strip()]
    summary = lines[-1] if lines else "unknown import error"
    return False, detail or summary


def is_policy_block(detail: str) -> bool:
    """True when the import failure looks like a Windows code-integrity block."""
    lowered = detail.lower()
    return any(marker in lowered for marker in BLOCK_MARKERS)


def print_block_help() -> None:
    """Explain the Application Control situation and the options."""
    print()
    print("!" * 78)
    print(" Streamlit cannot start because pandas could not be imported.")
    print("!" * 78)
    print("""
 Windows (WDAC / Smart App Control / AppLocker) refused to load a compiled
 pandas extension module - typically
     pandas\\_libs\\tslibs\\vectorized.cp3xx-win_amd64.pyd
 Streamlit imports pandas during its own start-up, so "streamlit run" can never
 work while the policy blocks that file.

 The dashboard you are about to use does NOT need pandas, numpy, pyarrow or
 Streamlit - it runs on the Python standard library only, and has the same
 features (scan controls, progress, host/port table, charts, CVE hints and
 JSON/CSV/XML/HTML/Word report downloads).

 To try to unblock Streamlit later, run:
     python diagnose_windows_env.py
     python diagnose_windows_env.py --repair --venv C:\\Tools\\lan-scanner-venv

 Full explanation and options: FIX_PANDAS_WINDOWS.md
""")


def launch_streamlit(host: str, port: int, open_browser: bool) -> int:
    """Start Streamlit via its CLI in this process."""
    if not os.path.exists(APP_PATH):
        print(f"[!] Streamlit app not found at {APP_PATH}")
        return 1

    from streamlit.web import cli as stcli  # imported lazily on purpose

    argv = [
        "streamlit",
        "run",
        APP_PATH,
        "--server.address",
        host,
        "--server.port",
        str(port),
        "--server.headless",
        "true" if not open_browser else "false",
        "--browser.gatherUsageStats",
        "false",
    ]
    if open_browser and host in ("127.0.0.1", "localhost"):
        import threading
        import time

        def _open() -> None:
            time.sleep(3.0)
            try:
                webbrowser.open(f"http://127.0.0.1:{port}")
            except Exception:
                pass

        threading.Thread(target=_open, daemon=True).start()

    sys.argv = argv
    try:
        stcli.main()
    except SystemExit as exc:  # Streamlit exits with a status code
        return int(exc.code or 0)
    return 0


def launch_standalone(host: str, port: int, open_browser: bool) -> int:
    """Start the dependency-free dashboard."""
    from dashboard.standalone_server import main as standalone_main

    argv: List[str] = ["--host", host, "--port", str(port), "--auto-port"]
    if not open_browser:
        argv.append("--no-browser")
    return standalone_main(argv)


def run_diagnostics() -> int:
    """Run the environment diagnostics script."""
    try:
        from diagnose_windows_env import main as diagnose_main
    except ImportError as exc:
        print(f"[!] Diagnostics module unavailable: {exc}", file=sys.stderr)
        return 1
    return diagnose_main([])


def main(argv: Optional[List[str]] = None) -> int:
    """Resolve the requested backend and start it."""
    parser = argparse.ArgumentParser(
        description="Start the LAN Scanner web dashboard (auto-selects a backend).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--backend",
        choices=["auto", "streamlit", "standalone"],
        default="auto",
        help="Which web front end to use (default: auto).",
    )
    parser.add_argument("--host", default="0.0.0.0", help="Interface to bind (default: 0.0.0.0).")
    parser.add_argument("--port", type=int, default=8501, help="Port to listen on (default: 8501).")
    parser.add_argument("--no-browser", action="store_true", help="Do not open a browser window.")
    parser.add_argument("--diagnose", action="store_true", help="Run environment diagnostics and exit.")
    args = parser.parse_args(argv)

    if args.diagnose:
        return run_diagnostics()

    open_browser = not args.no_browser

    if args.backend == "standalone":
        print("[*] Dashboard backend: standalone (Python standard library only).")
        return launch_standalone(args.host, args.port, open_browser)

    if args.backend == "streamlit":
        available, detail = probe_streamlit()
        if not available:
            if is_policy_block(detail):
                print_block_help()
            else:
                print("[!] Streamlit/pandas are not usable in this Python environment:")
                print("    " + detail.replace("\n", "\n    "))
                print("\n    Run: python diagnose_windows_env.py")
                print("    Or:  python run_dashboard.py --backend standalone")
            return 1
        print(f"[*] Dashboard backend: streamlit ({detail}).")
        return launch_streamlit(args.host, args.port, open_browser)

    # auto
    available, detail = probe_streamlit()
    if available:
        print(f"[*] Dashboard backend: streamlit ({detail}).")
        return launch_streamlit(args.host, args.port, open_browser)

    if is_policy_block(detail):
        print_block_help()
    else:
        print("[!] Streamlit is not available here; falling back to the dependency-free dashboard.")
        lines = [line for line in (detail or "").splitlines() if line.strip()]
        print("    Reason: " + (lines[-1] if lines else "unknown"))

    print("[*] Dashboard backend: standalone (Python standard library only).")
    return launch_standalone(args.host, args.port, open_browser)


if __name__ == "__main__":
    raise SystemExit(main())
