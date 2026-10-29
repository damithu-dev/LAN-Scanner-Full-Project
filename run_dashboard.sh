#!/usr/bin/env bash
# Start the LAN Scanner web dashboard (Linux / macOS).
# Auto-selects Streamlit when available, otherwise the dependency-free dashboard.
set -euo pipefail
cd "$(dirname "$0")"

if [ -x ".venv/bin/python" ]; then
  PYTHON=".venv/bin/python"
  echo "[*] Using virtual environment: .venv"
else
  PYTHON="${PYTHON:-python3}"
  echo "[!] No .venv found here - using $PYTHON"
fi

exec "$PYTHON" run_dashboard.py "$@"
