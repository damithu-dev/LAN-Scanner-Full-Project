@echo off
REM ---------------------------------------------------------------------------
REM  LAN Scanner - start the web dashboard on Windows.
REM
REM  Double-click this file. It activates the local virtual environment (if one
REM  exists next to this script), then starts the dashboard. If pandas/Streamlit
REM  are blocked by an Application Control policy, the launcher automatically
REM  switches to the dependency-free dashboard, which needs no pandas at all.
REM ---------------------------------------------------------------------------

setlocal
cd /d "%~dp0"

set "PYTHON=python"

if exist ".venv\Scripts\python.exe" (
    set "PYTHON=.venv\Scripts\python.exe"
    echo [*] Using virtual environment: .venv
) else (
    echo [!] No .venv found here - using the system Python.
    echo     To create one: python -m venv .venv ^&^& .venv\Scripts\activate
)

echo [*] Starting the LAN Scanner dashboard...
"%PYTHON%" run_dashboard.py %*

echo.
echo [*] The dashboard has stopped. Press any key to close this window.
pause >nul
endlocal
