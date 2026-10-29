# LAN Scanner & Active Port Scanner

[![Python Version](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-72%20passed-success.svg)](tests/)
[![Security Boundaries](https://img.shields.io/badge/safety-RFC%201918%20Restricted-red.svg)](utils/safety.py)

An educational network reconnaissance and port auditing tool developed in Python. Discovers active endpoints across local IPv4 subnets, determines open TCP/UDP ports, grabs service banners, flags known vulnerability (CVE) signatures, and provides multi-format reporting and an interactive web dashboard.

> **IMPORTANT**: This software is designed exclusively for authorized penetration testing, educational laboratories, and home network administration. Unauthorized scanning violates network policies and local legislation.

---

## Key Features

- **Layer 2 ARP Sweep**: Fast broadcast enumeration across `/24` subnets with MAC address extraction and local IEEE OUI manufacturer resolution.
- **Multithreaded TCP Connect Probing**: Non-privileged 3-way handshake probing utilizing `concurrent.futures.ThreadPoolExecutor` with thread-safe result queuing.
- **TCP SYN Half-Open Stealth Scanning**: Raw Layer 3/4 packet crafting using Scapy with automated fallback to TCP connect mode on unprivileged systems.
- **UDP Scanning with Payloads**: Connectionless probing utilizing tailored request payloads for DNS (53), TFTP (69), NTP (123), SNMP (161), and NetBIOS (137) with ICMP port unreachable error trapping.
- **Service & Banner Detection**: Protocol identification and banner grabbing for HTTP/HTTPS, SSH, FTP, SMTP, and Redis with ANSI escape sequence sanitization.
- **Offline Vulnerability (CVE) Hints**: Signature-based matching against high-impact flaws (vsftpd 2.3.4 backdoor, OpenSSH RegreSSHion, Apache path traversal) with remediation fixes.
- **Built-in Safety Guardrails**: Public IP address blocking by default, packet rate limiting (`--max-pps`), and startup authorization notices.
- **Multi-Format Exporters**: Output export to structured JSON, flat CSV spreadsheets, Nmap-compatible XML, and self-contained interactive HTML reports.
- **Interactive Web Dashboard**: Streamlit graphical interface with real-time progress bars, open port charts, risk distribution graphs, and download buttons.
- **Isolated Practice Lab**: Docker Compose multi-service environment (Nginx, Redis, PostgreSQL, vsftpd).

---

## Project Structure

```text
├── dashboard/
│   ├── __init__.py
│   ├── app.py                  # Streamlit graphical web application
│   ├── scan_job.py             # Shared, UI-independent scan orchestration
│   ├── standalone_server.py    # Dependency-free web dashboard (stdlib only)
│   └── static/
│       └── index.html          # Standalone dashboard front end
├── docs/                       # Project documentation & user manuals
├── exporters/
│   ├── __init__.py
│   ├── csv_exporter.py         # CSV tabular export engine
│   ├── html_exporter.py        # Standalone responsive HTML dashboard export
│   ├── json_exporter.py        # Structured JSON export engine
│   └── xml_exporter.py         # Nmap-compliant DTD XML export engine
├── lab/
│   ├── docker-compose.yml      # Isolated 4-container multi-service lab
│   └── README.md               # Lab execution instructions
├── scanner/
│   ├── __init__.py
│   ├── banner.py               # Banner grabber, sanitizer & regex parser
│   ├── concurrent_scan.py      # Multithreaded scan engine with rate limiter
│   ├── cve_lookup.py           # Offline CVE signature matching engine
│   ├── data/
│   │   └── cve_database.json   # Curated CVE signature registry
│   ├── host_discovery.py       # Layer 2 ARP sweep & OUI manufacturer table
│   ├── models.py               # Host and PortResult dataclass models
│   ├── port_probe.py           # TCP Connect probe engine
│   ├── stealth.py              # TCP SYN half-open raw socket prober
│   └── udp_probe.py            # UDP payload prober with ICMP error handler
├── tests/
│   ├── __init__.py
│   ├── test_phase1.py          # Models, network utilities & safety tests
│   ├── test_phase2.py          # Port list parser, TCP connect & thread tests
│   ├── test_phase3.py          # Banner sanitization & regex parser tests
│   ├── test_phase4.py          # Stealth SYN & UDP payload tests
│   ├── test_phase5.py          # JSON, CSV, XML, HTML exporters & UI tests
│   ├── test_phase6.py          # CVE lookup & false-positive verification tests
│   └── test_phase7.py          # Streamlit dashboard tests
├── ui/
│   ├── __init__.py
│   └── terminal.py             # Rich formatting, color palettes & summary boxes
├── utils/
│   ├── __init__.py
│   ├── network.py              # Local IP, interface & subnet auto-detection
│   ├── ports.py                # Port string parser, Top-100 & Top-1000 lists
│   └── safety.py               # Boundary verification & token-bucket rate limiter
├── build_executable.py         # PyInstaller standalone executable builder
├── run_dashboard.py            # Web dashboard launcher (auto-selects backend)
├── run_dashboard.bat           # Windows one-click launcher
├── run_dashboard.sh            # Linux/macOS launcher
├── diagnose_windows_env.py     # Explains/repairs blocked pandas DLL errors
├── FIX_PANDAS_WINDOWS.md       # Application Control / DLL troubleshooting guide
├── main.py                     # Command-line interface entry point
├── requirements.txt            # Python dependencies
└── README.md                   # Project documentation
```

---

## Installation & Setup

### Requirements
- **Python**: Version 3.10 or higher.
- **Windows**: [Npcap](https://npcap.com/) (required for Layer 2 ARP sweeps and Layer 3/4 raw TCP SYN packets). If Npcap is absent, the tool automatically falls back to OS ARP cache inspection and non-privileged TCP Connect probing.
- **Linux**: Standard `libpcap` library (`sudo apt install libpcap-dev`).

### 1. Clone or Extract the Project
```bash
git clone <repository_url>
cd <project_directory>
```

### 2. Set Up a Python Virtual Environment
#### On Windows:
```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
```

#### On Linux / macOS:
```bash
python3 -m venv venv
source venv/bin/activate
```

### 3. Install Dependencies
```bash
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

---

## Command-Line Usage (`main.py`)

Run the scanner directly using `python main.py [OPTIONS]`:

```text
options:
  -h, --help            show this help message and exit
  -t, --target TARGET   Target IP (e.g. 192.168.1.1) or CIDR subnet (e.g. 192.168.1.0/24).
  -p, --ports PORTS     Ports to scan: single (80), list (22,80,443), or range (1-1024).
  --top100              Scan the top 100 most common TCP ports (default).
  --top1000             Scan the top 1000 common TCP ports.
  --timeout TIMEOUT     Per-socket connection timeout in seconds (default: 1.0s).
  --threads THREADS     Maximum concurrent probe threads (default: 100, capped at 500).
  --interface INTERFACE Explicit network interface identifier to utilize for scanning.
  --max-pps MAX_PPS     Rate limit: maximum packets/probes per second (0 = unthrottled).
  --allow-public        Explicit safety override to permit scanning public IP addresses.
  --arp-only            Discover active hosts using ARP without launching port probes.
  --no-banners          Skip service banner grabbing on discovered open ports.
  -sS, --stealth        Perform TCP SYN (half-open) stealth scan (requires admin/root).
  -sU, --udp            Perform UDP port scan with service payloads (DNS, NTP, SNMP).
  --show-all            Display all ports (including closed/filtered) in results table.

Report Exporters:
  --json JSON_FILE      Export scan results to specified JSON file path.
  --csv CSV_FILE        Export scan results to specified CSV spreadsheet file path.
  --xml XML_FILE        Export scan results to Nmap-compatible XML file path.
  --html HTML_FILE      Export scan results to standalone interactive HTML report path.
```

### 5 Copy-Paste Example Commands

#### 1. Auto-Detect and Sweep the Local Subnet:
```bash
python main.py
```

#### 2. Fast Scan on Localhost for Web & Admin Ports:
```bash
python main.py -t 127.0.0.1 -p 80,443,8080,3306,5432 --timeout 0.5
```

#### 3. Scan Common Top 100 Ports with Rate Limiting (Paced at 50 packets/sec):
```bash
python main.py -t 192.168.1.1 --top100 --max-pps 50 --threads 20
```

#### 4. Stealth TCP SYN Scan with All Export Formats Enabled:
```bash
python main.py -t 192.168.1.50 -p 1-1024 --stealth --json report.json --csv report.csv --xml report.xml --html report.html
```

#### 5. UDP Audit for Core Network Services (DNS, NTP, SNMP):
```bash
python main.py -t 192.168.1.1 -p 53,123,161 --udp --timeout 1.5
```

---

## Interactive Web Dashboard

There are two interchangeable web dashboards that share the same scan engine
(`dashboard/scan_job.py`):

| Backend | Start it with | Dependencies |
| --- | --- | --- |
| **Standalone (recommended default)** | `python run_dashboard.py --backend standalone` | Python standard library only — no pandas, no numpy, no Streamlit |
| **Streamlit** | `python run_dashboard.py --backend streamlit` (or `streamlit run dashboard/app.py`) | `streamlit` (which pulls in pandas/pyarrow) |

`python run_dashboard.py` with no arguments tests the environment and picks a
backend automatically. On Windows you can simply double-click **`run_dashboard.bat`**;
on Linux/macOS use `./run_dashboard.sh`.

Both front ends are served at `http://localhost:8501` and provide real-time
parameter tuning, a progress bar, a sortable/filterable host-and-port table, bar
charts of open services and risk levels, vulnerability hint cards, and one-click
JSON / CSV / XML / HTML / Word report downloads.

### Why a second dashboard exists

Streamlit imports pandas during its own start-up. On managed Windows machines an
Application Control policy (Smart App Control / WDAC / AppLocker) can block a
compiled pandas file:

```
ImportError: DLL load failed while importing vectorized:
An Application Control policy has blocked this file.
```

That makes `streamlit run` impossible to start — it fails before any project code
runs. The standalone dashboard has no such dependency, so the web UI keeps working
on those machines. See **[FIX_PANDAS_WINDOWS.md](FIX_PANDAS_WINDOWS.md)** for the
full explanation, the diagnostic tool (`python diagnose_windows_env.py`), and the
repair options.

---

## Running the Practice Lab (`lab/`)

An isolated Docker Compose environment is provided to safely test against real services:

```bash
# Start lab services
docker compose -f lab/docker-compose.yml up -d

# Scan exposed lab services
python main.py -t 127.0.0.1 -p 2121,5432,6379,8080

# Tear down lab
docker compose -f lab/docker-compose.yml down
```

---

## Automated Testing & Coverage

Run the comprehensive pytest suite:

```bash
python -m pytest -v --cov=scanner --cov=utils --cov=exporters --cov=ui --cov=dashboard
```

**Real Test Suite Metric**: 101 automated unit tests across 7 phases plus the
standalone-dashboard suite, running with 0 failures. The dashboard tests run with no
third-party packages installed at all, which proves the pandas-free path works.

---

## Compiling Standalone Executable (PyInstaller)

To build a standalone Windows `.exe` or Linux binary:

```bash
python build_executable.py
```
The compiled single-file binary will be generated in `dist/lan_scanner.exe`.

## Beginner-friendly dashboard and Word report

Install dependencies from the project root:

```bash
python -m venv .venv
.venv\Scripts\activate
python -m pip install -r requirements.txt
```

Start the web dashboard (auto-selects a working backend):

```bash
python run_dashboard.py
```

If you see `ImportError: DLL load failed while importing vectorized: An
Application Control policy has blocked this file`, that is a Windows security
policy blocking pandas — **not** a bug in this project. Run the pandas-free
dashboard instead, and see [FIX_PANDAS_WINDOWS.md](FIX_PANDAS_WINDOWS.md):

```bash
python run_dashboard.py --backend standalone
python diagnose_windows_env.py          # explains the policy block
```

The Word report (.docx) download needs the optional `python-docx` package:

```bash
python -m pip install python-docx
```

Open the local URL printed by Streamlit (usually http://localhost:8501). Run a scan only against devices or networks you own or have explicit permission to assess. After a scan, open **Download Your Report** and choose **Download Word Report** for a detailed `.docx` report written for non-technical readers. It includes a plain-language summary, explanations of terms, device-by-device port results, possible vulnerability hints, recommended next steps, and scope/limitations.

CVE entries are hints based on available service information, not confirmation that a device is vulnerable. An open port is not automatically a security issue, and no findings do not guarantee that a device is secure.
