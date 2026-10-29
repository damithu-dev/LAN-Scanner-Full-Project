"""Dependency-free web dashboard for the LAN Scanner (standard library only).

Why this exists
---------------
The original dashboard is built on Streamlit, and **Streamlit itself imports
pandas at start-up** (``streamlit.type_util`` imports ``pyarrow``/``pandas`` for
dataframe handling). If a Windows Application Control policy blocks a pandas
compiled DLL - e.g. ``pandas/_libs/tslibs/vectorized.cp312-win_amd64.pyd`` - then
``streamlit run`` can never start, no matter what ``app.py`` does.

This module renders the same workflow - configure a scan, watch progress, review
hosts/ports/CVEs, download reports - using only ``http.server``, ``json`` and
plain HTML/CSS/JS. No pandas, no numpy, no Streamlit, no pyarrow.

Usage:
    python -m dashboard.standalone_server --port 8501
    python run_dashboard.py --backend standalone
"""

from __future__ import annotations

import argparse
import json
import os
import socket
import sys
import tempfile
import threading
import time
import traceback
import uuid
import webbrowser
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qs, urlparse

# Make "import scanner", "import exporters" work when executed as a script.
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from dashboard.scan_job import (  # noqa: E402  (path bootstrap must run first)
    ScanConfig,
    collect_cves,
    environment_info,
    flatten_hosts,
    risk_summary,
    run_scan,
    service_summary,
    summarize,
)
from scanner.models import Host  # noqa: E402

STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")
INDEX_PATH = os.path.join(STATIC_DIR, "index.html")

# Keep a bounded history so a long session cannot leak memory.
MAX_JOBS = 8

EXPORT_FORMATS = ("json", "csv", "xml", "html", "docx")

_MIME_TYPES = {
    "json": ("application/json", "lan_scan_report.json"),
    "csv": ("text/csv", "lan_scan_report.csv"),
    "xml": ("application/xml", "lan_scan_report.xml"),
    "html": ("text/html", "lan_scan_report.html"),
    "docx": (
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "lan_scan_detailed_report.docx",
    ),
}


# --------------------------------------------------------------------------- #
# Jobs
# --------------------------------------------------------------------------- #


@dataclass
class ScanJob:
    """A single background scan and its observable state."""

    job_id: str
    config: ScanConfig
    status: str = "running"  # running | done | error | cancelled
    message: str = "Starting..."
    progress: float = 0.0
    error: Optional[str] = None
    warnings: List[str] = field(default_factory=list)
    hosts: List[Host] = field(default_factory=list)
    elapsed: float = 0.0
    created_at: float = field(default_factory=time.time)
    cancel_event: threading.Event = field(default_factory=threading.Event)

    # -- serialization ---------------------------------------------------- #

    def status_payload(self) -> Dict[str, Any]:
        """Lightweight payload polled by the browser while the scan runs.

        Results are included once the job is finished - including a cancelled
        scan, so partial findings stay available in the UI.
        """
        has_results = bool(self.hosts) and self.status in ("done", "cancelled")
        payload: Dict[str, Any] = {
            "job_id": self.job_id,
            "status": self.status,
            "message": self.message,
            "progress": round(self.progress, 4),
            "error": self.error,
            "warnings": self.warnings,
            "elapsed": round(self.elapsed, 2),
            "config": self.config.to_dict(),
            "has_results": has_results,
        }
        if has_results:
            payload["summary"] = summarize(self.hosts)
            payload["services"] = service_summary(self.hosts)
            rows = flatten_hosts(self.hosts)
            payload["risks"] = risk_summary(rows)
            payload["hosts"] = [h.to_dict() for h in self.hosts]
            payload["rows"] = rows
            payload["cves"] = collect_cves(self.hosts)
        return payload

    # -- execution -------------------------------------------------------- #

    def _on_progress(self, message: str, fraction: float) -> None:
        self.message = message
        self.progress = fraction

    def _should_cancel(self) -> bool:
        return self.cancel_event.is_set()

    def run(self) -> None:
        """Blocking scan body; executed on a worker thread."""
        try:
            outcome = run_scan(self.config, self._on_progress, self._should_cancel)
            self.hosts = outcome.hosts
            self.warnings = outcome.warnings
            self.elapsed = outcome.elapsed
            if outcome.error:
                self.status = "error"
                self.error = outcome.error
                self.message = "Scan could not be completed."
            elif outcome.cancelled:
                self.status = "cancelled"
                self.message = "Scan cancelled."
            else:
                self.status = "done"
                self.message = "Scan completed."
                self.progress = 1.0
        except Exception as exc:  # pragma: no cover - defensive
            self.status = "error"
            self.error = f"{type(exc).__name__}: {exc}"
            self.message = "Unexpected error during scan."
            traceback.print_exc()


class JobManager:
    """Thread-safe registry of scan jobs."""

    def __init__(self, max_jobs: int = MAX_JOBS) -> None:
        self._jobs: Dict[str, ScanJob] = {}
        self._order: List[str] = []
        self._lock = threading.Lock()
        self._max_jobs = max_jobs
        self._active: Optional[ScanJob] = None

    def active_job(self) -> Optional[ScanJob]:
        """Return the most recent job if it is still running."""
        with self._lock:
            job = self._active
            if job is not None and job.status == "running":
                return job
            return None

    def start(self, config: ScanConfig) -> ScanJob:
        """Create a job and start it on a daemon thread."""
        running = self.active_job()
        if running is not None:
            raise RuntimeError("A scan is already running. Wait for it to finish or cancel it first.")

        job = ScanJob(job_id=uuid.uuid4().hex[:12], config=config)
        with self._lock:
            self._jobs[job.job_id] = job
            self._order.append(job.job_id)
            while len(self._order) > self._max_jobs:
                oldest = self._order.pop(0)
                self._jobs.pop(oldest, None)
            self._active = job

        thread = threading.Thread(target=job.run, name=f"scan-{job.job_id}", daemon=True)
        thread.start()
        return job

    def get(self, job_id: str) -> Optional[ScanJob]:
        """Look up a job by id."""
        with self._lock:
            return self._jobs.get(job_id)

    def latest(self) -> Optional[ScanJob]:
        """Return the most recently started job."""
        with self._lock:
            if not self._order:
                return None
            return self._jobs.get(self._order[-1])


# --------------------------------------------------------------------------- #
# Export helpers (lazy imports so missing optional deps cannot break the app)
# --------------------------------------------------------------------------- #


def build_export(job: ScanJob, fmt: str) -> tuple:
    """Render a report for ``job`` in ``fmt``.

    Returns:
        tuple[bytes, str, str]: (payload, content-type, suggested filename)

    Raises:
        ValueError: For an unsupported format.
        RuntimeError: When an optional dependency for that format is missing.
    """
    fmt = fmt.lower().strip()
    if fmt not in EXPORT_FORMATS:
        raise ValueError(f"Unsupported export format '{fmt}'.")
    mime, filename = _MIME_TYPES[fmt]
    hosts = job.hosts
    target = job.config.target or "Not recorded"

    if fmt == "json":
        from exporters.json_exporter import export_json

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as handle:
            path = handle.name
        try:
            export_json(hosts, path, target=target, scan_time=job.elapsed)
            with open(path, "rb") as handle:
                return handle.read(), mime, filename
        finally:
            _safe_remove(path)

    if fmt == "csv":
        from exporters.csv_exporter import export_csv

        with tempfile.NamedTemporaryFile(suffix=".csv", delete=False) as handle:
            path = handle.name
        try:
            export_csv(hosts, path)
            with open(path, "rb") as handle:
                return handle.read(), mime, filename
        finally:
            _safe_remove(path)

    if fmt == "xml":
        from exporters.xml_exporter import export_xml

        with tempfile.NamedTemporaryFile(suffix=".xml", delete=False) as handle:
            path = handle.name
        try:
            export_xml(hosts, path, target=target, scan_time=job.elapsed)
            with open(path, "rb") as handle:
                return handle.read(), mime, filename
        finally:
            _safe_remove(path)

    if fmt == "html":
        from exporters.html_exporter import export_html

        with tempfile.NamedTemporaryFile(suffix=".html", delete=False) as handle:
            path = handle.name
        try:
            export_html(hosts, path, target=target, scan_time=job.elapsed)
            with open(path, "rb") as handle:
                return handle.read(), mime, filename
        finally:
            _safe_remove(path)

    # fmt == "docx"
    try:
        from exporters.word_exporter import export_word_report
    except ImportError as exc:  # pragma: no cover - depends on environment
        raise RuntimeError(
            "The Word report needs the 'python-docx' package. Install it with: "
            "python -m pip install python-docx"
        ) from exc

    with tempfile.NamedTemporaryFile(suffix=".docx", delete=False) as handle:
        path = handle.name
    try:
        export_word_report(
            hosts,
            path,
            target=target,
            scan_time=job.elapsed,
            scan_mode=job.config.scan_mode,
            port_selection=job.config.port_selection,
        )
        with open(path, "rb") as handle:
            return handle.read(), mime, filename
    finally:
        _safe_remove(path)


def _safe_remove(path: str) -> None:
    try:
        if path and os.path.exists(path):
            os.remove(path)
    except OSError:  # pragma: no cover
        pass


# --------------------------------------------------------------------------- #
# HTTP layer
# --------------------------------------------------------------------------- #


class DashboardHandler(BaseHTTPRequestHandler):
    """Route requests for the single-page dashboard and its JSON API."""

    server_version = "LANScannerDashboard/2.0"
    jobs: JobManager = JobManager()  # replaced per server instance in make_server

    # -- utilities -------------------------------------------------------- #

    def log_message(self, fmt: str, *args: Any) -> None:  # noqa: A003
        """Quieter, timestamped request log."""
        sys.stderr.write(f"[dashboard] {self.address_string()} - {fmt % args}\n")

    def _send(self, status: int, body: bytes, content_type: str, extra: Optional[Dict[str, str]] = None) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        for key, value in (extra or {}).items():
            self.send_header(key, value)
        self.end_headers()
        if self.command != "HEAD":
            try:
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError):  # pragma: no cover
                pass

    def _send_json(self, status: int, payload: Dict[str, Any]) -> None:
        body = json.dumps(payload, default=str).encode("utf-8")
        self._send(status, body, "application/json; charset=utf-8")

    def _read_json(self) -> Dict[str, Any]:
        try:
            length = int(self.headers.get("Content-Length", "0") or 0)
        except ValueError:
            length = 0
        if length <= 0:
            return {}
        raw = self.rfile.read(length)
        try:
            data = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return {}
        return data if isinstance(data, dict) else {}

    # -- verbs ------------------------------------------------------------ #

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"
        query = parse_qs(parsed.query)

        if path in ("/", "/index.html"):
            self._serve_index()
        elif path == "/healthz":
            self._send(200, b"ok", "text/plain; charset=utf-8")
        elif path == "/api/config":
            self._send_json(200, environment_info())
        elif path == "/api/job":
            self._handle_job(query)
        elif path == "/api/export":
            self._handle_export(query)
        elif path == "/favicon.ico":
            self._send(204, b"", "image/x-icon")
        else:
            self._send_json(404, {"error": f"Not found: {path}"})

    def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"

        if path == "/api/scan":
            self._handle_scan_start()
        elif path == "/api/cancel":
            self._handle_cancel()
        else:
            self._send_json(404, {"error": f"Not found: {path}"})

    # -- handlers --------------------------------------------------------- #

    def _serve_index(self) -> None:
        try:
            with open(INDEX_PATH, "rb") as handle:
                body = handle.read()
        except OSError:
            body = (
                "<h1>LAN Scanner Dashboard</h1><p>The file "
                f"<code>{INDEX_PATH}</code> is missing. Re-download the project.</p>"
            ).encode("utf-8")
        self._send(200, body, "text/html; charset=utf-8")

    def _handle_job(self, query: Dict[str, List[str]]) -> None:
        job_id = (query.get("id") or [""])[0]
        if job_id:
            job = self.jobs.get(job_id)
        else:
            job = self.jobs.latest()
        if job is None:
            self._send_json(404, {"error": "No scan found. Start a scan first."})
            return
        self._send_json(200, job.status_payload())

    def _handle_scan_start(self) -> None:
        data = self._read_json()
        config = ScanConfig.from_mapping(data)
        if not config.target:
            self._send_json(
                400,
                {"error": "Please enter a device or network to check (the target is empty)."},
            )
            return
        try:
            job = self.jobs.start(config)
        except RuntimeError as exc:
            self._send_json(409, {"error": str(exc)})
            return
        self._send_json(202, {"job_id": job.job_id, "status": job.status})

    def _handle_cancel(self) -> None:
        job = self.jobs.active_job()
        if job is None:
            self._send_json(404, {"error": "No scan is currently running."})
            return
        job.cancel_event.set()
        job.message = "Cancelling..."
        self._send_json(200, {"job_id": job.job_id, "status": "cancelling"})

    def _handle_export(self, query: Dict[str, List[str]]) -> None:
        fmt = (query.get("fmt") or [""])[0]
        job_id = (query.get("id") or [""])[0]
        job = self.jobs.get(job_id) if job_id else self.jobs.latest()
        if job is None:
            self._send_json(404, {"error": "No scan found to export."})
            return
        if job.status != "done" and not job.hosts:
            self._send_json(409, {"error": "The scan has not produced results yet."})
            return
        try:
            payload, mime, filename = build_export(job, fmt)
        except ValueError as exc:
            self._send_json(400, {"error": str(exc)})
            return
        except RuntimeError as exc:
            self._send_json(503, {"error": str(exc)})
            return
        except Exception as exc:  # pragma: no cover - defensive
            self._send_json(500, {"error": f"Export failed: {type(exc).__name__}: {exc}"})
            return
        self._send(
            200,
            payload,
            mime,
            {"Content-Disposition": f'attachment; filename="{filename}"'},
        )


def make_server(host: str = "0.0.0.0", port: int = 8501) -> ThreadingHTTPServer:
    """Create (but do not start) the dashboard HTTP server."""
    handler = type("BoundDashboardHandler", (DashboardHandler,), {"jobs": JobManager()})
    server = ThreadingHTTPServer((host, port), handler)
    server.daemon_threads = True
    return server


def _port_is_free(host: str, port: int) -> bool:
    probe_host = "127.0.0.1" if host in ("0.0.0.0", "") else host
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind((probe_host, port))
            return True
        except OSError:
            return False


def find_free_port(host: str, start_port: int, attempts: int = 20) -> int:
    """Return the first free port at or after ``start_port``."""
    for offset in range(attempts):
        candidate = start_port + offset
        if _port_is_free(host, candidate):
            return candidate
    raise OSError(f"No free port found in range {start_port}-{start_port + attempts - 1}.")


def main(argv: Optional[List[str]] = None) -> int:
    """CLI entry point for the standalone dashboard."""
    parser = argparse.ArgumentParser(
        description="Dependency-free LAN Scanner web dashboard (no pandas/Streamlit required).",
    )
    parser.add_argument("--host", default="0.0.0.0", help="Interface to bind (default: 0.0.0.0).")
    parser.add_argument("--port", type=int, default=8501, help="Port to listen on (default: 8501).")
    parser.add_argument("--no-browser", action="store_true", help="Do not open a browser window.")
    parser.add_argument("--auto-port", action="store_true", help="Pick the next free port if the requested one is busy.")
    args = parser.parse_args(argv)

    port = args.port
    if not _port_is_free(args.host, port):
        if args.auto_port:
            port = find_free_port(args.host, port)
            print(f"[!] Port {args.port} is busy - using {port} instead.")
        else:
            print(f"[!] Port {port} is already in use. Try: --port {port + 1} (or --auto-port)")
            return 1

    server = make_server(host=args.host, port=port)
    url = f"http://127.0.0.1:{port}"

    print("=" * 70)
    print(" LAN Scanner - Web Dashboard (dependency-free edition)")
    print("=" * 70)
    print(f" Open in your browser: {url}")
    print(" Uses only the Python standard library: no pandas, no Streamlit.")
    if args.host not in ("127.0.0.1", "localhost"):
        print(f" Also reachable on your network at http://<this-machine-ip>:{port}")
        print(" Note: this dashboard has no login, so only run it on networks you trust")
        print("       (use --host 127.0.0.1 to restrict it to this computer).")
    print(" Press CTRL+C to stop the server.")
    print("=" * 70)

    if not args.no_browser:
        def _open() -> None:
            time.sleep(0.6)
            try:
                webbrowser.open(url)
            except Exception:  # pragma: no cover
                pass

        threading.Thread(target=_open, daemon=True).start()

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[dashboard] Shutting down.")
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
