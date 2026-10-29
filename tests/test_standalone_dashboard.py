"""Tests for the dependency-free dashboard and the shared scan core.

These tests must pass with **no third-party packages installed at all** (no
pandas, no numpy, no Streamlit), which is exactly the environment a Windows
Application Control policy creates.
"""

import json
import threading
import time
import urllib.error
import urllib.request
from unittest.mock import MagicMock

import pytest

from dashboard import scan_job
from dashboard.scan_job import (
    ARP_MODE,
    CUSTOM_SELECTION,
    SCAN_MODES,
    TOP_100_SELECTION,
    ScanConfig,
    collect_cves,
    flatten_hosts,
    port_risk_level,
    resolve_ports,
    risk_summary,
    run_scan,
    service_summary,
    summarize,
)
from scanner.models import Host, PortResult


# --------------------------------------------------------------------------- #
# Fixtures
# --------------------------------------------------------------------------- #


def _sample_hosts():
    """Two hosts: one with an open port carrying a CVE, one with no ports."""
    web = Host(ip="192.168.1.10", mac="AA:BB:CC:DD:EE:FF", vendor="Test Vendor")
    web.add_port(
        PortResult(
            port=22,
            protocol="tcp",
            state="OPEN",
            service="OpenSSH",
            banner="SSH-2.0-OpenSSH_8.9",
            cve_list=[{"cve_id": "CVE-2024-6387", "severity": "HIGH", "cvss": 8.1}],
        )
    )
    web.add_port(PortResult(port=80, protocol="tcp", state="CLOSED", service="http"))
    idle = Host(ip="192.168.1.11")
    return [web, idle]


# --------------------------------------------------------------------------- #
# scan_job unit tests
# --------------------------------------------------------------------------- #


def test_scan_config_from_mapping_coerces_untrusted_values():
    """HTTP JSON bodies must never crash the engine with bad types."""
    config = ScanConfig.from_mapping(
        {
            "target": "  192.168.1.0/24 ",
            "threads": "25",
            "timeout": "0.5",
            "max_pps": "abc",
            "grab_banners": "false",
            "allow_public": 0,
            "unknown_key": "ignored",
        }
    )
    assert config.target == "192.168.1.0/24"
    assert config.threads == 25
    assert config.timeout == 0.5
    assert config.max_pps == 0  # invalid int falls back to default
    assert config.grab_banners is False
    assert config.allow_public is False


def test_scan_config_defaults_are_valid():
    """Empty input should still produce a usable config object."""
    config = ScanConfig.from_mapping({})
    assert config.target == ""
    assert config.scan_mode in SCAN_MODES
    assert config.port_selection == TOP_100_SELECTION


def test_resolve_ports_modes():
    """Port resolution covers top-100, custom lists and the ARP-only mode."""
    assert len(resolve_ports(ScanConfig(target="1.2.3.4"))) == len(scan_job.TOP_100_PORTS)
    custom = resolve_ports(
        ScanConfig(target="1.2.3.4", port_selection=CUSTOM_SELECTION, custom_ports="22,80,100-102")
    )
    assert custom == [22, 80, 100, 101, 102]
    assert resolve_ports(ScanConfig(target="1.2.3.4", scan_mode=ARP_MODE)) == []


def test_resolve_ports_rejects_garbage():
    """An unparsable custom port string raises ValueError (handled by run_scan)."""
    with pytest.raises(ValueError):
        resolve_ports(
            ScanConfig(target="1.2.3.4", port_selection=CUSTOM_SELECTION, custom_ports="http")
        )


def test_port_risk_level_prefers_highest_severity():
    """CVE severities dominate the risk label; plain open ports are LOW."""
    critical = PortResult(port=1, state="OPEN", cve_list=[{"severity": "HIGH"}, {"severity": "CRITICAL"}])
    high = PortResult(port=2, state="OPEN", cve_list=[{"severity": "high"}])
    open_only = PortResult(port=3, state="OPEN")
    closed = PortResult(port=4, state="CLOSED")

    assert port_risk_level(critical) == "CRITICAL"
    assert port_risk_level(high) == "HIGH"
    assert port_risk_level(open_only) == "LOW"
    assert port_risk_level(closed) == "INFORMATIONAL"


def test_flatten_hosts_produces_plain_dict_rows():
    """The table data is plain Python - no DataFrame library involved."""
    rows = flatten_hosts(_sample_hosts())
    assert isinstance(rows, list)
    assert all(isinstance(row, dict) for row in rows)
    assert len(rows) == 3  # two ports on host 1, one synthetic row for host 2
    assert rows[0]["ip"] == "192.168.1.10"
    assert rows[0]["risk"] == "HIGH"
    assert rows[-1]["state"] == "UP (Host Active)"
    assert rows[-1]["port"] == "-"


def test_flatten_hosts_does_not_import_pandas():
    """Guard against a regression that reintroduces the pandas dependency."""
    flatten_hosts(_sample_hosts())
    import sys

    assert "pandas" not in sys.modules


def test_service_and_risk_summaries():
    """Chart data is plain dicts, ordered for display."""
    hosts = _sample_hosts()
    services = service_summary(hosts)
    assert services == {"OpenSSH (22)": 1}

    risks = risk_summary(flatten_hosts(hosts))
    assert list(risks.keys())[0] == "HIGH"  # severity order is preserved
    assert risks["HIGH"] == 1
    assert risks["INFORMATIONAL"] == 2


def test_collect_cves_annotates_location():
    """CVE findings carry the host/port they were observed on."""
    findings = collect_cves(_sample_hosts())
    assert len(findings) == 1
    assert findings[0]["cve_id"] == "CVE-2024-6387"
    assert findings[0]["ip"] == "192.168.1.10"
    assert findings[0]["port"] == 22


def test_summarize_counts():
    """KPI numbers match the sample data."""
    stats = summarize(_sample_hosts())
    assert stats["hosts"] == 2
    assert stats["open_ports"] == 1
    assert stats["alerts"] == 1
    assert stats["critical"] == 0


# --------------------------------------------------------------------------- #
# run_scan behaviour with mocked network layers
# --------------------------------------------------------------------------- #


def test_run_scan_blocks_public_target():
    """Safety guardrail: public targets are refused without an explicit override."""
    outcome = run_scan(ScanConfig(target="8.8.8.8"))
    assert outcome.error is not None
    assert "SAFETY BLOCK" in outcome.error
    assert outcome.hosts == []


def test_run_scan_rejects_empty_target():
    """An empty target is reported, not raised."""
    outcome = run_scan(ScanConfig(target="  "))
    assert outcome.error is not None


def test_run_scan_reports_progress_and_results(monkeypatch):
    """A full scan reports progress and collects hosts from the engine."""
    progress = []

    monkeypatch.setattr(scan_job, "arp_sweep", lambda subnet, timeout=2.0: [Host(ip="192.168.1.10")])

    engine = MagicMock()

    def _fake_scan_host(host, ports, probe_fn, on_result=None):
        result = PortResult(port=80, state="OPEN", service="http")
        host.add_port(result)
        if on_result:
            on_result(result)
        return host

    engine.scan_host.side_effect = _fake_scan_host
    monkeypatch.setattr(scan_job, "ConcurrentScanEngine", MagicMock(return_value=engine))
    monkeypatch.setattr(scan_job, "get_cve_engine", lambda: MagicMock())
    monkeypatch.setattr(scan_job, "grab_banner", lambda **kwargs: ("HTTP/1.1 200 OK", "http", "nginx"))

    outcome = run_scan(
        ScanConfig(
            target="192.168.1.0/24",
            port_selection=CUSTOM_SELECTION,
            custom_ports="80",
            grab_banners=False,
        ),
        on_progress=lambda message, fraction: progress.append((message, fraction)),
    )

    assert outcome.error is None
    assert len(outcome.hosts) == 1
    assert outcome.hosts[0].open_ports[0].port == 80
    assert progress, "progress callback was never invoked"
    assert progress[-1][1] == pytest.approx(1.0)
    engine.scan_host.assert_called_once()


def test_run_scan_honours_cancellation(monkeypatch):
    """A cancel request stops the scan and flags the outcome."""
    monkeypatch.setattr(scan_job, "arp_sweep", lambda subnet, timeout=2.0: [Host(ip="192.168.1.10")])
    monkeypatch.setattr(
        scan_job, "ConcurrentScanEngine", MagicMock(return_value=MagicMock())
    )

    outcome = run_scan(
        ScanConfig(target="192.168.1.0/24", port_selection=CUSTOM_SELECTION, custom_ports="80"),
        should_cancel=lambda: True,
    )
    assert outcome.cancelled is True


def test_arp_only_mode_returns_hosts_without_port_probing(monkeypatch):
    """ARP-only sweeps skip port probing entirely."""
    monkeypatch.setattr(scan_job, "arp_sweep", lambda subnet, timeout=2.0: [Host(ip="192.168.1.10")])
    engine_cls = MagicMock()
    monkeypatch.setattr(scan_job, "ConcurrentScanEngine", engine_cls)

    outcome = run_scan(ScanConfig(target="192.168.1.0/24", scan_mode=ARP_MODE))
    assert len(outcome.hosts) == 1
    engine_cls.assert_not_called()


# --------------------------------------------------------------------------- #
# HTTP server tests
# --------------------------------------------------------------------------- #


@pytest.fixture()
def live_server(monkeypatch):
    """Start the standalone dashboard on an ephemeral port for real HTTP tests."""

    def _fake_arp(subnet, timeout=2.0):
        return [Host(ip="192.168.1.10")]

    engine = MagicMock()

    def _fake_scan_host(host, ports, probe_fn, on_result=None):
        result = PortResult(port=8080, state="OPEN", service="http-alt")
        host.add_port(result)
        if on_result:
            on_result(result)
        return host

    engine.scan_host.side_effect = _fake_scan_host

    monkeypatch.setattr(scan_job, "arp_sweep", _fake_arp)
    monkeypatch.setattr(scan_job, "ConcurrentScanEngine", MagicMock(return_value=engine))

    from dashboard import standalone_server

    server = standalone_server.make_server(host="127.0.0.1", port=0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_address[1]}"
    try:
        yield base
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def _get(base, path):
    with urllib.request.urlopen(base + path, timeout=15) as response:
        return response.status, response.read(), response.headers


def _post(base, path, payload):
    data = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(
        base + path, data=data, headers={"Content-Type": "application/json"}, method="POST"
    )
    with urllib.request.urlopen(request, timeout=15) as response:
        return response.status, json.loads(response.read().decode("utf-8"))


def _wait_for_job(base, job_id, timeout=30.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        _, body, _ = _get(base, f"/api/job?id={job_id}")
        payload = json.loads(body.decode("utf-8"))
        if payload["status"] != "running":
            return payload
        time.sleep(0.1)
    raise AssertionError("scan did not finish in time")


def test_index_page_is_served(live_server):
    """The dashboard HTML is served with an iframe-friendly, same-origin page."""
    status, body, headers = _get(live_server, "/")
    assert status == 200
    assert "text/html" in headers["Content-Type"]
    html = body.decode("utf-8")
    assert "LAN Scanner" in html
    assert "api/scan" in html
    # No frame-busting headers: the page must be embeddable in a preview pane.
    assert "X-Frame-Options" not in headers


def test_health_endpoint(live_server):
    """A trivial health check exists for scripts and tests."""
    status, body, _ = _get(live_server, "/healthz")
    assert status == 200
    assert body == b"ok"


def test_config_endpoint_exposes_options(live_server):
    """The front end gets its dropdown values from the server, not hard-coded HTML."""
    status, body, _ = _get(live_server, "/api/config")
    assert status == 200
    payload = json.loads(body.decode("utf-8"))
    assert set(payload["scan_modes"]) == set(SCAN_MODES)
    assert payload["subnet"]
    assert payload["authorization_notice"]


def test_scan_rejects_empty_target(live_server):
    """Missing target yields a 400 rather than a crash."""
    with pytest.raises(urllib.error.HTTPError) as excinfo:
        _post(live_server, "/api/scan", {"target": ""})
    assert excinfo.value.code == 400
    error = json.loads(excinfo.value.read().decode("utf-8"))
    assert "target" in error["error"].lower()


def test_scan_end_to_end_and_exports(live_server):
    """Run a scan through the HTTP API, then download each report format."""
    status, started = _post(
        live_server,
        "/api/scan",
        {
            "target": "192.168.1.0/24",
            "scan_mode": SCAN_MODES[0],
            "port_selection": CUSTOM_SELECTION,
            "custom_ports": "8080",
            "threads": 5,
            "timeout": 0.3,
            "max_pps": 0,
            "grab_banners": False,
        },
    )
    assert status == 202
    job = _wait_for_job(live_server, started["job_id"])
    assert job["status"] == "done"
    assert job["progress"] == pytest.approx(1.0)
    assert job["summary"]["hosts"] == 1
    assert job["summary"]["open_ports"] == 1
    assert job["rows"][0]["service"] == "http-alt"

    for fmt, expected_mime in (
        ("json", "application/json"),
        ("csv", "text/csv"),
        ("xml", "application/xml"),
        ("html", "text/html"),
    ):
        status, body, headers = _get(live_server, f"/api/export?fmt={fmt}&id={started['job_id']}")
        assert status == 200, fmt
        assert expected_mime in headers["Content-Type"]
        assert "attachment" in headers["Content-Disposition"]
        assert body

    json_status, json_body, _ = _get(live_server, f"/api/export?fmt=json&id={started['job_id']}")
    assert json_status == 200
    assert json.loads(json_body.decode("utf-8"))["scan_summary"]["hosts_discovered"] == 1


def test_scan_rejects_public_target_through_api(live_server):
    """The safety guardrail also applies over HTTP."""
    _, started = _post(live_server, "/api/scan", {"target": "8.8.8.8"})
    job = _wait_for_job(live_server, started["job_id"])
    assert job["status"] == "error"
    assert "SAFETY BLOCK" in job["error"]


def test_unknown_export_format_is_rejected(live_server):
    """Unsupported formats return a 400 with a helpful message."""
    _, started = _post(live_server, "/api/scan", {"target": "127.0.0.1"})
    _wait_for_job(live_server, started["job_id"])
    with pytest.raises(urllib.error.HTTPError) as excinfo:
        _get(live_server, f"/api/export?fmt=exe&id={started['job_id']}")
    assert excinfo.value.code == 400


def test_unknown_route_returns_json_404(live_server):
    """Unknown API paths fail cleanly."""
    with pytest.raises(urllib.error.HTTPError) as excinfo:
        _get(live_server, "/api/nope")
    assert excinfo.value.code == 404


def test_single_scan_at_a_time(live_server, monkeypatch):
    """A second scan while one is running returns 409 instead of racing."""
    slow_started = threading.Event()
    release = threading.Event()

    def _slow_arp(subnet, timeout=2.0):
        slow_started.set()
        release.wait(timeout=10)
        return [Host(ip="192.168.1.10")]

    monkeypatch.setattr(scan_job, "arp_sweep", _slow_arp)

    _, first = _post(live_server, "/api/scan", {"target": "192.168.1.0/24"})
    assert slow_started.wait(timeout=10)
    try:
        with pytest.raises(urllib.error.HTTPError) as excinfo:
            _post(live_server, "/api/scan", {"target": "192.168.1.0/24"})
        assert excinfo.value.code == 409
    finally:
        release.set()
    _wait_for_job(live_server, first["job_id"])


# --------------------------------------------------------------------------- #
# Launcher / diagnostics helpers
# --------------------------------------------------------------------------- #


def test_run_dashboard_launcher_imports_without_streamlit():
    """The launcher must be importable (and able to fall back) with no Streamlit."""
    import run_dashboard

    assert hasattr(run_dashboard, "main")
    assert hasattr(run_dashboard, "probe_streamlit")
    assert run_dashboard.is_policy_block("An Application Control policy has blocked this file.")
    assert not run_dashboard.is_policy_block("ModuleNotFoundError: No module named 'scapy'")


def test_diagnostics_module_is_importable():
    """The diagnostics script must not require any third-party package."""
    import diagnose_windows_env

    assert hasattr(diagnose_windows_env, "main")
    assert hasattr(diagnose_windows_env, "check_imports")


def test_dashboard_app_has_no_pandas_import():
    """Regression guard: dashboard/app.py must never import pandas again."""
    with open("dashboard/app.py", "r", encoding="utf-8") as handle:
        source = handle.read()
    assert "import pandas" not in source
    assert "pd.DataFrame" not in source


def test_cancelled_job_keeps_partial_results():
    """A cancelled scan still exposes the findings gathered so far."""
    from dashboard.standalone_server import ScanJob

    job = ScanJob(job_id="abc123", config=ScanConfig(target="192.168.1.0/24"))
    job.hosts = _sample_hosts()
    job.status = "cancelled"
    job.message = "Scan cancelled."

    payload = job.status_payload()
    assert payload["has_results"] is True
    assert payload["summary"]["hosts"] == 2
    assert payload["rows"]
    assert payload["risks"]["HIGH"] == 1


def test_running_job_does_not_publish_results():
    """While a scan is running the payload stays small (no partial tables)."""
    from dashboard.standalone_server import ScanJob

    job = ScanJob(job_id="def456", config=ScanConfig(target="192.168.1.0/24"))
    job.hosts = _sample_hosts()

    payload = job.status_payload()
    assert payload["status"] == "running"
    assert payload["has_results"] is False
    assert "rows" not in payload
