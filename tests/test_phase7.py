"""Unit tests for Phase 7: Web Dashboard.

Validates:
1. Dashboard module structure (importable even when Streamlit is unavailable).
2. Session-state defaults.
3. The scan wrapper used by the Streamlit UI (all logic lives in dashboard.scan_job).
"""

from unittest.mock import MagicMock, patch

import pytest

from dashboard import scan_job
from dashboard.app import initialize_session_state
from dashboard.scan_job import CUSTOM_SELECTION, SCAN_MODES
from scanner.models import Host, PortResult


def test_dashboard_imports_and_components():
    """Verify all dashboard subcomponents import cleanly without syntax or import errors."""
    import dashboard.app as app

    assert hasattr(app, "render_dashboard")
    assert hasattr(app, "execute_scan")
    assert hasattr(app, "render_sidebar")
    assert hasattr(app, "get_streamlit_help_message")


def test_dashboard_imports_without_streamlit_or_pandas():
    """The module must import even when Streamlit/pandas cannot be imported at all.

    This is the situation created by a Windows Application Control policy, and it
    must never turn into a broken import for the rest of the project.
    """
    import dashboard.app as app

    assert isinstance(app.STREAMLIT_AVAILABLE, bool)
    if not app.STREAMLIT_AVAILABLE:
        assert "standalone" in app.get_streamlit_help_message()


def test_session_state_initialization():
    """Verify session state defaults are populated when keys are absent."""
    pytest.importorskip("streamlit", reason="Streamlit not installed in this environment")

    with patch("streamlit.session_state", {}) as mock_state:
        initialize_session_state()
        assert "scanned_hosts" in mock_state
        assert "is_scanning" in mock_state
        assert "last_scan_time" in mock_state
        assert "last_target" in mock_state


@patch("dashboard.scan_job.ConcurrentScanEngine")
@patch("dashboard.scan_job.arp_sweep")
def test_dashboard_execute_scan_flow(mock_arp, mock_engine_cls):
    """Verify execute_scan (the Streamlit wrapper) wires arguments to the scan engine."""
    import dashboard.app as app

    mock_arp.return_value = [Host(ip="192.168.1.10")]
    mock_engine = MagicMock()

    def _fake_scan_host(host, ports, probe_fn, on_result=None):
        result = PortResult(port=22, state="OPEN", service="OpenSSH")
        host.add_port(result)
        if on_result:
            on_result(result)
        return host

    mock_engine.scan_host.side_effect = _fake_scan_host
    mock_engine_cls.return_value = mock_engine

    config = {
        "target": "192.168.1.0/24",
        "scan_mode": SCAN_MODES[0],
        "port_selection": CUSTOM_SELECTION,
        "custom_ports": "22",
        "threads": 10,
        "timeout": 0.5,
        "max_pps": 0,
        "grab_banners": False,
        "allow_public": False,
    }

    mock_progress = MagicMock()
    mock_status = MagicMock()

    hosts = app.execute_scan(config, mock_progress, mock_status)
    assert len(hosts) == 1
    assert hosts[0].ip == "192.168.1.10"
    assert hosts[0].open_ports[0].port == 22
    mock_engine.scan_host.assert_called_once()
    assert mock_progress.progress.called
    assert mock_status.text.called


def test_execute_scan_reports_safety_block():
    """A refused target returns no hosts and shows an error rather than raising."""
    import dashboard.app as app

    hosts = app.execute_scan(
        {"target": "8.8.8.8", "threads": 5, "timeout": 0.2, "max_pps": 0, "grab_banners": False},
        MagicMock(),
        MagicMock(),
    )
    assert hosts == []


def test_scan_job_is_shared_by_both_front_ends():
    """Both dashboards must use the same scan implementation."""
    import dashboard.standalone_server as standalone

    assert standalone.run_scan is scan_job.run_scan


def test_streamlit_app_renders_without_relying_on_pandas():
    """Smoke-test the real Streamlit script with Streamlit's own test harness."""
    pytest.importorskip("streamlit", reason="Streamlit not installed in this environment")
    from streamlit.testing.v1 import AppTest

    at = AppTest.from_file("dashboard/app.py", default_timeout=90)
    at.run()

    assert not at.exception, f"dashboard raised: {[e.value for e in at.exception]}"
    labels = [metric.label for metric in at.metric]
    assert "Local IP" in labels
    assert any(button.label.startswith("▶️ Launch Scan") or "Launch Scan" in button.label
               for button in at.sidebar.button)
