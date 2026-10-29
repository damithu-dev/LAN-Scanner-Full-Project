"""Interactive Streamlit web dashboard for the LAN Scanner & Active Port Scanner.

This front end is optional. It gives real-time graphical controls for network
discovery sweeps, active port probes, service detection, charts of open services
and security risk levels, report generation/downloads, and visible ethical
safety policies.

Two important notes
-------------------
1. **This module no longer imports pandas.** Tables are built from plain lists of
   dictionaries and charts from plain dictionaries, which Streamlit renders
   natively. Removing pandas from application code removes one whole class of
   environment problems (blocked compiled DLLs, version clashes, slow imports).

2. **Streamlit itself still imports pandas internally** (``streamlit.type_util``
   imports ``pyarrow``/``pandas`` at start-up). If a Windows Application Control /
   Smart App Control policy blocks a pandas DLL such as
   ``pandas\\_libs\\tslibs\\vectorized.cp312-win_amd64.pyd``, then ``streamlit run``
   cannot start at all - the failure happens before this file is executed.

   In that situation use the dependency-free dashboard instead::

       python run_dashboard.py --backend standalone

   It serves an equivalent web UI using only the Python standard library.
   See FIX_PANDAS_WINDOWS.md for the full explanation and repair options.

Run with:
    streamlit run dashboard/app.py
"""

from __future__ import annotations

import csv
import io
import json
import os
import sys
import tempfile
import time
from typing import Any, Dict, List, Optional

# Ensure parent directory is in Python path for intra-package imports
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)

# Streamlit is optional: import failures are captured so this module can still be
# imported (by tests, tooling, or the launcher) and can explain what to do next.
try:
    import streamlit as st

    STREAMLIT_AVAILABLE = True
    STREAMLIT_IMPORT_ERROR: Optional[BaseException] = None
except Exception as _streamlit_exc:  # pragma: no cover - environment dependent
    st = None  # type: ignore[assignment]
    STREAMLIT_AVAILABLE = False
    STREAMLIT_IMPORT_ERROR = _streamlit_exc

from dashboard.scan_job import (  # noqa: E402  (after sys.path bootstrap)
    CUSTOM_SELECTION,
    PORT_SELECTIONS,
    SCAN_MODES,
    ScanConfig,
    collect_cves,
    flatten_hosts,
    risk_summary,
    run_scan,
    service_summary,
    summarize,
)
from scanner.models import Host  # noqa: E402

# Report exporters are imported defensively: the Word exporter needs the optional
# python-docx package, and a missing optional dependency must not stop the whole
# dashboard (the JSON/CSV downloads are pure standard library).
try:
    from exporters.html_exporter import export_html
except Exception as _exc:  # pragma: no cover - environment dependent
    export_html = None  # type: ignore[assignment]
    _HTML_EXPORT_ERROR = f"{type(_exc).__name__}: {_exc}"
else:
    _HTML_EXPORT_ERROR = ""

try:
    from exporters.xml_exporter import export_xml
except Exception as _exc:  # pragma: no cover
    export_xml = None  # type: ignore[assignment]
    _XML_EXPORT_ERROR = f"{type(_exc).__name__}: {_exc}"
else:
    _XML_EXPORT_ERROR = ""

try:
    from exporters.word_exporter import export_word_report
except Exception as _exc:  # pragma: no cover
    export_word_report = None  # type: ignore[assignment]
    _WORD_EXPORT_ERROR = f"{type(_exc).__name__}: {_exc}"
else:
    _WORD_EXPORT_ERROR = ""
from utils.network import get_default_interface, get_local_ip, get_subnet_24, is_admin  # noqa: E402
from utils.safety import AUTHORIZATION_NOTICE  # noqa: E402

# Human-friendly column headers for the results table.
TABLE_COLUMNS = [
    ("ip", "IP Address"),
    ("mac", "MAC Address"),
    ("vendor", "Hardware Vendor"),
    ("port", "Port"),
    ("protocol", "Protocol"),
    ("state", "State"),
    ("service", "Service"),
    ("banner", "Banner / Version"),
    ("risk", "Risk Level"),
]


def get_streamlit_help_message(error: Optional[BaseException] = None) -> str:
    """Return an actionable message when Streamlit cannot be imported."""
    detail = f"\n\nUnderlying error:\n{type(error).__name__}: {error}" if error else ""
    return (
        "The Streamlit dashboard cannot start in this environment.\n\n"
        "Streamlit imports pandas during its own start-up, so a blocked pandas DLL "
        "(for example 'vectorized.cp3xx-win_amd64.pyd' blocked by an Application "
        "Control policy) prevents Streamlit from loading at all.\n\n"
        "Use the dependency-free dashboard instead - it needs no pandas/Streamlit:\n"
        "    python run_dashboard.py --backend standalone\n\n"
        "Or repair the Python environment (see FIX_PANDAS_WINDOWS.md):\n"
        "    python diagnose_windows_env.py\n"
        "    python diagnose_windows_env.py --repair" + detail
    )


def _require_streamlit() -> None:
    """Abort with a clear message if Streamlit is unavailable."""
    if STREAMLIT_AVAILABLE and st is not None:
        return
    raise SystemExit(get_streamlit_help_message(STREAMLIT_IMPORT_ERROR))


def initialize_session_state() -> None:
    """Initialize persistent Streamlit session keys."""
    defaults = {
        "scanned_hosts": [],
        "is_scanning": False,
        "last_scan_time": 0.0,
        "last_target": "",
    }
    for key, value in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = value


def render_sidebar() -> Dict[str, Any]:
    """Render the configuration sidebar containing scan options and controls.

    Returns:
        dict: Parsed user configuration dictionary.
    """
    _require_streamlit()

    st.sidebar.title("🛡️ Scan Setup")
    st.sidebar.caption("Choose what to check. Hover over ⓘ help icons for explanations.")

    default_subnet = get_subnet_24()
    target_input = st.sidebar.text_input(
        "Device or network to check",
        value=default_subnet,
        help=(
            "Enter one device IP (for example, 127.0.0.1) or a network range "
            "(for example, 192.168.1.0/24). Only scan systems you own or have "
            "permission to test."
        ),
    )

    scan_mode = st.sidebar.selectbox(
        "How should it check?",
        SCAN_MODES,
        index=0,
        help=(
            "TCP Connect is a standard, straightforward check. SYN uses a half-open TCP "
            "probe and may require elevated permissions. UDP checks selected UDP services. "
            "ARP discovers local-network devices without checking their ports."
        ),
    )

    port_selection = st.sidebar.radio(
        "Port Selection",
        PORT_SELECTIONS,
        index=0,
        help=(
            "More ports take longer to check. Start with the top 100 common ports or "
            "choose a small custom list for a quick demonstration."
        ),
    )

    custom_ports_str = ""
    if port_selection == CUSTOM_SELECTION:
        custom_ports_str = st.sidebar.text_input(
            "Custom Ports",
            value="21,22,80,443,8080",
            help="E.g., 80,443 or 1-1024 or 80,8080-8090",
        )

    st.sidebar.markdown("---")
    st.sidebar.subheader("⚙️ Performance & Safety")

    threads = st.sidebar.slider("Concurrent Worker Threads", min_value=5, max_value=200, value=50, step=5)
    timeout = st.sidebar.slider("Socket Timeout (seconds)", min_value=0.2, max_value=3.0, value=1.0, step=0.1)
    max_pps = st.sidebar.slider(
        "Rate Limit (Max Packets/Sec)",
        min_value=0,
        max_value=500,
        value=0,
        step=25,
        help="0 = unthrottled pacing",
    )

    grab_banners_option = st.sidebar.checkbox("Grab Service Banners & CVE Hints", value=True)
    allow_public_option = st.sidebar.checkbox(
        "Allow Public IP Scanning",
        value=False,
        help="Explicit override for external testing.",
    )

    return {
        "target": target_input,
        "scan_mode": scan_mode,
        "port_selection": port_selection,
        "custom_ports": custom_ports_str,
        "threads": threads,
        "timeout": timeout,
        "max_pps": max_pps,
        "grab_banners": grab_banners_option,
        "allow_public": allow_public_option,
    }


def execute_scan(config: Dict[str, Any], progress_bar, status_text) -> List[Host]:
    """Execute the scan described by ``config`` and update Streamlit widgets.

    All scanning logic lives in :mod:`dashboard.scan_job` so the Streamlit UI and
    the dependency-free UI behave identically.

    Args:
        config (dict): Configuration options from the sidebar.
        progress_bar: Streamlit progress widget.
        status_text: Streamlit text widget for status messaging.

    Returns:
        List[Host]: Hosts with results (empty list if the scan was refused).
    """
    scan_config = ScanConfig.from_mapping(config)

    def _progress(message: str, fraction: float) -> None:
        try:
            progress_bar.progress(max(0.0, min(1.0, fraction)))
            status_text.text(message)
        except Exception:  # pragma: no cover - widgets may be detached
            pass

    outcome = run_scan(scan_config, on_progress=_progress)

    for warning in outcome.warnings:
        try:
            st.warning(warning)
        except Exception:  # pragma: no cover
            pass

    if outcome.error:
        try:
            st.error(outcome.error)
        except Exception:  # pragma: no cover
            pass
        return []

    return outcome.hosts


def _table_rows(hosts: List[Host]) -> List[Dict[str, Any]]:
    """Convert flattened rows into display-labeled table rows."""
    return [{label: row.get(key, "") for key, label in TABLE_COLUMNS} for row in flatten_hosts(hosts)]


def render_dashboard() -> None:
    """Main rendering routine for the dashboard UI."""
    _require_streamlit()

    st.set_page_config(
        page_title="LAN Scanner & Active Port Scanner",
        page_icon="🛡️",
        layout="wide",
        initial_sidebar_state="expanded",
    )

    initialize_session_state()

    # Safety Notice Banner (Required Safety Rule)
    with st.expander("⚖️ Ethical & Legal Authorization Notice (Click to expand)", expanded=False):
        st.info(AUTHORIZATION_NOTICE)

    st.title("🌐 LAN Scanner & Active Port Scanner")
    st.caption("A guided network check for learning and authorized security reviews.")
    st.info(
        "New here? Set the device or network in the left panel, keep the default settings "
        "for a first test, and select **Launch Scan**. Results appear below. An open port "
        "is not automatically a problem."
    )
    with st.expander("📘 Understand the results (plain-language guide)"):
        st.markdown(
            "- **Device found:** a device that responded to the scan.\n"
            "- **Open port:** a network service appears to be listening; confirm it is expected.\n"
            "- **Closed port:** the device responded, but no service accepted the connection on that port.\n"
            "- **Filtered:** a firewall or network rule may have blocked the check.\n"
            "- **Vulnerability hint:** a possible match based on service information, not proof of a "
            "vulnerability. Verify before taking action.\n"
            "- **No findings:** this scan did not detect a matching issue; it does not guarantee the "
            "device is secure."
        )

    # Environment Metrics Bar
    col_env1, col_env2, col_env3, col_env4 = st.columns(4)
    with col_env1:
        st.metric("Local IP", get_local_ip())
    with col_env2:
        st.metric("Primary Interface", get_default_interface() or "Auto")
    with col_env3:
        st.metric("/24 Local Subnet", get_subnet_24())
    with col_env4:
        admin_flag = is_admin()
        st.metric("Privilege Mode", "Administrator (Raw L2/L3)" if admin_flag else "User (TCP Connect)")

    st.markdown("---")

    # Sidebar inputs
    config = render_sidebar()

    # Trigger scan button
    if st.sidebar.button("▶️ Launch Scan", type="primary", use_container_width=True):
        progress_bar = st.progress(0.0)
        status_text = st.empty()

        start_time = time.time()
        scanned = execute_scan(config, progress_bar, status_text)
        elapsed = time.time() - start_time

        st.session_state.scanned_hosts = scanned
        st.session_state.last_scan_time = elapsed
        st.session_state.last_target = config["target"]

    hosts: List[Host] = st.session_state.scanned_hosts

    if not hosts:
        st.info("👈 Configure your scan parameters in the sidebar and click **'Launch Scan'** to begin auditing.")
        return

    # Top KPI Metrics Cards
    stats = summarize(hosts)
    rows = flatten_hosts(hosts)
    all_cves = collect_cves(hosts)

    m1, m2, m3, m4, m5 = st.columns(5)
    m1.metric("Hosts Discovered", stats["hosts"])
    m2.metric("Open Ports", stats["open_ports"])
    m3.metric(
        "Security Alerts",
        stats["alerts"],
        delta=f"{stats['critical']} Critical" if stats["critical"] else None,
        delta_color="inverse",
    )
    m4.metric("Scan Time", f"{st.session_state.last_scan_time:.2f}s")
    m5.metric("Target Scope", st.session_state.last_target or "Local")

    # Tabbed Views: Results Table, Charts, Vulnerability Insights, Exporters
    tab_table, tab_charts, tab_cves, tab_export = st.tabs(
        [
            "📋 Discovered Hosts & Ports",
            "📊 Visual Analytics & Charts",
            "🚨 Vulnerability Hints",
            "💾 Export Reports",
        ]
    )

    with tab_table:
        st.subheader("Discovered Network Endpoints")
        # A list of dicts is rendered natively - no pandas DataFrame required.
        st.dataframe(_table_rows(hosts), use_container_width=True, hide_index=True)

    with tab_charts:
        st.subheader("Network Audit Analytics")
        c1, c2 = st.columns(2)

        with c1:
            st.markdown("##### Open Ports by Service")
            services = service_summary(hosts)
            if services:
                st.bar_chart(services)
            else:
                st.info("No open ports found to chart.")

        with c2:
            st.markdown("##### Security Risk Level Distribution")
            risks = risk_summary(rows)
            if risks:
                st.bar_chart(risks)
            else:
                st.info("No results found to chart.")

    with tab_cves:
        st.subheader("Vulnerability Findings & Remediation Hints")
        st.caption(
            "DISCLAIMER: Basic vulnerability hints only, based on banner heuristics. "
            "Not a full vulnerability scanner."
        )

        if all_cves:
            for cve in all_cves:
                severity = str(cve.get("severity", "MEDIUM")).upper()
                box = st.error if severity == "CRITICAL" else (st.warning if severity == "HIGH" else st.info)
                box(
                    f"**{cve.get('cve_id')} ({severity} - CVSS {cve.get('cvss')})** "
                    f"on {cve.get('ip', '')}:{cve.get('port', '')} — {cve.get('title')}\n\n"
                    f"• **Description:** {cve.get('description')}\n\n"
                    f"• **Remediation:** {cve.get('fix')}"
                )
        else:
            st.success("✅ No known high-impact CVEs detected in the captured service banners.")

    with tab_export:
        st.subheader("Download Your Report")
        st.markdown(
            "Choose a format below. **Word report** is recommended for non-technical readers "
            "because it explains what the results mean and suggests practical next steps. "
            "The other formats are better for spreadsheets or technical tools."
        )

        col_d1, col_d2, col_d3, col_d4, col_d5 = st.columns(5)

        # JSON Export in-memory
        with col_d1:
            report_dict = {
                "generator": "LAN Scanner Dashboard",
                "target": st.session_state.last_target,
                "hosts": [h.to_dict() for h in hosts],
            }
            st.download_button(
                label="📥 Download JSON",
                data=json.dumps(report_dict, indent=2),
                file_name="lan_scan_report.json",
                mime="application/json",
                use_container_width=True,
            )

        # CSV Export in-memory
        with col_d2:
            csv_buffer = io.StringIO()
            writer = csv.writer(csv_buffer)
            writer.writerow(["IP", "MAC", "Vendor", "Port", "Protocol", "State", "Service", "Banner", "CVEs"])
            for h in hosts:
                for p in h.ports:
                    cves = "; ".join(c.get("cve_id", "") for c in p.cve_list if isinstance(c, dict))
                    writer.writerow(
                        [h.ip, h.mac or "N/A", h.vendor, p.port, p.protocol, p.state, p.service, p.banner, cves]
                    )
            st.download_button(
                label="📥 Download CSV",
                data=csv_buffer.getvalue(),
                file_name="lan_scan_report.csv",
                mime="text/csv",
                use_container_width=True,
            )

        # XML Export in-memory
        with col_d3:
            if export_xml is None:
                st.warning(f"XML export unavailable ({_XML_EXPORT_ERROR}).")
            else:
                with tempfile.NamedTemporaryFile(suffix=".xml", delete=False) as tf:
                    xml_path = tf.name
                try:
                    export_xml(
                        hosts,
                        xml_path,
                        target=st.session_state.last_target,
                        scan_time=st.session_state.last_scan_time,
                    )
                    with open(xml_path, "r", encoding="utf-8") as f:
                        xml_content = f.read()
                finally:
                    if os.path.exists(xml_path):
                        os.remove(xml_path)

                st.download_button(
                    label="📥 Download XML (Nmap)",
                    data=xml_content,
                    file_name="lan_scan_report.xml",
                    mime="application/xml",
                    use_container_width=True,
                )

        # HTML Export in-memory
        with col_d4:
            if export_html is None:
                st.warning(f"HTML export unavailable ({_HTML_EXPORT_ERROR}).")
            else:
                with tempfile.NamedTemporaryFile(suffix=".html", delete=False) as tf:
                    html_path = tf.name
                try:
                    export_html(
                        hosts,
                        html_path,
                        target=st.session_state.last_target,
                        scan_time=st.session_state.last_scan_time,
                    )
                    with open(html_path, "r", encoding="utf-8") as f:
                        html_content = f.read()
                finally:
                    if os.path.exists(html_path):
                        os.remove(html_path)

                st.download_button(
                    label="📥 Download HTML Report",
                    data=html_content,
                    file_name="lan_scan_report.html",
                    mime="text/html",
                    use_container_width=True,
                )

        # Detailed Word report for non-technical readers
        with col_d5:
            if export_word_report is None:
                st.warning(
                    "Word report unavailable: the optional 'python-docx' package could not be "
                    f"imported ({_WORD_EXPORT_ERROR}). Install it with: "
                    "python -m pip install python-docx"
                )
            else:
                word_path = None
                try:
                    with tempfile.NamedTemporaryFile(suffix=".docx", delete=False) as tf:
                        word_path = tf.name
                    export_word_report(
                        hosts,
                        word_path,
                        target=st.session_state.last_target or "Not recorded",
                        scan_time=st.session_state.last_scan_time,
                        scan_mode=config["scan_mode"],
                        port_selection=config["port_selection"],
                    )
                    with open(word_path, "rb") as f:
                        word_content = f.read()
                    st.download_button(
                        label="\U0001f4c4 Download Word Report",
                        data=word_content,
                        file_name="lan_scan_detailed_report.docx",
                        mime="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                        help=(
                            "A detailed report with an executive summary, explanations of terms, "
                            "device-by-device results, possible vulnerability hints, and recommended "
                            "next steps."
                        ),
                        use_container_width=True,
                    )
                finally:
                    if word_path and os.path.exists(word_path):
                        os.remove(word_path)


if __name__ == "__main__":
    if not STREAMLIT_AVAILABLE:
        # Running as a plain script instead of through "streamlit run".
        print(get_streamlit_help_message(STREAMLIT_IMPORT_ERROR), file=sys.stderr)
        raise SystemExit(1)
    render_dashboard()
