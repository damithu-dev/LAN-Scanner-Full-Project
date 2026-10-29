"""Unit tests for Phase 5: Output & Exporters.

Validates:
1. JSON exporter generation and schema structure.
2. CSV tabular exporter generation and column mapping.
3. Nmap-compatible XML exporter generation and XML DTD structure.
4. Standalone HTML exporter generation and content integrity.
5. Rich terminal status formatting and display components.
"""

import csv
import json
import os
import tempfile
import xml.etree.ElementTree as ET
import pytest

from exporters.csv_exporter import export_csv
from exporters.html_exporter import export_html
from exporters.json_exporter import export_json
from exporters.xml_exporter import export_xml
from scanner.models import Host, PortResult
from ui.terminal import (
    display_header,
    display_host_results,
    display_summary,
    format_state,
)


@pytest.fixture
def sample_scanned_hosts():
    """Fixture providing populated sample Host objects with various port states."""
    host1 = Host(
        ip="192.168.1.50",
        mac="00:50:56:11:22:33",
        vendor="VMware, Inc.",
        hostname="web-prod.lan",
    )
    p1 = PortResult(port=80, protocol="tcp", state="OPEN", service="http", banner="Apache/2.4.41")
    p2 = PortResult(port=443, protocol="tcp", state="CLOSED", service="https")
    p3 = PortResult(port=22, protocol="tcp", state="FILTERED", service="ssh")
    host1.add_port(p1)
    host1.add_port(p2)
    host1.add_port(p3)

    host2 = Host(
        ip="192.168.1.60",
        mac="B8:27:EB:AA:BB:CC",
        vendor="Raspberry Pi Foundation",
    )
    p4 = PortResult(port=53, protocol="udp", state="OPEN", service="dns", banner="dnsmasq-2.80")
    p5 = PortResult(port=161, protocol="udp", state="OPEN|FILTERED", service="snmp")
    host2.add_port(p4)
    host2.add_port(p5)

    return [host1, host2]


# ==============================================================================
# 1. JSON Exporter Tests
# ==============================================================================

def test_export_json_structure(sample_scanned_hosts):
    """Verify JSON export contains all required fields and valid serialization."""
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf:
        path = tf.name

    try:
        out = export_json(
            sample_scanned_hosts,
            path,
            target="192.168.1.0/24",
            scan_time=2.45,
            metadata={"scan_type": "tcp_connect"},
        )
        assert out == path
        assert os.path.exists(path)

        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)

        assert "generator" in data
        assert "timestamp" in data
        assert data["scan_summary"]["target"] == "192.168.1.0/24"
        assert data["scan_summary"]["hosts_discovered"] == 2
        assert data["scan_summary"]["total_open_ports"] == 2  # Port 80 and 53
        assert len(data["hosts"]) == 2
        assert data["hosts"][0]["ip"] == "192.168.1.50"
        assert len(data["hosts"][0]["ports"]) == 3
    finally:
        if os.path.exists(path):
            os.remove(path)


# ==============================================================================
# 2. CSV Exporter Tests
# ==============================================================================

def test_export_csv_columns_and_data(sample_scanned_hosts):
    """Verify CSV export writes valid header and matches scanned port rows."""
    with tempfile.NamedTemporaryFile(suffix=".csv", delete=False) as tf:
        path = tf.name

    try:
        out = export_csv(sample_scanned_hosts, path)
        assert out == path

        with open(path, "r", newline="", encoding="utf-8") as f:
            reader = csv.reader(f)
            rows = list(reader)

        header = rows[0]
        assert "IP" in header
        assert "Port" in header
        assert "State" in header
        assert "Service" in header
        assert "Banner" in header

        # 1 header row + 3 ports from host1 + 2 ports from host2 = 6 rows
        assert len(rows) == 6
        assert rows[1][0] == "192.168.1.50"
        assert rows[1][4] == "80"
        assert rows[1][6] == "OPEN"
    finally:
        if os.path.exists(path):
            os.remove(path)


# ==============================================================================
# 3. XML Exporter Tests
# ==============================================================================

def test_export_xml_nmap_compatibility(sample_scanned_hosts):
    """Verify generated XML complies with standard Nmap XML structure."""
    with tempfile.NamedTemporaryFile(suffix=".xml", delete=False) as tf:
        path = tf.name

    try:
        out = export_xml(sample_scanned_hosts, path, target="192.168.1.0/24", scan_time=1.5)
        assert out == path

        tree = ET.parse(path)
        root = tree.getroot()
        assert root.tag == "nmaprun"
        assert root.attrib["scanner"] == "lanscanner"

        hosts_elems = root.findall("host")
        assert len(hosts_elems) == 2

        # Verify host addresses
        h1_addrs = hosts_elems[0].findall("address")
        assert any(a.attrib["addr"] == "192.168.1.50" for a in h1_addrs)
        assert any(a.attrib["addr"] == "00:50:56:11:22:33" for a in h1_addrs)

        # Verify ports
        ports = hosts_elems[0].find("ports").findall("port")
        assert len(ports) == 3

        # Verify runstats
        runstats = root.find("runstats")
        assert runstats is not None
        assert runstats.find("hosts").attrib["up"] == "2"
    finally:
        if os.path.exists(path):
            os.remove(path)


# ==============================================================================
# 4. HTML Exporter Tests
# ==============================================================================

def test_export_html_content(sample_scanned_hosts):
    """Verify HTML export renders complete report with metrics and badges."""
    with tempfile.NamedTemporaryFile(suffix=".html", delete=False) as tf:
        path = tf.name

    try:
        out = export_html(sample_scanned_hosts, path, target="192.168.1.0/24", scan_time=3.14)
        assert out == path

        with open(path, "r", encoding="utf-8") as f:
            content = f.read()

        assert "<!DOCTYPE html>" in content
        assert "LAN Scanner &amp; Active Port Scanner" in content or "LAN Scanner & Active Port Scanner" in content
        assert "192.168.1.50" in content
        assert "VMware, Inc." in content
        assert "badge-open" in content
        assert "Apache/2.4.41" in content
    finally:
        if os.path.exists(path):
            os.remove(path)


# ==============================================================================
# 5. Rich Terminal UI Tests
# ==============================================================================

def test_format_state_color_codes():
    """Verify color codes assigned to port states."""
    assert "green" in format_state("OPEN")
    assert "red" in format_state("CLOSED")
    assert "yellow" in format_state("FILTERED")
    assert "magenta" in format_state("OPEN|FILTERED")


def test_ui_display_functions_smoke_test(sample_scanned_hosts):
    """Smoke test ensuring display functions run without exceptions."""
    display_header(admin_status=True)
    display_header(admin_status=False)
    display_host_results(sample_scanned_hosts, show_all_states=True)
    display_host_results(sample_scanned_hosts, show_all_states=False)
    display_summary(hosts_count=2, open_ports_count=2, elapsed_time=1.23, interrupted=False)
    display_summary(hosts_count=2, open_ports_count=1, elapsed_time=0.45, interrupted=True)
