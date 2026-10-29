"""Unit tests for Phase 6: Vulnerability Hints.

Validates:
1. Offline CVE signature database loading and parsing.
2. Banner matching against high-impact CVEs (vsftpd 2.3.4, OpenSSH RegreSSHion, Apache 2.4.49, etc.).
3. Verification that patched/modern versions produce zero false positives.
4. PortResult and Host annotation with required disclaimer notices.
"""

import pytest

from scanner.cve_lookup import (
    CVE_DISCLAIMER,
    CVELookupEngine,
    get_cve_engine,
    lookup_vulnerabilities,
)
from scanner.models import Host, PortResult


@pytest.fixture
def cve_engine():
    """Fixture providing initialized CVE lookup engine."""
    return get_cve_engine()


# ==============================================================================
# 1. Signature Matching Tests
# ==============================================================================

def test_vsftpd_backdoor_match(cve_engine):
    """Verify vsftpd 2.3.4 matches critical backdoor CVE-2011-2523."""
    banner = "220 (vsFTPd 2.3.4)"
    matches = cve_engine.lookup("vsftpd", banner)
    assert len(matches) >= 1
    assert any(m["cve_id"] == "CVE-2011-2523" for m in matches)
    assert matches[0]["severity"] == "CRITICAL"
    assert "disclaimer" in matches[0]
    assert CVE_DISCLAIMER in matches[0]["disclaimer"]


def test_proftpd_mod_copy_match(cve_engine):
    """Verify ProFTPD 1.3.5 matches CVE-2015-3306."""
    banner = "220 ProFTPD 1.3.5 Server (Debian)"
    matches = cve_engine.lookup("ProFTPD", banner)
    assert len(matches) >= 1
    assert any(m["cve_id"] == "CVE-2015-3306" for m in matches)
    assert matches[0]["severity"] == "HIGH"


def test_openssh_regresshion_match(cve_engine):
    """Verify vulnerable OpenSSH version matches CVE-2024-6387."""
    banner = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"
    matches = cve_engine.lookup("OpenSSH", banner)
    assert len(matches) >= 1
    assert any(m["cve_id"] == "CVE-2024-6387" for m in matches)


def test_apache_traversal_match(cve_engine):
    """Verify Apache 2.4.49 matches CVE-2021-41773."""
    banner = "HTTP/1.1 200 OK Server: Apache/2.4.49 (Unix)"
    matches = cve_engine.lookup("Apache", banner)
    assert len(matches) >= 1
    assert any(m["cve_id"] == "CVE-2021-41773" for m in matches)
    assert matches[0]["severity"] == "CRITICAL"


def test_secure_modern_versions_no_false_positives(cve_engine):
    """Verify secure modern software versions return no vulnerability hints."""
    # Modern secure versions
    assert len(cve_engine.lookup("vsftpd", "220 (vsFTPd 3.0.5)")) == 0
    assert len(cve_engine.lookup("OpenSSH", "SSH-2.0-OpenSSH_9.8p1")) == 0
    assert len(cve_engine.lookup("Apache", "Server: Apache/2.4.58 (Ubuntu)")) == 0
    assert len(cve_engine.lookup("nginx", "Server: nginx/1.24.0")) == 0


def test_unknown_banner_no_match(cve_engine):
    """Verify generic unknown services produce empty results."""
    assert len(cve_engine.lookup("custom_service", "Welcome 1.0")) == 0
    assert len(cve_engine.lookup("", "")) == 0


# ==============================================================================
# 2. Annotation Tests
# ==============================================================================

def test_annotate_open_port(cve_engine):
    """Verify open port with vulnerable banner gets populated cve_list."""
    port_res = PortResult(
        port=21,
        protocol="tcp",
        state="OPEN",
        service="vsftpd",
        banner="220 (vsFTPd 2.3.4)",
    )
    cve_engine.annotate_port(port_res)
    assert len(port_res.cve_list) >= 1
    assert port_res.cve_list[0]["cve_id"] == "CVE-2011-2523"


def test_closed_port_not_annotated(cve_engine):
    """Verify closed ports do not trigger CVE hints."""
    port_res = PortResult(
        port=21,
        protocol="tcp",
        state="CLOSED",
        service="vsftpd",
        banner="220 (vsFTPd 2.3.4)",
    )
    cve_engine.annotate_port(port_res)
    assert len(port_res.cve_list) == 0


def test_annotate_host(cve_engine):
    """Verify Host object open ports are annotated."""
    host = Host(ip="192.168.1.10")
    p1 = PortResult(port=21, state="OPEN", service="vsftpd", banner="220 (vsFTPd 2.3.4)")
    p2 = PortResult(port=80, state="OPEN", service="Apache", banner="Server: Apache/2.4.58")
    host.add_port(p1)
    host.add_port(p2)

    cve_engine.annotate_host(host)
    assert len(p1.cve_list) >= 1
    assert len(p2.cve_list) == 0
