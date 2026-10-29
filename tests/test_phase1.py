"""Unit tests for Phase 1: Foundation.

Validates:
1. Data models (Host, PortResult).
2. Network environment detection (local IP, /24 subnet, interfaces).
3. Safety rules (private vs. public IP boundary, allow-public override, rate limiting).
4. MAC vendor OUI lookups and ARP sweep error handling.
"""

import time
from unittest.mock import MagicMock, patch
import pytest

from scanner.host_discovery import (
    OUI_VENDOR_TABLE,
    arp_sweep,
    lookup_mac_vendor,
    parse_system_arp_table,
)
from scanner.models import Host, PortResult
from utils.network import (
    get_default_interface,
    get_local_ip,
    get_network_details,
    get_subnet_24,
    is_admin,
)
from utils.safety import (
    RateLimiter,
    is_target_private,
    print_authorization_notice,
    validate_target,
)


# ==============================================================================
# 1. Model Tests
# ==============================================================================

def test_port_result_initialization_and_dict():
    """Verify PortResult defaults, properties, and dictionary serialization."""
    pr = PortResult(port=80, protocol="tcp", state="OPEN", service="http", banner="Apache/2.4")
    assert pr.port == 80
    assert pr.protocol == "tcp"
    assert pr.is_open is True
    assert pr.state == "OPEN"

    data = pr.to_dict()
    assert data["port"] == 80
    assert data["state"] == "OPEN"
    assert data["service"] == "http"
    assert data["banner"] == "Apache/2.4"
    assert data["cve_list"] == []


def test_host_initialization_and_port_management():
    """Verify Host creation, port insertion, update, and open_ports filtering."""
    host = Host(ip="192.168.1.50", mac="B8:27:EB:11:22:33", vendor="Raspberry Pi Foundation")
    assert host.ip == "192.168.1.50"
    assert host.mac == "B8:27:EB:11:22:33"
    assert host.vendor == "Raspberry Pi Foundation"
    assert len(host.ports) == 0
    assert len(host.open_ports) == 0

    # Add open port
    p1 = PortResult(port=22, state="OPEN", service="ssh")
    host.add_port(p1)
    assert len(host.open_ports) == 1

    # Add closed port
    p2 = PortResult(port=80, state="CLOSED", service="http")
    host.add_port(p2)
    assert len(host.ports) == 2
    assert len(host.open_ports) == 1

    # Update existing port
    p2_updated = PortResult(port=80, state="OPEN", service="http", banner="nginx")
    host.add_port(p2_updated)
    assert len(host.ports) == 2
    assert len(host.open_ports) == 2
    assert host.open_ports[1].banner == "nginx"

    h_dict = host.to_dict()
    assert h_dict["ip"] == "192.168.1.50"
    assert h_dict["open_ports_count"] == 2
    assert len(h_dict["ports"]) == 2


# ==============================================================================
# 2. Network Utilities Tests
# ==============================================================================

def test_get_local_ip_returns_valid_string():
    """Verify get_local_ip returns a non-empty IP string."""
    ip = get_local_ip()
    assert isinstance(ip, str)
    assert len(ip.split(".")) == 4


def test_get_subnet_24():
    """Verify /24 subnet calculation for standard addresses."""
    assert get_subnet_24("192.168.1.45") == "192.168.1.0/24"
    assert get_subnet_24("10.0.5.210") == "10.0.5.0/24"
    assert get_subnet_24("172.16.20.9") == "172.16.20.0/24"


def test_get_network_details():
    """Verify get_network_details structure."""
    details = get_network_details()
    assert "local_ip" in details
    assert "subnet_24" in details
    assert "hostname" in details
    assert "is_admin" in details
    assert isinstance(details["is_admin"], bool)


def test_is_admin_check():
    """Verify is_admin returns a boolean value without error."""
    admin_status = is_admin()
    assert isinstance(admin_status, bool)


# ==============================================================================
# 3. Safety and Authorization Tests
# ==============================================================================

def test_is_target_private():
    """Verify classification of private vs. public IP ranges."""
    # Private / Safe
    assert is_target_private("127.0.0.1") is True
    assert is_target_private("192.168.1.1") is True
    assert is_target_private("10.0.0.1") is True
    assert is_target_private("172.16.0.1") is True
    assert is_target_private("172.31.255.255") is True
    assert is_target_private("192.168.1.0/24") is True
    assert is_target_private("10.10.0.0/16") is True

    # Public / Unsafe
    assert is_target_private("8.8.8.8") is False
    assert is_target_private("1.1.1.1") is False
    assert is_target_private("142.250.190.46") is False
    assert is_target_private("93.184.216.0/24") is False


def test_validate_target_safety_blocking():
    """Verify target validation blocks public IPs unless explicitly permitted."""
    # Private allowed by default
    ok, msg = validate_target("192.168.1.100")
    assert ok is True
    assert "private/local" in msg

    # Public blocked by default
    ok, msg = validate_target("8.8.8.8", allow_public=False)
    assert ok is False
    assert "SAFETY BLOCK" in msg

    # Public allowed with override flag
    ok, msg = validate_target("8.8.8.8", allow_public=True)
    assert ok is True
    assert "WARNING" in msg
    assert "--allow-public" in msg

    # Empty target rejected
    ok, msg = validate_target("")
    assert ok is False


def test_rate_limiter():
    """Verify token pacing logic in RateLimiter."""
    limiter = RateLimiter(max_pps=50)  # 20ms per tick
    t0 = time.time()
    for _ in range(3):
        limiter.wait()
    t1 = time.time()
    # 3 calls at 50 pps should take at least ~0.03 seconds
    assert (t1 - t0) >= 0.03

    # Zero PPS does not block
    no_limit = RateLimiter(max_pps=0)
    no_limit.wait()


def test_print_authorization_notice(capsys):
    """Verify authorization notice prints expected keywords."""
    print_authorization_notice()
    captured = capsys.readouterr()
    assert "ETHICAL USE & AUTHORIZATION NOTICE" in captured.out
    assert "SAFEGUARDS IN EFFECT" in captured.out


# ==============================================================================
# 4. Host Discovery & OUI Lookup Tests
# ==============================================================================

def test_lookup_mac_vendor():
    """Verify MAC vendor lookup for common formats and OUIs."""
    # Standard colon notation
    assert lookup_mac_vendor("B8:27:EB:AA:BB:CC") == "Raspberry Pi Foundation"
    assert lookup_mac_vendor("08:00:27:12:34:56") == "Oracle VirtualBox"
    assert lookup_mac_vendor("00:50:56:01:02:03") == "VMware, Inc."
    assert lookup_mac_vendor("F0:18:98:99:88:77") == "Apple, Inc."

    # Hyphen notation & lowercase
    assert lookup_mac_vendor("b8-27-eb-11-22-33") == "Raspberry Pi Foundation"
    assert lookup_mac_vendor("00-0c-29-aa-bb-cc") == "VMware, Inc."

    # Unknown vendor & invalid input
    assert lookup_mac_vendor("FF:FF:FF:00:11:22") == "Unknown Vendor"
    assert lookup_mac_vendor(None) == "Unknown Vendor"
    assert lookup_mac_vendor("") == "Unknown Vendor"
    assert lookup_mac_vendor("12:34") == "Unknown Vendor"


def test_arp_sweep_invalid_subnet():
    """Verify ValueError is raised on malformed CIDR input."""
    with pytest.raises(ValueError):
        arp_sweep("999.999.999.999/99")


@patch("scanner.host_discovery.srp")
def test_arp_sweep_with_scapy_mock(mock_srp):
    """Verify ARP sweep parses Scapy responses correctly."""
    # Mock received packet
    mock_pkt = MagicMock()
    mock_pkt.psrc = "192.168.1.10"
    mock_pkt.hwsrc = "b8:27:eb:aa:bb:cc"

    mock_srp.return_value = ([(None, mock_pkt)], [])

    hosts = arp_sweep("192.168.1.0/24", timeout=0.1)
    assert len(hosts) == 1
    assert hosts[0].ip == "192.168.1.10"
    assert hosts[0].mac == "B8:27:EB:AA:BB:CC"
    assert hosts[0].vendor == "Raspberry Pi Foundation"


@patch("subprocess.check_output")
def test_parse_system_arp_table(mock_sub):
    """Verify parsing of OS arp -a command output."""
    sample_arp_output = """
Interface: 192.168.1.50 --- 0x10
  Internet Address      Physical Address      Type
  192.168.1.1           08-00-27-3a-2b-1c     dynamic
  192.168.1.255         ff-ff-ff-ff-ff-ff     static
  224.0.0.22            01-00-5e-00-00-16     static
    """
    mock_sub.return_value = sample_arp_output

    hosts = parse_system_arp_table(target_subnet="192.168.1.0/24")
    assert len(hosts) == 1
    assert hosts[0].ip == "192.168.1.1"
    assert hosts[0].mac == "08:00:27:3A:2B:1C"
    assert hosts[0].vendor == "Oracle VirtualBox"
