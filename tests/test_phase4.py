"""Unit tests for Phase 4: Advanced Scans (TCP SYN Stealth and UDP Probing).

Validates:
1. TCP SYN stealth probe responses (SYN-ACK, RST, ICMP unreachable, timeout).
2. Automatic fallback from SYN to TCP Connect scan when unprivileged.
3. UDP service payload generation for DNS, NTP, SNMP, and NetBIOS.
4. UDP probe response classification (OPEN, CLOSED, FILTERED, OPEN|FILTERED)
   using Scapy mocks and socket mocks.
"""

import errno
import socket
from unittest.mock import MagicMock, patch
import pytest

from scanner.models import PortResult
from scanner.stealth import tcp_syn_probe
from scanner.udp_probe import (
    DEFAULT_UDP_PAYLOAD,
    WSAECONNRESET,
    get_udp_payload,
    udp_probe,
    _udp_socket_probe,
)


# ==============================================================================
# 1. TCP SYN Stealth Scanner Tests
# ==============================================================================

@patch("scanner.stealth.is_admin", return_value=False)
@patch("scanner.stealth.tcp_connect_probe")
def test_tcp_syn_unprivileged_fallback(mock_connect_probe, mock_admin):
    """Verify non-admin execution falls back to TCP connect scan automatically."""
    mock_connect_probe.return_value = PortResult(port=80, state="OPEN", service="http")

    res = tcp_syn_probe("127.0.0.1", 80, timeout=0.5)
    assert res.state == "OPEN"
    mock_connect_probe.assert_called_once()


@patch("scanner.stealth.is_admin", return_value=True)
@patch("scanner.stealth.sr1")
@patch("scapy.all.send")
def test_tcp_syn_open_state(mock_send, mock_sr1, mock_admin):
    """Verify SYN-ACK response (0x12) classifies port as OPEN and transmits RST."""
    # Mock Scapy TCP SYN-ACK response
    mock_pkt = MagicMock()
    mock_pkt.haslayer.side_effect = lambda layer: layer.__name__ == "TCP"
    mock_tcp = MagicMock()
    mock_tcp.flags = 0x12  # SYN + ACK
    mock_pkt.getlayer.return_value = mock_tcp
    mock_pkt.ack = 12345
    mock_sr1.return_value = mock_pkt

    res = tcp_syn_probe("192.168.1.1", 80, timeout=0.5)
    assert res.port == 80
    assert res.state == "OPEN"
    # Verify RST packet transmission was attempted
    mock_send.assert_called_once()


@patch("scanner.stealth.is_admin", return_value=True)
@patch("scanner.stealth.sr1")
def test_tcp_syn_closed_state(mock_sr1, mock_admin):
    """Verify RST response (0x04) classifies port as CLOSED."""
    mock_pkt = MagicMock()
    mock_pkt.haslayer.side_effect = lambda layer: layer.__name__ == "TCP"
    mock_tcp = MagicMock()
    mock_tcp.flags = 0x14  # RST + ACK
    mock_pkt.getlayer.return_value = mock_tcp
    mock_sr1.return_value = mock_pkt

    res = tcp_syn_probe("192.168.1.1", 22, timeout=0.5)
    assert res.state == "CLOSED"


@patch("scanner.stealth.is_admin", return_value=True)
@patch("scanner.stealth.sr1")
def test_tcp_syn_filtered_timeout(mock_sr1, mock_admin):
    """Verify lack of response (None) classifies port as FILTERED."""
    mock_sr1.return_value = None

    res = tcp_syn_probe("192.168.1.1", 443, timeout=0.5)
    assert res.state == "FILTERED"


@patch("scanner.stealth.is_admin", return_value=True)
@patch("scanner.stealth.sr1")
def test_tcp_syn_filtered_icmp(mock_sr1, mock_admin):
    """Verify ICMP unreachable response classifies port as FILTERED."""
    mock_pkt = MagicMock()
    mock_pkt.haslayer.side_effect = lambda layer: layer.__name__ == "ICMP"
    mock_icmp = MagicMock()
    mock_icmp.type = 3
    mock_icmp.code = 13  # Communication administratively prohibited
    mock_pkt.getlayer.return_value = mock_icmp
    mock_sr1.return_value = mock_pkt

    res = tcp_syn_probe("192.168.1.1", 8080, timeout=0.5)
    assert res.state == "FILTERED"


# ==============================================================================
# 2. UDP Payloads Tests
# ==============================================================================

def test_udp_payload_resolution():
    """Verify payload retrieval for DNS, NTP, SNMP, and default ports."""
    dns_payload = get_udp_payload(53)
    assert b"google" in dns_payload

    ntp_payload = get_udp_payload(123)
    assert len(ntp_payload) == 48
    assert ntp_payload[0] == 0x1B

    snmp_payload = get_udp_payload(161)
    assert b"public" in snmp_payload

    generic_payload = get_udp_payload(9999)
    assert generic_payload == DEFAULT_UDP_PAYLOAD


# ==============================================================================
# 3. UDP Probing Tests (Scapy Privileged & Socket Fallback)
# ==============================================================================

@patch("scanner.udp_probe.is_admin", return_value=True)
@patch("scanner.udp_probe.sr1")
def test_udp_scapy_open_state(mock_sr1, mock_admin):
    """Verify UDP reply packet classifies port as OPEN."""
    mock_pkt = MagicMock()
    mock_pkt.haslayer.side_effect = lambda layer: layer.__name__ == "UDP"
    mock_sr1.return_value = mock_pkt

    res = udp_probe("192.168.1.1", 53, timeout=0.5)
    assert res.port == 53
    assert res.state == "OPEN"
    assert res.protocol == "udp"


@patch("scanner.udp_probe.is_admin", return_value=True)
@patch("scanner.udp_probe.sr1")
def test_udp_scapy_closed_icmp_port_unreachable(mock_sr1, mock_admin):
    """Verify ICMP Type 3 Code 3 classifies UDP port as CLOSED."""
    mock_pkt = MagicMock()
    mock_pkt.haslayer.side_effect = lambda layer: layer.__name__ == "ICMP"
    mock_icmp = MagicMock()
    mock_icmp.type = 3
    mock_icmp.code = 3  # Port unreachable
    mock_pkt.getlayer.return_value = mock_icmp
    mock_sr1.return_value = mock_pkt

    res = udp_probe("192.168.1.1", 123, timeout=0.5)
    assert res.state == "CLOSED"


@patch("scanner.udp_probe.is_admin", return_value=True)
@patch("scanner.udp_probe.sr1")
def test_udp_scapy_open_or_filtered_timeout(mock_sr1, mock_admin):
    """Verify unanswered UDP probe classifies port as OPEN|FILTERED."""
    mock_sr1.return_value = None

    res = udp_probe("192.168.1.1", 161, timeout=0.5)
    assert res.state == "OPEN|FILTERED"


@patch("socket.socket")
def test_udp_socket_open_state(mock_socket_cls):
    """Verify socket-based UDP probe receives data and marks OPEN."""
    mock_sock = MagicMock()
    mock_sock.recv.return_value = b"\x10\x00\x81\x80\x00\x01\x00\x01"  # DNS reply
    mock_socket_cls.return_value = mock_sock

    res = _udp_socket_probe("127.0.0.1", 53, timeout=0.5)
    assert res.state == "OPEN"


@patch("socket.socket")
def test_udp_socket_closed_state(mock_socket_cls):
    """Verify socket-based probe catching ICMP Port Unreachable marks CLOSED."""
    mock_sock = MagicMock()
    # Trigger Windows WSAECONNRESET (10054) on recv
    mock_sock.recv.side_effect = OSError(WSAECONNRESET, "Connection reset by peer")
    mock_socket_cls.return_value = mock_sock

    res = _udp_socket_probe("127.0.0.1", 9999, timeout=0.5)
    assert res.state == "CLOSED"


@patch("socket.socket")
def test_udp_socket_open_or_filtered_on_timeout(mock_socket_cls):
    """Verify socket timeout marks port as OPEN|FILTERED."""
    mock_sock = MagicMock()
    mock_sock.recv.side_effect = socket.timeout("Timed out")
    mock_socket_cls.return_value = mock_sock

    res = _udp_socket_probe("127.0.0.1", 123, timeout=0.5)
    assert res.state == "OPEN|FILTERED"
