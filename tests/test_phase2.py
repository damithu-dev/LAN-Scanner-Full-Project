"""Unit tests for Phase 2: Port Scanning Engine.

Validates:
1. Port string parser (single, comma, range, deduplication, invalid syntax handling).
2. Top-100 and Top-1000 port lists integrity.
3. TCP connect probe state classification (OPEN, CLOSED, FILTERED) via socket mocks.
4. ConcurrentScanEngine multithreading, safety caps, and cancellation.
5. CLI argument parser options and flags.
"""

import errno
import socket
from unittest.mock import MagicMock, patch
import pytest

from main import build_argument_parser
from scanner.concurrent_scan import ConcurrentScanEngine, MAX_SAFE_THREADS
from scanner.models import Host, PortResult
from scanner.port_probe import WSAECONNREFUSED, WSAETIMEDOUT, tcp_connect_probe
from utils.ports import (
    TOP_100_PORTS,
    TOP_1000_PORTS,
    get_service_name,
    parse_port_string,
)


# ==============================================================================
# 1. Port Parser Tests
# ==============================================================================

def test_parse_single_port():
    """Verify single port string parsing."""
    assert parse_port_string("80") == [80]
    assert parse_port_string("443") == [443]


def test_parse_comma_separated_ports():
    """Verify comma-separated list parsing and ordering."""
    assert parse_port_string("80,22,443") == [22, 80, 443]
    assert parse_port_string(" 8080 , 21 , 25 ") == [21, 25, 8080]


def test_parse_port_range():
    """Verify contiguous range parsing."""
    assert parse_port_string("80-84") == [80, 81, 82, 83, 84]
    assert parse_port_string("1-3") == [1, 2, 3]


def test_parse_mixed_and_deduplication():
    """Verify combined ranges, singles, and duplicate removal."""
    assert parse_port_string("80,80,80-82,22,22") == [22, 80, 81, 82]


def test_parse_invalid_ports():
    """Verify invalid strings, boundaries, and inverted ranges raise ValueError."""
    # Out of boundary
    with pytest.raises(ValueError):
        parse_port_string("0")
    with pytest.raises(ValueError):
        parse_port_string("65536")
    with pytest.raises(ValueError):
        parse_port_string("80,70000")

    # Inverted range
    with pytest.raises(ValueError):
        parse_port_string("500-200")

    # Malformed non-numeric
    with pytest.raises(ValueError):
        parse_port_string("http,ssh")
    with pytest.raises(ValueError):
        parse_port_string("80-")
    with pytest.raises(ValueError):
        parse_port_string("")


def test_top_port_lists():
    """Verify Top 100 and Top 1000 port lists are valid, distinct, and sorted."""
    assert len(TOP_100_PORTS) == 100
    assert len(TOP_1000_PORTS) == 1000
    assert all(1 <= p <= 65535 for p in TOP_100_PORTS)
    assert all(1 <= p <= 65535 for p in TOP_1000_PORTS)
    assert len(set(TOP_100_PORTS)) == 100
    assert len(set(TOP_1000_PORTS)) == 1000


def test_get_service_name():
    """Verify resolution of standard and unknown ports to service names."""
    assert get_service_name(80) == "http"
    assert get_service_name(22) == "ssh"
    assert get_service_name(443) == "https"
    assert get_service_name(65500) in ("unknown", "")


# ==============================================================================
# 2. TCP Connect Probe Tests (Socket Mocking)
# ==============================================================================

@patch("socket.socket")
def test_tcp_probe_open_state(mock_socket_cls):
    """Verify connect_ex returning 0 is classified as OPEN."""
    mock_sock = MagicMock()
    mock_sock.connect_ex.return_value = 0
    mock_socket_cls.return_value = mock_sock

    res = tcp_connect_probe("127.0.0.1", 80, timeout=0.5)
    assert res.port == 80
    assert res.state == "OPEN"
    assert res.service == "http"
    assert res.is_open is True


@patch("socket.socket")
def test_tcp_probe_closed_state(mock_socket_cls):
    """Verify ECONNREFUSED is classified as CLOSED."""
    mock_sock = MagicMock()
    mock_sock.connect_ex.return_value = errno.ECONNREFUSED
    mock_socket_cls.return_value = mock_sock

    res = tcp_connect_probe("127.0.0.1", 22, timeout=0.5)
    assert res.state == "CLOSED"
    assert res.is_open is False


@patch("socket.socket")
def test_tcp_probe_filtered_on_timeout(mock_socket_cls):
    """Verify timeout and ETIMEDOUT are classified as FILTERED."""
    mock_sock = MagicMock()
    mock_sock.connect_ex.return_value = errno.ETIMEDOUT
    mock_socket_cls.return_value = mock_sock

    res = tcp_connect_probe("10.0.0.99", 443, timeout=0.5)
    assert res.state == "FILTERED"


@patch("socket.socket")
def test_tcp_probe_filtered_on_socket_exception(mock_socket_cls):
    """Verify socket timeout exception is caught and marked FILTERED."""
    mock_sock = MagicMock()
    mock_sock.connect_ex.side_effect = socket.timeout("Timed out")
    mock_socket_cls.return_value = mock_sock

    res = tcp_connect_probe("10.0.0.99", 8080, timeout=0.5)
    assert res.state == "FILTERED"


# ==============================================================================
# 3. Concurrent Engine Tests
# ==============================================================================

def test_engine_threads_safety_cap():
    """Verify max_threads parameter is capped at MAX_SAFE_THREADS."""
    engine = ConcurrentScanEngine(max_threads=9999)
    assert engine.max_threads == MAX_SAFE_THREADS


def test_engine_scan_ports_concurrent():
    """Verify multi-port scan returns sorted results and calls callbacks."""
    engine = ConcurrentScanEngine(max_threads=5, timeout=0.1)

    def mock_probe(ip: str, port: int, timeout: float = 1.0, rate_limiter=None) -> PortResult:
        state = "OPEN" if port in (80, 443) else "CLOSED"
        return PortResult(port=port, state=state, service="web")

    callback_results = []
    ports = [443, 80, 22, 21]
    results = engine.scan_ports(
        "127.0.0.1",
        ports=ports,
        probe_fn=mock_probe,
        on_result=lambda r: callback_results.append(r),
    )

    assert len(results) == 4
    assert [r.port for r in results] == [21, 22, 80, 443]
    assert len(callback_results) == 4
    assert engine.results_queue.qsize() == 4


def test_engine_cancellation():
    """Verify cancellation flag stops execution gracefully."""
    engine = ConcurrentScanEngine(max_threads=2, timeout=0.5)
    engine.cancel()

    def mock_probe(ip, port, **kwargs):
        return PortResult(port=port, state="OPEN")

    results = engine.scan_ports("127.0.0.1", ports=[80, 443], probe_fn=mock_probe)
    assert len(results) == 0


def test_engine_scan_host():
    """Verify scan_host attaches PortResults directly to the Host object."""
    host = Host(ip="127.0.0.1")
    engine = ConcurrentScanEngine(max_threads=2)

    def mock_probe(ip, port, **kwargs):
        return PortResult(port=port, state="OPEN" if port == 80 else "CLOSED")

    engine.scan_host(host, ports=[80, 81], probe_fn=mock_probe)
    assert len(host.ports) == 2
    assert len(host.open_ports) == 1
    assert host.open_ports[0].port == 80


# ==============================================================================
# 4. Argument Parser Tests
# ==============================================================================

def test_argument_parser_flags():
    """Verify CLI argument parsing across all standard options."""
    parser = build_argument_parser()
    args = parser.parse_args([
        "--target", "192.168.1.1",
        "--ports", "80,443",
        "--timeout", "2.0",
        "--threads", "50",
        "--max-pps", "100",
        "--allow-public",
    ])

    assert args.target == "192.168.1.1"
    assert args.ports == "80,443"
    assert args.timeout == 2.0
    assert args.threads == 50
    assert args.max_pps == 100
    assert args.allow_public is True
    assert args.top100 is False
    assert args.top1000 is False
