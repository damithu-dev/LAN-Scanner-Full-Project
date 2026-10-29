"""TCP Connect port probe implementation.

Utilizes non-privileged TCP stream sockets via socket.connect_ex() to classify
port accessibility into OPEN, CLOSED, or FILTERED states without requiring
administrative/root privileges.
"""

import errno
import socket
from typing import Optional

from scanner.models import PortResult
from utils.ports import get_service_name
from utils.safety import RateLimiter

# Windows socket error code constants for cross-platform compatibility
WSAECONNREFUSED = 10061
WSAETIMEDOUT = 10060
WSAEHOSTUNREACH = 10065
WSAENETUNREACH = 10051


def tcp_connect_probe(
    ip: str,
    port: int,
    timeout: float = 1.0,
    rate_limiter: Optional[RateLimiter] = None,
) -> PortResult:
    """Probe a single TCP port using a standard 3-way handshake connect_ex() call.

    State classification rules:
    - Return code 0 -> OPEN
    - ECONNREFUSED / WSAECONNREFUSED -> CLOSED (Target actively sent RST packet)
    - ETIMEDOUT / WSAETIMEDOUT / socket.timeout -> FILTERED (Packet dropped by firewall / no reply)
    - EHOSTUNREACH / ENETUNREACH -> FILTERED

    Args:
        ip (str): Target IPv4 address.
        port (int): Target TCP port number (1-65535).
        timeout (float): Connection timeout in seconds.
        rate_limiter (Optional[RateLimiter]): Rate limiter instance to throttle PPS.

    Returns:
        PortResult: Result object containing port, protocol, state, and service name.
    """
    if rate_limiter:
        rate_limiter.wait()

    service = get_service_name(port, "tcp")
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)

    state = "FILTERED"
    try:
        err = sock.connect_ex((ip, port))
        if err == 0:
            state = "OPEN"
        elif err in (errno.ECONNREFUSED, WSAECONNREFUSED):
            state = "CLOSED"
        elif err in (errno.ETIMEDOUT, WSAETIMEDOUT, errno.EHOSTUNREACH, WSAEHOSTUNREACH, WSAENETUNREACH):
            state = "FILTERED"
        else:
            # Any unhandled nonzero socket error is classified as FILTERED
            state = "FILTERED"
    except (socket.timeout, TimeoutError):
        state = "FILTERED"
    except OSError:
        state = "FILTERED"
    finally:
        sock.close()

    return PortResult(
        port=port,
        protocol="tcp",
        state=state,
        service=service,
        banner="",
    )
