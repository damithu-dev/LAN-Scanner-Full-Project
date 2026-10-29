"""UDP port scanning module with service-specific payloads and ICMP handling.

UDP is connectionless; non-responsive services cannot easily be distinguished from
packets dropped by firewalls. This module provides specialized request payloads
for common UDP services (DNS, NTP, SNMP, NetBIOS) and handles ICMP port unreachable
signals to classify ports into OPEN, CLOSED, or OPEN|FILTERED.
"""

import errno
import socket
from typing import Dict, Optional

try:
    from scapy.all import IP, UDP, ICMP, Raw, sr1
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

from scanner.models import PortResult
from utils.network import is_admin
from utils.ports import get_service_name
from utils.safety import RateLimiter

# Windows socket error constant for ICMP port unreachable notification on UDP sockets
WSAECONNRESET = 10054

# Hand-crafted service inquiry payloads
UDP_SERVICE_PAYLOADS: Dict[int, bytes] = {
    # DNS: Standard A query for "google.com"
    53: (
        b"\x10\x00"  # Transaction ID
        b"\x01\x00"  # Standard query flags
        b"\x00\x01\x00\x00\x00\x00\x00\x00"  # 1 question
        b"\x06google\x03com\x00"  # QNAME
        b"\x00\x01\x00\x01"  # QTYPE A, QCLASS IN
    ),
    # TFTP: Read request (RRQ) for file "test" in netascii mode
    69: b"\x00\x01test\x00netascii\x00",
    # NTP: Version 3 client request mode (48 bytes total)
    123: b"\x1b" + (b"\x00" * 47),
    # NetBIOS Name Service: Wildcard name status request
    137: (
        b"\x82\x28\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
        b"\x20\x43\x4b\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41"
        b"\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41"
        b"\x41\x41\x41\x41\x41\x00\x00\x21\x00\x01"
    ),
    # SNMP: SNMPv1 GetRequest for sysDescr (1.3.6.1.2.1.1.1.0) with "public" community
    161: (
        b"\x30\x29\x02\x01\x00\x04\x06\x70\x75\x62\x6c\x69\x63\xa0\x1c\x02\x04"
        b"\x12\x34\x56\x78\x02\x01\x00\x02\x01\x00\x30\x0e\x30\x0c\x06\x08\x2b"
        b"\x06\x01\x02\x01\x01\x01\x00\x05\x00"
    ),
}

DEFAULT_UDP_PAYLOAD = b"\x00\x00\x00\x00"


def get_udp_payload(port: int) -> bytes:
    """Retrieve service-specific query payload for designated UDP port.

    Args:
        port (int): Destination UDP port number.

    Returns:
        bytes: Payload byte sequence optimized to provoke an application response.
    """
    return UDP_SERVICE_PAYLOADS.get(port, DEFAULT_UDP_PAYLOAD)


def _udp_socket_probe(
    ip: str,
    port: int,
    timeout: float = 1.0,
    rate_limiter: Optional[RateLimiter] = None,
) -> PortResult:
    """Perform non-privileged socket-based UDP probe.

    Connects a datagram socket and listens for return bytes or OS ICMP error traps.

    Args:
        ip (str): Target IPv4 address.
        port (int): Target UDP port.
        timeout (float): Per-packet timeout in seconds.
        rate_limiter (Optional[RateLimiter]): Rate limiter instance.

    Returns:
        PortResult: Classified result (OPEN, CLOSED, or OPEN|FILTERED).
    """
    if rate_limiter:
        rate_limiter.wait()

    service = get_service_name(port, "udp")
    payload = get_udp_payload(port)
    state = "OPEN|FILTERED"
    banner = ""

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)

    try:
        sock.connect((ip, port))
        sock.send(payload)
        data = sock.recv(1024)
        if data:
            state = "OPEN"
            banner = data[:64].decode("utf-8", errors="ignore").strip()
    except (socket.timeout, TimeoutError):
        # Unresponsive UDP port: Could be an open service that ignored packet, or firewall dropped it
        state = "OPEN|FILTERED"
    except OSError as err:
        # OS notifications for ICMP Port Unreachable:
        # Windows WSAECONNRESET (10054) or Linux ECONNREFUSED (111)
        if err.errno in (errno.ECONNREFUSED, WSAECONNRESET, 10061):
            state = "CLOSED"
        else:
            state = "OPEN|FILTERED"
    finally:
        sock.close()

    return PortResult(
        port=port,
        protocol="udp",
        state=state,
        service=service,
        banner=banner,
    )


def udp_probe(
    ip: str,
    port: int,
    timeout: float = 1.5,
    rate_limiter: Optional[RateLimiter] = None,
    iface: Optional[str] = None,
) -> PortResult:
    """Probe a single UDP port using Scapy if privileged or datagram sockets otherwise.

    Classification matrix:
    - UDP reply packet received -> OPEN
    - ICMP Type 3, Code 3 (Port Unreachable) received -> CLOSED
    - ICMP Type 3, Code 1, 2, 9, 10, or 13 received -> FILTERED
    - No reply within timeout period -> OPEN|FILTERED

    Args:
        ip (str): Target IPv4 address.
        port (int): Target UDP port number.
        timeout (float): Timeout in seconds.
        rate_limiter (Optional[RateLimiter]): Rate limiter for packet pacing.
        iface (Optional[str]): Network interface identifier.

    Returns:
        PortResult: Populated PortResult dataclass instance.
    """
    # Use socket probe if not running with admin rights or Scapy unavailable
    if not is_admin() or not SCAPY_AVAILABLE:
        return _udp_socket_probe(ip=ip, port=port, timeout=timeout, rate_limiter=rate_limiter)

    if rate_limiter:
        rate_limiter.wait()

    service = get_service_name(port, "udp")
    payload = get_udp_payload(port)

    try:
        packet = IP(dst=ip) / UDP(dport=port) / Raw(load=payload)
        kwargs = {"timeout": timeout, "verbose": 0}
        if iface:
            kwargs["iface"] = iface

        response = sr1(packet, **kwargs)

        if response is None:
            return PortResult(port=port, protocol="udp", state="OPEN|FILTERED", service=service)

        if response.haslayer(UDP):
            return PortResult(port=port, protocol="udp", state="OPEN", service=service)

        if response.haslayer(ICMP):
            icmp = response.getlayer(ICMP)
            # ICMP Type 3 Code 3 -> Port Unreachable (Active OS rejection)
            if icmp.type == 3 and icmp.code == 3:
                return PortResult(port=port, protocol="udp", state="CLOSED", service=service)
            # Other ICMP unreachables -> Filtered
            elif icmp.type == 3 and icmp.code in (1, 2, 9, 10, 13):
                return PortResult(port=port, protocol="udp", state="FILTERED", service=service)

        return PortResult(port=port, protocol="udp", state="OPEN|FILTERED", service=service)

    except (PermissionError, OSError):
        return _udp_socket_probe(ip=ip, port=port, timeout=timeout, rate_limiter=rate_limiter)
    except Exception:
        return PortResult(port=port, protocol="udp", state="OPEN|FILTERED", service=service)
