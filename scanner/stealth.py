"""TCP SYN (Half-Open) Stealth Scanner.

Performs stealth scanning by transmitting raw TCP SYN packets using Scapy and
analyzing the response flags. Automatically falls back to standard TCP connect
scanning when run without administrative privileges or when raw packet injection
drivers (such as Npcap) are unavailable.
"""

from typing import Optional

try:
    from scapy.all import IP, TCP, ICMP, conf, sr1
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

from scanner.models import PortResult
from scanner.port_probe import tcp_connect_probe
from utils.network import is_admin
from utils.ports import get_service_name
from utils.safety import RateLimiter

# Track if fallback warning has already been displayed to prevent terminal spam
_FALLBACK_WARNED = False


def tcp_syn_probe(
    ip: str,
    port: int,
    timeout: float = 1.0,
    rate_limiter: Optional[RateLimiter] = None,
    iface: Optional[str] = None,
) -> PortResult:
    """Execute a TCP SYN (half-open) stealth scan against a single destination port.

    Protocol Logic:
    1. Send IP/TCP packet with SYN flag (S).
    2. Analyze response:
       - SYN+ACK received (flags == 0x12): Port is OPEN. Immediately transmit a
         RST packet to terminate the embryonic connection without completing
         the 3-way handshake (avoiding application-level connection logging).
       - RST or RST+ACK received (flags & 0x04): Port is CLOSED.
       - ICMP Destination Unreachable received: Port is FILTERED.
       - No response (timeout): Port is FILTERED.

    Fallback Behavior:
    If process lacks administrative/root rights or Scapy/pcap drivers are absent,
    gracefully redirects to tcp_connect_probe().

    Args:
        ip (str): Target IPv4 address.
        port (int): Target TCP port.
        timeout (float): Per-packet timeout in seconds.
        rate_limiter (Optional[RateLimiter]): Rate limiter instance for packet pacing.
        iface (Optional[str]): Network interface for transmission.

    Returns:
        PortResult: Result object containing port state (OPEN, CLOSED, FILTERED).
    """
    global _FALLBACK_WARNED

    # Check whether raw socket packet injection is supported in current environment
    if not is_admin() or not SCAPY_AVAILABLE:
        if not _FALLBACK_WARNED:
            print("[*] Notice: Administrative privileges or Npcap missing. Falling back to TCP Connect scan.")
            _FALLBACK_WARNED = True
        return tcp_connect_probe(ip=ip, port=port, timeout=timeout, rate_limiter=rate_limiter)

    if rate_limiter:
        rate_limiter.wait()

    service = get_service_name(port, "tcp")

    try:
        syn_packet = IP(dst=ip) / TCP(dport=port, flags="S")
        kwargs = {"timeout": timeout, "verbose": 0}
        if iface:
            kwargs["iface"] = iface

        response = sr1(syn_packet, **kwargs)

        if response is None:
            return PortResult(port=port, protocol="tcp", state="FILTERED", service=service)

        if response.haslayer(TCP):
            tcp_layer = response.getlayer(TCP)
            flags = tcp_layer.flags

            # SYN-ACK (0x12) -> OPEN
            if flags & 0x12 == 0x12:
                # Send immediate RST to tear down half-open connection cleanly
                try:
                    rst_packet = IP(dst=ip) / TCP(dport=port, flags="R", seq=response.ack)
                    from scapy.all import send
                    send(rst_packet, verbose=0)
                except Exception:
                    pass
                return PortResult(port=port, protocol="tcp", state="OPEN", service=service)

            # RST (0x04) or RST-ACK (0x14) -> CLOSED
            elif flags & 0x04:
                return PortResult(port=port, protocol="tcp", state="CLOSED", service=service)

        elif response.haslayer(ICMP):
            icmp_layer = response.getlayer(ICMP)
            # ICMP Type 3 (Destination Unreachable), codes 1, 2, 3, 9, 10, 13
            if icmp_layer.type == 3 and icmp_layer.code in (1, 2, 3, 9, 10, 13):
                return PortResult(port=port, protocol="tcp", state="FILTERED", service=service)

        return PortResult(port=port, protocol="tcp", state="FILTERED", service=service)

    except (PermissionError, OSError) as exc:
        if not _FALLBACK_WARNED:
            print(f"[*] Raw packet permission error ({exc}). Falling back to TCP Connect scan.")
            _FALLBACK_WARNED = True
        return tcp_connect_probe(ip=ip, port=port, timeout=timeout, rate_limiter=rate_limiter)
    except Exception:
        return PortResult(port=port, protocol="tcp", state="FILTERED", service=service)
