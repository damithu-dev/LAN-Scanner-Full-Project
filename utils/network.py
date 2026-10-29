"""Network environment detection utilities.

Provides functions to identify the active local IP address, network interface,
subnet boundaries, and administrative execution rights.
"""

import ctypes
import ipaddress
import os
import platform
import socket
from typing import Any, Dict, Optional

try:
    from scapy.all import conf
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


def is_admin() -> bool:
    """Determine whether the current process is running with administrative/root privileges.

    Returns:
        bool: True if running as Administrator on Windows or root (UID 0) on Unix, False otherwise.
    """
    try:
        if platform.system() == "Windows":
            return bool(ctypes.windll.shell32.IsUserAnAdmin() != 0)
        return os.geteuid() == 0
    except Exception:
        return False


def get_local_ip() -> str:
    """Detect the active local IPv4 address connected to the primary network gateway.

    Creates a local UDP connection handle without transmitting actual network traffic
    to determine the routing kernel's outbound IP.

    Returns:
        str: Local IPv4 address (e.g., '192.168.1.15'), or '127.0.0.1' as fallback.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # Using a private non-routable address to force routing table lookup
        s.connect(("10.255.255.255", 1))
        ip = s.getsockname()[0]
        if ip and not ip.startswith("127."):
            return ip
    except Exception:
        pass
    finally:
        s.close()

    # Fallback attempt via hostname
    try:
        hostname = socket.gethostname()
        ip = socket.gethostbyname(hostname)
        if ip and not ip.startswith("127."):
            return ip
    except Exception:
        pass

    # Scapy routing fallback if available
    if SCAPY_AVAILABLE:
        try:
            route = conf.route.route("0.0.0.0")
            if route and route[1]:
                return route[1]
        except Exception:
            pass

    return "127.0.0.1"


def get_default_interface() -> Optional[str]:
    """Identify the primary network interface name.

    Returns:
        Optional[str]: Interface identifier or description (e.g., 'eth0', 'Ethernet'),
                       or None if undetected.
    """
    if SCAPY_AVAILABLE:
        try:
            if hasattr(conf.iface, "name"):
                return conf.iface.name
            if hasattr(conf.iface, "description"):
                return conf.iface.description
            return str(conf.iface)
        except Exception:
            pass
    return None


def get_subnet_24(ip: Optional[str] = None) -> str:
    """Calculate the /24 subnet CIDR block for a given IP or the current host IP.

    Args:
        ip (Optional[str]): Target IPv4 address. If None, detects the current local IP.

    Returns:
        str: CIDR string representing the /24 subnet (e.g., '192.168.1.0/24').
    """
    target_ip = ip or get_local_ip()
    try:
        network = ipaddress.IPv4Network(f"{target_ip}/24", strict=False)
        return str(network)
    except ValueError:
        return "127.0.0.1/32"


def get_network_details() -> Dict[str, Any]:
    """Retrieve a comprehensive dictionary of current network interface properties.

    Returns:
        Dict[str, Any]: Contains 'local_ip', 'interface', 'subnet_24', 'hostname',
                        and 'is_admin'.
    """
    local_ip = get_local_ip()
    hostname = socket.gethostname()
    return {
        "local_ip": local_ip,
        "hostname": hostname,
        "interface": get_default_interface(),
        "subnet_24": get_subnet_24(local_ip),
        "is_admin": is_admin(),
    }
