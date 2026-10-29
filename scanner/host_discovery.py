"""Host discovery module using Layer 2 ARP sweeps and MAC vendor lookups.

Discovers live hosts within a local IPv4 subnet by transmitting ARP requests
and mapping responses to hardware MAC addresses and hardware manufacturer OUIs.
"""

import ipaddress
import re
import subprocess
import platform
from typing import Dict, List, Optional

try:
    from scapy.all import ARP, Ether, conf, srp
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

from scanner.models import Host


# Curated table of common IEEE Organizationally Unique Identifiers (OUIs)
OUI_VENDOR_TABLE: Dict[str, str] = {
    # Virtualization & Emulation
    "00:05:69": "VMware, Inc.",
    "00:0C:29": "VMware, Inc.",
    "00:50:56": "VMware, Inc.",
    "08:00:27": "Oracle VirtualBox",
    "52:54:00": "QEMU / KVM Virtual NIC",
    "00:15:5D": "Microsoft Hyper-V",
    "00:16:3E": "XenSource, Inc.",
    "00:1C:42": "Parallels, Inc.",
    # Embedded & Single Board Computers
    "B8:27:EB": "Raspberry Pi Foundation",
    "DC:A6:32": "Raspberry Pi Trading Ltd",
    "E4:5F:01": "Raspberry Pi Trading Ltd",
    "28:CD:C1": "Raspberry Pi Foundation",
    "24:6F:28": "Espressif Systems (ESP32/ESP8266)",
    "30:AE:A4": "Espressif Systems",
    "84:F3:EB": "Espressif Systems",
    "A4:CF:12": "Espressif Systems",
    # Hardware & PC Manufacturers
    "00:14:22": "Dell Inc.",
    "18:66:DA": "Dell Inc.",
    "B8:2A:72": "Dell Inc.",
    "3C:D9:2B": "HP Inc.",
    "00:1F:29": "HP Inc.",
    "2C:44:FD": "HP Inc.",
    "D8:5D:4C": "ASUSTek Computer Inc.",
    "F4:6D:04": "ASUSTek Computer Inc.",
    "AC:DE:48": "Intel Corporate",
    "00:1E:67": "Intel Corporate",
    "00:15:00": "Intel Corporate",
    "F8:63:3F": "Intel Corporate",
    "00:E0:4C": "Realtek Semiconductor",
    "54:EE:75": "Realtek Semiconductor",
    # Mobile & Consumer Devices
    "F0:18:98": "Apple, Inc.",
    "3C:22:FB": "Apple, Inc.",
    "AC:BC:32": "Apple, Inc.",
    "00:17:F2": "Apple, Inc.",
    "A4:83:E7": "Apple, Inc.",
    "50:85:69": "Samsung Electronics",
    "B0:EC:71": "Samsung Electronics",
    "30:07:4D": "Samsung Electronics",
    "00:1A:11": "Google, Inc.",
    "F4:F5:E8": "Google, Inc.",
    "D8:6C:63": "Google, Inc.",
    "44:65:0D": "Amazon Technologies",
    "FC:A6:67": "Amazon Technologies",
    "68:54:5A": "Amazon Technologies",
    "F8:46:1C": "Sony Corporation",
    # Networking & Routers
    "00:00:0C": "Cisco Systems",
    "00:01:42": "Cisco Systems",
    "00:1A:2B": "Cisco Systems",
    "50:C7:BF": "TP-Link Corporation",
    "E8:48:B8": "TP-Link Corporation",
    "B0:4E:26": "TP-Link Corporation",
    "20:4E:7F": "Netgear Inc.",
    "9C:3D:CF": "Netgear Inc.",
    "48:46:FB": "Huawei Technologies",
    "70:72:3C": "Huawei Technologies",
    "98:A9:42": "Huawei Technologies",
}


def lookup_mac_vendor(mac: Optional[str]) -> str:
    """Look up the hardware manufacturer name for a given MAC address.

    Normalizes MAC address format (removing colons, hyphens, and casing)
    and queries the internal OUI vendor prefix registry.

    Args:
        mac (Optional[str]): MAC address in standard colon or hyphen notation.

    Returns:
        str: Detected manufacturer name, or 'Unknown Vendor' if not matched.
    """
    if not mac:
        return "Unknown Vendor"

    clean_mac = re.sub(r"[^0-9A-Fa-f]", "", mac).upper()
    if len(clean_mac) < 6:
        return "Unknown Vendor"

    prefix = f"{clean_mac[0:2]}:{clean_mac[2:4]}:{clean_mac[4:6]}"
    return OUI_VENDOR_TABLE.get(prefix, "Unknown Vendor")


def parse_system_arp_table(target_subnet: Optional[str] = None) -> List[Host]:
    """Parse the operating system's local ARP cache as an offline or fallback discovery method.

    Useful when raw socket permissions are restricted or Scapy driver is unavailable.

    Args:
        target_subnet (Optional[str]): Optional CIDR filter (e.g. '192.168.1.0/24').

    Returns:
        List[Host]: Discovered hosts extracted from the OS ARP cache table.
    """
    hosts: List[Host] = []
    seen_ips = set()

    try:
        cmd = ["arp", "-a"]
        output = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, text=True)
    except Exception:
        return hosts

    filter_net = None
    if target_subnet:
        try:
            filter_net = ipaddress.ip_network(target_subnet, strict=False)
        except ValueError:
            pass

    # Regex to match IPv4 and MAC addresses across Windows and Linux arp -a output
    pattern = re.compile(
        r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+([0-9a-fA-F:-]{11,17})"
    )

    for line in output.splitlines():
        match = pattern.search(line)
        if match:
            ip_str, mac_str = match.groups()
            mac_formatted = mac_str.replace("-", ":").upper()
            try:
                ip_obj = ipaddress.ip_address(ip_str)
                # Filter out multicast, broadcast, loopback
                if ip_obj.is_multicast or ip_str.endswith(".255") or ip_str.startswith("127."):
                    continue
                if filter_net and ip_obj not in filter_net:
                    continue
                if ip_str not in seen_ips:
                    seen_ips.add(ip_str)
                    vendor = lookup_mac_vendor(mac_formatted)
                    hosts.append(Host(ip=ip_str, mac=mac_formatted, vendor=vendor))
            except ValueError:
                continue

    return hosts


def arp_sweep(
    subnet: str,
    timeout: float = 2.0,
    iface: Optional[str] = None,
    retry: int = 1,
) -> List[Host]:
    """Perform a Layer 2 ARP broadcast sweep across an IPv4 subnet to find live hosts.

    Constructs an Ethernet broadcast frame containing an ARP Who-has query for each
    host address within the designated CIDR block.

    Args:
        subnet (str): Target IPv4 subnet in CIDR notation (e.g., '192.168.1.0/24').
        timeout (float): Response listen timeout in seconds (default: 2.0s).
        iface (Optional[str]): Network interface identifier to send requests through.
        retry (int): Number of retransmissions for unanswering hosts (default: 1).

    Returns:
        List[Host]: Discovered live hosts with IP, MAC, and vendor fields populated,
                   sorted by IP address.
    """
    hosts: List[Host] = []
    seen_ips = set()

    # Validate target subnet format
    try:
        network = ipaddress.ip_network(subnet, strict=False)
    except ValueError as e:
        raise ValueError(f"Invalid target subnet format '{subnet}': {e}") from e

    if not SCAPY_AVAILABLE:
        # Fall back gracefully to system ARP cache inspection
        return parse_system_arp_table(subnet)

    try:
        # Build Layer 2 Ethernet Broadcast + ARP packet
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        arp = ARP(pdst=str(network))
        packet = ether / arp

        kwargs = {"timeout": timeout, "verbose": 0, "retry": retry}
        if iface:
            kwargs["iface"] = iface

        answered, _ = srp(packet, **kwargs)

        for _, received in answered:
            ip_str = received.psrc
            mac_str = received.hwsrc.upper()
            if ip_str not in seen_ips:
                seen_ips.add(ip_str)
                vendor = lookup_mac_vendor(mac_str)
                hosts.append(Host(ip=ip_str, mac=mac_str, vendor=vendor))

    except (PermissionError, OSError) as exc:
        # On Windows or Linux without admin/root or missing Npcap, catch and fallback
        print(f"[*] Note: Raw ARP sweep unavailable ({exc}). Reading OS ARP table fallback...")
        hosts = parse_system_arp_table(subnet)
    except Exception as exc:
        print(f"[*] Warning: ARP sweep encountered an error ({exc}). Attempting ARP cache fallback...")
        hosts = parse_system_arp_table(subnet)

    # Sort discovered hosts numerically by IP address
    hosts.sort(key=lambda h: ipaddress.ip_address(h.ip))
    return hosts
