"""Data models for hosts and port scan results.

This module provides standard dataclasses used across the LAN Scanner
to represent discovered hosts, probed ports, banners, and vulnerability hints.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class PortResult:
    """Represents the scan outcome for an individual network port.

    Attributes:
        port (int): The destination port number (1-65535).
        protocol (str): Transport layer protocol ('tcp' or 'udp').
        state (str): State of the port ('OPEN', 'CLOSED', 'FILTERED', 'OPEN|FILTERED').
        service (str): Inferred service name (e.g., 'http', 'ssh', 'unknown').
        banner (str): Banner string captured from the service, sanitized.
        cve_list (List[Dict[str, Any]]): Known CVE vulnerability hints matching service/banner.
    """

    port: int
    protocol: str = "tcp"
    state: str = "CLOSED"
    service: str = "unknown"
    banner: str = ""
    cve_list: List[Dict[str, Any]] = field(default_factory=list)

    @property
    def is_open(self) -> bool:
        """Check if port state indicates open.

        Returns:
            bool: True if state is 'OPEN', False otherwise.
        """
        return self.state == "OPEN"

    def to_dict(self) -> Dict[str, Any]:
        """Convert PortResult instance into a serializable dictionary.

        Returns:
            Dict[str, Any]: Dictionary representation of the port result.
        """
        return {
            "port": self.port,
            "protocol": self.protocol,
            "state": self.state,
            "service": self.service,
            "banner": self.banner,
            "cve_list": self.cve_list,
        }


@dataclass
class Host:
    """Represents a discovered host device on the local network.

    Attributes:
        ip (str): IPv4 address of the target.
        mac (Optional[str]): Hardware MAC address if discovered (e.g., via ARP).
        vendor (str): Hardware vendor identified from MAC OUI prefix.
        hostname (Optional[str]): Resolved DNS/NetBIOS hostname if available.
        ports (List[PortResult]): List of port scan results for this host.
        os_hint (Optional[str]): High-level OS fingerprint or banner hint.
    """

    ip: str
    mac: Optional[str] = None
    vendor: str = "Unknown"
    hostname: Optional[str] = None
    ports: List[PortResult] = field(default_factory=list)
    os_hint: Optional[str] = None

    def add_port(self, port_result: PortResult) -> None:
        """Add or update a port result for this host.

        Args:
            port_result (PortResult): The port probe result to register.
        """
        for i, existing in enumerate(self.ports):
            if existing.port == port_result.port and existing.protocol == port_result.protocol:
                self.ports[i] = port_result
                return
        self.ports.append(port_result)

    @property
    def open_ports(self) -> List[PortResult]:
        """Retrieve all open ports discovered on this host.

        Returns:
            List[PortResult]: Filtered list of ports with state == 'OPEN'.
        """
        return [p for p in self.ports if p.is_open]

    def to_dict(self) -> Dict[str, Any]:
        """Convert Host instance into a serializable dictionary.

        Returns:
            Dict[str, Any]: Dictionary representation of the host and its ports.
        """
        return {
            "ip": self.ip,
            "mac": self.mac,
            "vendor": self.vendor,
            "hostname": self.hostname,
            "os_hint": self.os_hint,
            "open_ports_count": len(self.open_ports),
            "ports": [p.to_dict() for p in self.ports],
        }
