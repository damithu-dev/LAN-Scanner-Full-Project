"""Offline CVE vulnerability hints lookup engine.

Matches captured service banners and parsed version strings against a curated
offline database of well-known, high-impact security vulnerabilities.

DISCLAIMER:
These findings are basic heuristic hints based strictly on service banners.
They do not constitute a full, definitive vulnerability assessment or penetration
test, and services may have backported security patches.
"""

import json
import os
import re
from typing import Any, Dict, List, Optional, Tuple

from scanner.models import Host, PortResult

CVE_DISCLAIMER = "Basic vulnerability hints only; not a full vulnerability scanner."

DEFAULT_DB_PATH = os.path.join(os.path.dirname(__file__), "data", "cve_database.json")


class CVELookupEngine:
    """Offline signature-based vulnerability lookup engine.

    Attributes:
        database_path (str): Path to JSON CVE registry file.
        entries (List[Dict[str, Any]]): Loaded vulnerability signatures.
    """

    def __init__(self, database_path: Optional[str] = None):
        """Initialize the CVE lookup engine and load signature entries."""
        self.database_path = database_path or DEFAULT_DB_PATH
        self.entries: List[Dict[str, Any]] = []
        self._compiled_patterns: List[Tuple] = []
        self.load_database(self.database_path)

    def load_database(self, path: str) -> None:
        """Load and compile vulnerability signatures from JSON file.

        Args:
            path (str): File path to JSON database.
        """
        if not os.path.exists(path):
            self.entries = []
            return

        try:
            with open(path, "r", encoding="utf-8") as f:
                self.entries = json.load(f)

            self._compiled_patterns = []
            for item in self.entries:
                service = item.get("service", "").lower()
                pattern_str = item.get("version_pattern", "")
                try:
                    compiled = re.compile(pattern_str, re.IGNORECASE) if pattern_str else None
                except re.error:
                    compiled = None
                self._compiled_patterns.append((service, compiled, item))
        except Exception:
            self.entries = []
            self._compiled_patterns = []

    def lookup(self, service: str, banner: str) -> List[Dict[str, Any]]:
        """Match service name and banner text against known vulnerability signatures.

        Args:
            service (str): Detected service name (e.g., 'vsftpd', 'Apache', 'OpenSSH').
            banner (str): Raw or sanitized banner string (e.g., 'SSH-2.0-OpenSSH_8.9p1').

        Returns:
            List[Dict[str, Any]]: List of matching CVE entries with ID, severity,
                                  description, and remediation fix.
        """
        matches: List[Dict[str, Any]] = []
        clean_service = service.lower().strip() if service else ""
        clean_banner = banner.strip() if banner else ""

        for svc_target, pattern, entry in self._compiled_patterns:
            service_match = (
                svc_target in clean_service
                or svc_target in clean_banner.lower()
                or not svc_target
            )
            if not service_match:
                continue

            # If version pattern exists, match against banner
            if pattern:
                if pattern.search(clean_banner) or pattern.search(clean_service):
                    match_copy = dict(entry)
                    match_copy["disclaimer"] = CVE_DISCLAIMER
                    matches.append(match_copy)
            else:
                match_copy = dict(entry)
                match_copy["disclaimer"] = CVE_DISCLAIMER
                matches.append(match_copy)

        return matches

    def annotate_port(self, port_result: PortResult) -> PortResult:
        """Query matching vulnerabilities and attach results to PortResult.cve_list.

        Args:
            port_result (PortResult): PortResult instance to annotate.

        Returns:
            PortResult: Updated PortResult with populated cve_list.
        """
        if port_result.is_open:
            hints = self.lookup(port_result.service, port_result.banner)
            port_result.cve_list = hints
        return port_result

    def annotate_host(self, host: Host) -> Host:
        """Annotate all open ports of a Host with vulnerability hints.

        Args:
            host (Host): Target Host object.

        Returns:
            Host: Host object with updated port CVE lists.
        """
        for port_result in host.ports:
            self.annotate_port(port_result)
        return host


# Singleton instance for quick module-level access
_GLOBAL_CVE_ENGINE: Optional[CVELookupEngine] = None


def get_cve_engine() -> CVELookupEngine:
    """Retrieve or initialize the global CVELookupEngine singleton."""
    global _GLOBAL_CVE_ENGINE
    if _GLOBAL_CVE_ENGINE is None:
        _GLOBAL_CVE_ENGINE = CVELookupEngine()
    return _GLOBAL_CVE_ENGINE


def lookup_vulnerabilities(service: str, banner: str) -> List[Dict[str, Any]]:
    """Convenience function to match service and banner against the CVE database."""
    return get_cve_engine().lookup(service=service, banner=banner)
