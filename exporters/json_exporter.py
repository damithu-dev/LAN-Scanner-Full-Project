"""JSON report exporter for LAN Scanner scan results.

Serializes host discovery details, port states, captured banners, and CVE hints
into structured, indented JSON for automated tooling and programmatic analysis.
"""

from datetime import datetime
import json
from typing import Any, Dict, List, Optional

from scanner.models import Host


def export_json(
    hosts: List[Host],
    filepath: str,
    target: str = "Local Subnet",
    scan_time: float = 0.0,
    metadata: Optional[Dict[str, Any]] = None,
) -> str:
    """Export scan results to a structured JSON file.

    Args:
        hosts (List[Host]): List of scanned Host objects.
        filepath (str): Target destination file path (.json).
        target (str): Target subnet or IP specification.
        scan_time (float): Elapsed scan duration in seconds.
        metadata (Optional[Dict[str, Any]]): Optional extra scan context.

    Returns:
        str: Absolute or verified path of the generated JSON file.
    """
    total_open_ports = sum(len(h.open_ports) for h in hosts)

    report_data: Dict[str, Any] = {
        "generator": "LAN Scanner & Active Port Scanner",
        "timestamp": datetime.now().isoformat(),
        "scan_summary": {
            "target": target,
            "hosts_discovered": len(hosts),
            "total_open_ports": total_open_ports,
            "elapsed_seconds": round(scan_time, 2),
        },
        "metadata": metadata or {},
        "hosts": [h.to_dict() for h in hosts],
    }

    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(report_data, f, indent=2, ensure_ascii=False)

    return filepath
