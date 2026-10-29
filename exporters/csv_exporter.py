"""CSV report exporter for LAN Scanner scan results.

Formats discovered network endpoints and port scan records into tabular,
spreadsheet-compatible CSV files.
"""

import csv
from typing import List

from scanner.models import Host


def export_csv(hosts: List[Host], filepath: str) -> str:
    """Export scan results into a tabular CSV file.

    Columns:
        IP, MAC, Vendor, Hostname, Port, Protocol, State, Service, Banner, CVE_Hints

    Args:
        hosts (List[Host]): Discovered hosts with populated port scan results.
        filepath (str): Target destination file path (.csv).

    Returns:
        str: Verified file path of the generated CSV report.
    """
    fieldnames = [
        "IP",
        "MAC",
        "Vendor",
        "Hostname",
        "Port",
        "Protocol",
        "State",
        "Service",
        "Banner",
        "CVE_Hints",
    ]

    with open(filepath, "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(fieldnames)

        for host in hosts:
            if not host.ports:
                writer.writerow([
                    host.ip,
                    host.mac or "N/A",
                    host.vendor,
                    host.hostname or "",
                    "N/A",
                    "N/A",
                    "NO_PORTS_SCANNED",
                    "N/A",
                    "",
                    "",
                ])
                continue

            for p in host.ports:
                cve_str = "; ".join(c.get("cve_id", "") for c in p.cve_list if isinstance(c, dict))
                writer.writerow([
                    host.ip,
                    host.mac or "N/A",
                    host.vendor,
                    host.hostname or "",
                    p.port,
                    p.protocol.upper(),
                    p.state,
                    p.service,
                    p.banner,
                    cve_str,
                ])

    return filepath
